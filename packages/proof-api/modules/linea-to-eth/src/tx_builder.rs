// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeSet, HashMap},
    time::UNIX_EPOCH,
};

use alloy::{
    network::Ethereum,
    primitives::{hex, Address, Bytes, B256},
    providers::RootProvider,
    rpc::types::EIP1186AccountProofResponse,
    sol_types::{SolCall, SolValue},
};
use anyhow::{anyhow, bail, Context, Result};
use ethereum_apis::eth_api::client::EthApiClient;
use ibc_eureka_solidity_types::{
    ibc_multicall::multicall_calldata,
    ics26::{
        router::{routerCalls, routerInstance, updateClientCall},
        IICS02ClientMsgs::Height as RouterHeight,
    },
    linea::linea_light_client,
    msgs::{IICS02ClientMsgs::Height as MsgHeight, ILineaLightClientMsgs},
};
use proof_api_lib::utils::{
    eth_bft::{
        attach_packet_proofs, map_storage_proofs, needs_update, packet_storage_key,
        parse_create_client_params, retain_provable_packet_calls, sort_commit_seals,
    },
    eth_eureka::{src_events_to_recv_and_ack_msgs, target_events_to_timeout_msgs},
    RelayEventsParams,
};

use crate::maru::{MaruApiClient, SealedBeaconBlock};

pub struct TxBuilder {
    src_provider: RootProvider,
    dst_provider: RootProvider,
    maru: MaruApiClient,
    src_ics26_router: routerInstance<RootProvider, Ethereum>,
    dst_ics26_router: routerInstance<RootProvider, Ethereum>,
}

impl TxBuilder {
    pub fn new(
        src_provider: RootProvider,
        dst_provider: RootProvider,
        maru: MaruApiClient,
        src_ics26_address: Address,
        dst_ics26_address: Address,
    ) -> Self {
        Self {
            src_ics26_router: routerInstance::new(src_ics26_address, src_provider.clone()),
            dst_ics26_router: routerInstance::new(dst_ics26_address, dst_provider.clone()),
            src_provider,
            dst_provider,
            maru,
        }
    }

    pub const fn ics26_router_address(&self) -> &Address {
        self.dst_ics26_router.address()
    }

    pub async fn create_client(&self, parameters: &HashMap<String, String>) -> Result<Vec<u8>> {
        let params = parse_create_client_params(parameters)?;
        let trusted_block = match params.trusted_height {
            Some(height) => self.maru.sealed_block_at(height).await?,
            None => self.maru.sealed_block("head").await?,
        };
        let trusted_state = self.consensus_state(&trusted_block).await?;
        let ics26_router = *self.dst_ics26_router.address();

        let calldata = linea_light_client::LineaLightClient::deploy_builder(
            self.dst_provider.clone(),
            linea_light_client::ILineaLightClientMsgs::ClientState {
                ibcRouter: *self.src_ics26_router.address(),
                latestHeight: linea_light_client::IICS02ClientMsgs::Height {
                    revisionNumber: 0,
                    revisionHeight: trusted_block.execution_payload.block_number,
                },
                trustingPeriod: params.trusting_period,
                maxClockDrift: params.max_clock_drift,
                isFrozen: false,
                trustLevel: linea_light_client::ILineaLightClientMsgs::TrustThreshold {
                    numerator: params.trust_level.0,
                    denominator: params.trust_level.1,
                },
            },
            linea_light_client::ILineaLightClientMsgs::ConsensusState {
                timestamp: trusted_state.timestamp,
                stateRoot: trusted_state.stateRoot,
                validators: trusted_state.validators,
            },
            ics26_router,
        )
        .calldata()
        .to_vec();

        Ok(calldata)
    }

    pub async fn update_client(&self, dst_client_id: &str) -> Result<Vec<u8>> {
        let target_block = self.maru.sealed_block("head").await?;
        let update_call = self
            .update_client_calldata_if_needed(dst_client_id, &target_block)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "client {dst_client_id} is already at the latest source height {}",
                    target_block.execution_payload.block_number
                )
            })?;

        Ok(multicall_calldata(
            *self.dst_ics26_router.address(),
            [update_call.into()],
            1,
        ))
    }

    pub async fn relay_events(&self, params: RelayEventsParams) -> Result<Vec<u8>> {
        // Prove against the latest source block rather than the event heights, as the besu-to-eth
        // module does: a Bonsai-backed node only serves `eth_getProof` for recent state. Packets
        // that have already been completed on the source chain since their event was emitted are
        // detected from the proven slot values and skipped.
        let min_proof_height = params
            .src_events
            .iter()
            .map(|event| event.height)
            .chain(params.timeout_relay_height)
            .max()
            .ok_or_else(|| anyhow!("no packets collected"))?;
        let block = self.maru.latest_sealed_block(min_proof_height).await?;
        let proof_height = block.execution_payload.block_number;
        let proof_timestamp = block.execution_payload.timestamp;
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("failed to read system time")?
            .as_secs();
        let proof_height_msg = RouterHeight {
            revisionNumber: 0,
            revisionHeight: proof_height,
        };

        let recv_and_ack_msgs = src_events_to_recv_and_ack_msgs(
            params.src_events,
            &params.src_client_id,
            &params.dst_client_id,
            &params.src_packet_seqs,
            &params.dst_packet_seqs,
            &proof_height_msg,
            now,
        )?;
        let timeout_msgs = target_events_to_timeout_msgs(
            params.target_events,
            &params.src_client_id,
            &params.dst_client_id,
            &params.dst_packet_seqs,
            &proof_height_msg,
            proof_timestamp,
        );

        let mut packet_calls: Vec<_> = recv_and_ack_msgs.into_iter().chain(timeout_msgs).collect();
        if packet_calls.is_empty() {
            bail!("no packets collected")
        }

        let storage_keys = packet_calls
            .iter()
            .map(packet_storage_key)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let proof = self
            .fetch_source_proofs(proof_height, &storage_keys)
            .await
            .with_context(|| {
                format!("failed to fetch proofs for source router at height {proof_height}")
            })?;
        let storage_proofs = map_storage_proofs(&storage_keys, &proof.storage_proof)?;
        retain_provable_packet_calls(&mut packet_calls, &storage_proofs)?;
        if packet_calls.is_empty() {
            bail!("all packets have already been completed on the source chain at height {proof_height}")
        }
        let proven_state = self.consensus_state(&block).await?;
        attach_packet_proofs(
            &mut packet_calls,
            &proof.account_proof,
            &storage_proofs,
            |account_proof_nodes, proof_nodes| {
                membership_proof(&proven_state, account_proof_nodes, proof_nodes)
            },
        )?;

        let update_call = self
            .update_client_calldata_if_needed(&params.dst_client_id, &block)
            .await?
            .map(Bytes::from);
        // The update and the first packet call, which carries the account proof that the
        // remaining calls rely on, must succeed. Every other packet call is allowed to fail.
        let strict_calls = usize::from(update_call.is_some()) + 1;
        let all_calls =
            update_call
                .into_iter()
                .chain(packet_calls.into_iter().map(|call| match call {
                    routerCalls::ackPacket(call) => call.abi_encode().into(),
                    routerCalls::recvPacket(call) => call.abi_encode().into(),
                    routerCalls::timeoutPacket(call) => call.abi_encode().into(),
                    _ => unreachable!("only recv, ack, and timeout calls are constructed"),
                }));

        Ok(multicall_calldata(
            *self.dst_ics26_router.address(),
            all_calls,
            strict_calls,
        ))
    }

    /// Builds the update from the destination client's trusted height to `target_block`, or
    /// returns `None` when the client already trusts that height.
    async fn update_client_calldata_if_needed(
        &self,
        dst_client_id: &str,
        target_block: &SealedBeaconBlock,
    ) -> Result<Option<Vec<u8>>> {
        let trusted_height = self.fetch_destination_trusted_height(dst_client_id).await?;
        let target_height = target_block.execution_payload.block_number;
        if !needs_update(trusted_height, target_height)? {
            tracing::info!("Client already at height {trusted_height}, skipping update");
            return Ok(None);
        }

        let trusted_block = self.maru.sealed_block_at(trusted_height).await?;
        let update_msg = ILineaLightClientMsgs::MsgUpdateClient {
            header: ILineaLightClientMsgs::BeaconBlockHeader {
                number: target_block.header.number,
                round: target_block.header.round,
                timestamp: target_block.header.timestamp,
                proposer: target_block.header.proposer,
                parentRoot: target_block.header.parent_root,
                stateRoot: target_block.header.state_root,
                bodyRoot: target_block.header.body_root,
            },
            bodyRlp: target_block.body_rlp(),
            validators: self.maru.validators(&target_block.header).await?,
            commitSeals: sort_commit_seals(&target_block.header.hash(), &target_block.commit_seals)
                .with_context(|| {
                    format!("failed to order commit seals of source block {target_height}")
                })?,
            trustedHeight: MsgHeight {
                revisionNumber: 0,
                revisionHeight: trusted_height,
            },
            consensusStatePreimage: self.consensus_state(&trusted_block).await?,
        };

        Ok(Some(
            updateClientCall {
                clientId: dst_client_id.to_string(),
                updateMsg: update_msg.abi_encode().into(),
            }
            .abi_encode(),
        ))
    }

    /// Rebuilds the consensus state the light client derives from a source block.
    ///
    /// The light client stores only `keccak256(abi.encode(ConsensusState))` per height, so every
    /// message that references a height must carry the full consensus state.
    async fn consensus_state(
        &self,
        block: &SealedBeaconBlock,
    ) -> Result<ILineaLightClientMsgs::ConsensusState> {
        Ok(ILineaLightClientMsgs::ConsensusState {
            timestamp: block.execution_payload.timestamp,
            stateRoot: block.execution_payload.state_root,
            validators: self.maru.validators(&block.header).await.with_context(|| {
                format!(
                    "failed to fetch validators of source block {}",
                    block.execution_payload.block_number
                )
            })?,
        })
    }

    async fn fetch_source_proofs(
        &self,
        block_height: u64,
        storage_keys: &[B256],
    ) -> Result<EIP1186AccountProofResponse> {
        Ok(EthApiClient::new(self.src_provider.clone())
            .get_proof(
                &self.src_ics26_router.address().to_string(),
                storage_keys
                    .iter()
                    .map(|key| format!("0x{}", hex::encode(key)))
                    .collect(),
                format!("0x{block_height:x}"),
            )
            .await?)
    }

    /// Returns the latest height trusted by the destination Linea light client.
    async fn fetch_destination_trusted_height(&self, dst_client_id: &str) -> Result<u64> {
        let client_address = self
            .dst_ics26_router
            .getClient(dst_client_id.to_string())
            .call()
            .await
            .with_context(|| {
                format!("failed to fetch destination client address for {dst_client_id}")
            })?;
        let client_state_bz: Bytes =
            linea_light_client::LineaLightClient::new(client_address, self.dst_provider.clone())
                .getClientState()
                .call()
                .await
                .with_context(|| {
                    format!("failed to fetch destination client state for {dst_client_id}")
                })?;

        ILineaLightClientMsgs::ClientState::abi_decode(client_state_bz.as_ref())
            .map(|client_state| client_state.latestHeight.revisionHeight)
            .with_context(|| {
                format!("failed to decode destination client state for {dst_client_id}")
            })
    }
}

/// Encodes the membership proof of a packet call against the consensus state it is verified with.
fn membership_proof(
    proven_state: &ILineaLightClientMsgs::ConsensusState,
    account_proof_nodes: Vec<Bytes>,
    proof_nodes: Vec<Bytes>,
) -> Bytes {
    ILineaLightClientMsgs::MembershipProof {
        consensusStatePreimage: proven_state.clone(),
        accountProofNodes: account_proof_nodes,
        proofNodes: proof_nodes,
    }
    .abi_encode()
    .into()
}
