// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeSet, HashMap},
    time::UNIX_EPOCH,
};

use alloy::{
    consensus::Header,
    network::Ethereum,
    primitives::{hex, keccak256, Address, Bytes, B256},
    providers::{Provider, RootProvider},
    rpc::types::EIP1186AccountProofResponse,
    sol_types::{SolCall, SolValue},
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ethereum_apis::eth_api::client::EthApiClient;
use ibc_eureka_solidity_types::{
    besu::besu_light_client,
    ibc_multicall::multicall_calldata,
    ics26::{
        router::{routerCalls, routerInstance, updateClientCall},
        IICS02ClientMsgs::Height as RouterHeight,
    },
    msgs::{IBesuLightClientMsgs, IICS02ClientMsgs::Height as MsgHeight},
};
use proof_api_lib::utils::{
    eth_bft::{
        attach_packet_proofs, map_storage_proofs, needs_update, packet_storage_key,
        parse_create_client_params, retain_provable_packet_calls, sort_commit_seals,
    },
    eth_eureka::{src_events_to_recv_and_ack_msgs, target_events_to_timeout_msgs},
    RelayEventsParams,
};
use rlp::{Rlp, RlpStream};

use crate::BesuConsensusType;

pub struct TxBuilder {
    src_provider: RootProvider,
    dst_provider: RootProvider,
    src_ics26_router: routerInstance<RootProvider, Ethereum>,
    dst_ics26_router: routerInstance<RootProvider, Ethereum>,
    consensus_type: BesuConsensusType,
}

impl TxBuilder {
    pub fn new(
        src_provider: RootProvider,
        dst_provider: RootProvider,
        src_ics26_address: Address,
        dst_ics26_address: Address,
        consensus_type: BesuConsensusType,
    ) -> Self {
        Self {
            src_ics26_router: routerInstance::new(src_ics26_address, src_provider.clone()),
            dst_ics26_router: routerInstance::new(dst_ics26_address, dst_provider.clone()),
            src_provider,
            dst_provider,
            consensus_type,
        }
    }

    pub const fn ics26_router_address(&self) -> &Address {
        self.dst_ics26_router.address()
    }

    pub async fn create_client(&self, parameters: &HashMap<String, String>) -> Result<Vec<u8>> {
        let params = parse_create_client_params(parameters)?;
        let trusted_height = match params.trusted_height {
            Some(height) => height,
            None => self
                .src_provider
                .get_block_number()
                .await
                .context("failed to fetch latest source block number")?,
        };

        let trusted_state = consensus_state(&self.fetch_source_header(trusted_height).await?)?;
        let ics26_router = *self.dst_ics26_router.address();

        let calldata = besu_light_client::BesuLightClient::deploy_builder(
            self.dst_provider.clone(),
            besu_light_client::IBesuLightClientMsgs::ClientState {
                ibcRouter: *self.src_ics26_router.address(),
                latestHeight: besu_light_client::IICS02ClientMsgs::Height {
                    revisionNumber: 0,
                    revisionHeight: trusted_height,
                },
                trustingPeriod: params.trusting_period,
                maxClockDrift: params.max_clock_drift,
                isFrozen: false,
                trustLevel: besu_light_client::IBesuLightClientMsgs::TrustThreshold {
                    numerator: params.trust_level.0,
                    denominator: params.trust_level.1,
                },
            },
            besu_light_client::IBesuLightClientMsgs::ConsensusState {
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
        let trusted_height = self.fetch_destination_trusted_height(dst_client_id).await?;
        let target_height = self
            .src_provider
            .get_block_number()
            .await
            .context("failed to fetch latest source block number")?;
        ensure!(
            needs_update(trusted_height, target_height)?,
            "client {dst_client_id} is already at the latest source height {target_height}"
        );

        let trusted_state = consensus_state(&self.fetch_source_header(trusted_height).await?)?;
        let target_header = self.fetch_source_header(target_height).await?;

        let update_call = Self::build_update_client_calldata(
            dst_client_id,
            trusted_height,
            trusted_state,
            &target_header,
            self.consensus_type,
        )?;

        Ok(multicall_calldata(
            *self.dst_ics26_router.address(),
            [update_call.into()],
            1,
        ))
    }

    pub async fn relay_events(&self, params: RelayEventsParams) -> Result<Vec<u8>> {
        // Prove against the latest source block rather than the event heights. A Bonsai-backed
        // Besu node only serves `eth_getProof` for recent state, so historical event heights may
        // already be pruned, whereas the latest block is always available. Packets that have
        // already been completed on the source chain since their event was emitted are detected
        // from the proven slot values and skipped instead of being sent as calls that would
        // revert, and timeouts benefit from the later timestamp.
        let min_proof_height = params
            .src_events
            .iter()
            .map(|event| event.height)
            .chain(params.timeout_relay_height)
            .max()
            .ok_or_else(|| anyhow!("no packets collected"))?;
        let proof_height = self
            .src_provider
            .get_block_number()
            .await
            .context("failed to fetch latest source block number")?;
        ensure!(
            proof_height >= min_proof_height,
            "latest source block {proof_height} is behind the required proof height {min_proof_height}"
        );
        let header = self
            .fetch_source_header(proof_height)
            .await
            .with_context(|| format!("failed to fetch source block at height {proof_height}"))?;
        let proof_timestamp = header.timestamp;
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
        let proven_state = consensus_state(&header)?;
        attach_packet_proofs(
            &mut packet_calls,
            &proof.account_proof,
            &storage_proofs,
            |account_proof_nodes, proof_nodes| {
                membership_proof(&proven_state, account_proof_nodes, proof_nodes)
            },
        )?;

        let update_call = self
            .update_client_calldata_if_needed(&params.dst_client_id, &header)
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

    /// Builds the update from the destination client's trusted height to `target_header`, or
    /// returns `None` when the client already trusts that height.
    async fn update_client_calldata_if_needed(
        &self,
        dst_client_id: &str,
        target_header: &Header,
    ) -> Result<Option<Vec<u8>>> {
        let trusted_height = self.fetch_destination_trusted_height(dst_client_id).await?;
        if !needs_update(trusted_height, target_header.number)? {
            tracing::info!("Client already at height {trusted_height}, skipping update");
            return Ok(None);
        }

        let trusted_state = consensus_state(&self.fetch_source_header(trusted_height).await?)?;
        Self::build_update_client_calldata(
            dst_client_id,
            trusted_height,
            trusted_state,
            target_header,
            self.consensus_type,
        )
        .map(Some)
    }

    fn build_update_client_calldata(
        dst_client_id: &str,
        trusted_height: u64,
        trusted_state: IBesuLightClientMsgs::ConsensusState,
        target_header: &Header,
        consensus_type: BesuConsensusType,
    ) -> Result<Vec<u8>> {
        let (header_rlp, commit_seals) = split_commit_seals(target_header, consensus_type)
            .with_context(|| {
                format!(
                    "failed to split commit seals of source block {}",
                    target_header.number
                )
            })?;
        let update_msg = IBesuLightClientMsgs::MsgUpdateClient {
            headerRlp: header_rlp,
            commitSeals: commit_seals,
            trustedHeight: MsgHeight {
                revisionNumber: 0,
                revisionHeight: trusted_height,
            },
            consensusStatePreimage: trusted_state,
        };

        Ok(updateClientCall {
            clientId: dst_client_id.to_string(),
            updateMsg: update_msg.abi_encode().into(),
        }
        .abi_encode())
    }

    async fn fetch_source_header(&self, block_height: u64) -> Result<Header> {
        let block = EthApiClient::new(self.src_provider.clone())
            .get_block(block_height)
            .await
            .with_context(|| format!("failed to fetch source block at height {block_height}"))?;
        Ok(block.into_consensus_header())
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

    /// Returns the latest height trusted by the destination Besu light client.
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
            besu_light_client::BesuLightClient::new(client_address, self.dst_provider.clone())
                .getClientState()
                .call()
                .await
                .with_context(|| {
                    format!("failed to fetch destination client state for {dst_client_id}")
                })?;

        IBesuLightClientMsgs::ClientState::abi_decode(client_state_bz.as_ref())
            .map(|client_state| client_state.latestHeight.revisionHeight)
            .with_context(|| {
                format!("failed to decode destination client state for {dst_client_id}")
            })
    }
}

/// Encodes the membership proof of a packet call against the consensus state it is verified with.
fn membership_proof(
    proven_state: &IBesuLightClientMsgs::ConsensusState,
    account_proof_nodes: Vec<Bytes>,
    proof_nodes: Vec<Bytes>,
) -> Bytes {
    IBesuLightClientMsgs::MembershipProof {
        consensusStatePreimage: proven_state.clone(),
        accountProofNodes: account_proof_nodes,
        proofNodes: proof_nodes,
    }
    .abi_encode()
    .into()
}

/// Rebuilds the consensus state the light client derives from a source header.
///
/// The light client stores only `keccak256(abi.encode(ConsensusState))` per height, so every
/// message that references a height must carry the full consensus state. Every field comes from the
/// header itself, so no state that a Bonsai-backed Besu node may have pruned is needed.
fn consensus_state(header: &Header) -> Result<IBesuLightClientMsgs::ConsensusState> {
    Ok(IBesuLightClientMsgs::ConsensusState {
        timestamp: header.timestamp,
        stateRoot: header.state_root,
        validators: extract_validators_from_extra_data(&header.extra_data).with_context(|| {
            format!(
                "failed to extract validators from source block {}",
                header.number
            )
        })?,
    })
}

/// Extracts the list of validators from the `extraData` field in ascending order.
fn extract_validators_from_extra_data(extra_data: &[u8]) -> Result<Vec<Address>> {
    let out = Rlp::new(extra_data)
        .at(1)
        .context("failed to read validator list from extraData")?
        .into_iter()
        .map(|validator_rlp| {
            let validator = validator_rlp
                .data()
                .context("failed to decode validator address")?;
            Address::try_from(validator)
                .map_err(|_| anyhow!("invalid validator address length: {}", validator.len()))
        })
        .collect::<Result<Vec<Address>>>()?;
    // Besu returns the validators in ascending order, so we can check that the list is sorted.
    if !out.is_sorted() {
        bail!("validators are not sorted in ascending order");
    }

    Ok(out)
}

/// Splits `header` into its commit-seal signing RLP and its commit seals, ordered by recovered
/// signer address and with 27/28 recovery ids.
///
/// The light client hashes the signing RLP to get the commit-seal digest, so it must be exactly the
/// header the validators signed: QBFT signs the header with an empty seal list, IBFT2 with the seal
/// list dropped. The light client also requires commit seals in strictly ascending signer order
/// with 27/28 recovery ids, but Besu orders them arbitrarily and uses 0/1 recovery ids.
fn split_commit_seals(
    header: &Header,
    consensus_type: BesuConsensusType,
) -> Result<(Bytes, Vec<Bytes>)> {
    let extra_data = Rlp::new(&header.extra_data);
    let item_count = extra_data
        .item_count()
        .context("failed to decode extraData")?;
    ensure!(
        item_count == 5,
        "expected 5 extraData items, got {item_count}"
    );
    let mut stream = RlpStream::new_list(match consensus_type {
        BesuConsensusType::Qbft => 5,
        BesuConsensusType::Ibft2 => 4,
    });
    for i in 0..4 {
        let item = extra_data
            .at(i)
            .context("failed to decode extraData items")?;
        stream.append_raw(item.as_raw(), 1);
    }
    if matches!(consensus_type, BesuConsensusType::Qbft) {
        stream.begin_list(0);
    }
    let seals: Vec<Vec<u8>> = extra_data
        .list_at(4)
        .context("failed to decode commit seals")?;

    let mut signing_header = header.clone();
    signing_header.extra_data = Bytes::from(stream.out().to_vec());
    let header_rlp = Bytes::from(alloy_rlp::encode(&signing_header));
    let digest = keccak256(&header_rlp);

    let commit_seals = sort_commit_seals(&digest, seals)?;

    Ok((header_rlp, commit_seals))
}

#[cfg(test)]
mod tests {
    use super::split_commit_seals;
    use crate::BesuConsensusType;
    use alloy::{
        consensus::Header,
        primitives::{keccak256, Address, Bytes, Signature, B256},
        signers::{local::PrivateKeySigner, SignerSync},
    };
    use rlp::{Rlp, RlpStream};

    fn besu_extra_data(validators: &[Address], seals: Option<&[Vec<u8>]>) -> Bytes {
        let mut stream = RlpStream::new_list(4 + usize::from(seals.is_some()));
        stream.append(&vec![0u8; 32]);
        stream.begin_list(validators.len());
        for validator in validators {
            stream.append(&validator.as_slice());
        }
        stream.begin_list(0);
        stream.append(&vec![0u8; 4]);
        if let Some(seals) = seals {
            stream.begin_list(seals.len());
            for seal in seals {
                stream.append(seal);
            }
        }
        Bytes::from(stream.out().to_vec())
    }

    /// Returns a header sealed by `signers` in the given order with Besu's 0/1 recovery ids, and the
    /// commit-seal digest.
    fn sealed_header(
        consensus_type: BesuConsensusType,
        signers: &[&PrivateKeySigner],
    ) -> (Header, B256) {
        let mut validators: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
        validators.sort();
        let mut header = Header {
            number: 7,
            extra_data: besu_extra_data(
                &validators,
                matches!(consensus_type, BesuConsensusType::Qbft).then_some(&[]),
            ),
            ..Header::default()
        };
        let digest = keccak256(alloy_rlp::encode(&header));
        let seals: Vec<_> = signers
            .iter()
            .map(|signer| {
                let mut seal = signer.sign_hash_sync(&digest).unwrap().as_bytes();
                seal[64] -= 27;
                seal.to_vec()
            })
            .collect();
        header.extra_data = besu_extra_data(&validators, Some(&seals));
        (header, digest)
    }

    #[test]
    fn split_commit_seals_returns_signing_rlp_and_sorted_seals() {
        let signers: Vec<_> = (0..4).map(|_| PrivateKeySigner::random()).collect();
        let mut unsorted: Vec<_> = signers.iter().collect();
        unsorted.sort_by_key(|signer| std::cmp::Reverse(signer.address()));

        for consensus_type in [BesuConsensusType::Qbft, BesuConsensusType::Ibft2] {
            let (header, digest) = sealed_header(consensus_type, &unsorted);
            let (header_rlp, seals) = split_commit_seals(&header, consensus_type).unwrap();
            assert_eq!(keccak256(&header_rlp), digest);

            let signing_header: Header = alloy_rlp::decode_exact(&header_rlp).unwrap();
            let extra_data = Rlp::new(&signing_header.extra_data);
            let original = Rlp::new(&header.extra_data);
            match consensus_type {
                BesuConsensusType::Qbft => {
                    assert_eq!(extra_data.item_count().unwrap(), 5);
                    assert_eq!(extra_data.at(4).unwrap().as_raw(), [0xc0]);
                }
                BesuConsensusType::Ibft2 => assert_eq!(extra_data.item_count().unwrap(), 4),
            }
            for i in 0..4 {
                assert_eq!(
                    extra_data.at(i).unwrap().as_raw(),
                    original.at(i).unwrap().as_raw()
                );
            }
            assert_eq!(
                Header {
                    extra_data: header.extra_data.clone(),
                    ..signing_header
                },
                header
            );

            let recovered: Vec<_> = seals
                .iter()
                .map(|seal| {
                    assert!(matches!(seal[64], 27 | 28));
                    Signature::from_raw(seal)
                        .unwrap()
                        .recover_address_from_prehash(&digest)
                        .unwrap()
                })
                .collect();
            let mut expected: Vec<_> = signers.iter().map(PrivateKeySigner::address).collect();
            expected.sort();
            assert_eq!(recovered, expected);
        }
    }

    #[test]
    fn split_commit_seals_rejects_duplicate_signers() {
        let signer = PrivateKeySigner::random();
        let (header, _) = sealed_header(BesuConsensusType::Qbft, &[&signer, &signer]);
        let err = split_commit_seals(&header, BesuConsensusType::Qbft).unwrap_err();
        assert!(err.to_string().contains("duplicate commit seal signer"));
    }
}
