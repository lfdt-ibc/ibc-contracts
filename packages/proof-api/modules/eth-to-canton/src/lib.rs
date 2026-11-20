// SPDX-License-Identifier: Apache-2.0

//! This is a one-sided proof API module from Ethereum to Canton.
//!
//! Only a mock mode exists: packets are relayed with empty proofs, for a Canton side that
//! tracks Ethereum with a light client accepting every proof.
//!
//! The relay transaction is the JSON body of a Ledger API command submission, without the
//! submitter fields (`commandId`, `userId`, `actAs`), which the caller adds.

#![deny(clippy::nursery, clippy::pedantic, warnings, unused_crate_dependencies)]
#![allow(unused_crate_dependencies, missing_docs)]

use std::collections::HashMap;

use alloy::{
    primitives::{hex, Address, TxHash},
    providers::{Provider, RootProvider},
    sol_types::SolValue,
};
use anyhow::{anyhow, bail, Result};
use ibc_eureka_solidity_types::ics26::IICS26RouterMsgs::Packet;
use proof_api_core::{
    api::{self, proof_api_service_server::ProofApiService},
    modules::ProofApiModule,
};
use proof_api_lib::{
    events::{EurekaEvent, EurekaEventWithHeight},
    listener::{canton, eth_eureka, ChainListenerService},
    utils::{
        canton::{
            DamlPacket, LedgerClient, CLIENT_TEMPLATE, GMP_RECEIVER_INTERFACE,
            PACKET_COMMITMENT_TEMPLATE, ROUTER_TEMPLATE,
        },
        solana_gmp::AbiGmpPacketData,
    },
};
use serde_json::{json, Value};
use tonic::{Request, Response};

/// The ICS27 GMP port id.
const GMP_PORT_ID: &str = "gmpport";

/// The `EthToCantonProofApiModule` struct defines the Ethereum to Canton proof API module.
#[derive(Clone, Copy, Debug)]
pub struct EthToCantonProofApiModule;

/// The `EthToCantonProofApiModuleService` defines the proof API service from Ethereum to Canton.
struct EthToCantonProofApiModuleService {
    /// The source ICS26 address.
    src_ics26_address: Address,
    /// The chain listener for Ethereum.
    src_listener: eth_eureka::ChainListener<RootProvider>,
    /// The chain listener for Canton.
    dst_listener: canton::ChainListener,
    /// The Canton ledger client.
    ledger: LedgerClient,
    config: EthToCantonConfig,
}

/// The configuration for the Ethereum to Canton proof API module.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EthToCantonConfig {
    /// The source Ethereum RPC URL.
    pub src_rpc_url: String,
    /// The source ICS26 address.
    pub src_ics26_address: Address,
    /// The URL of the JSON Ledger API of a Canton participant.
    pub dst_ledger_api_url: String,
    /// The Canton party operating the router.
    pub dst_operator_party: String,
    /// The Canton party that submits the relay transactions. It must be a relayer of the router.
    pub dst_relayer_party: String,
    /// The Canton party of the ICS27 GMP app, used to find the contracts that GMP packets call.
    pub dst_gmp_party: String,
}

impl EthToCantonProofApiModuleService {
    async fn new(config: EthToCantonConfig) -> Result<Self> {
        let src_provider = RootProvider::builder()
            .connect(&config.src_rpc_url)
            .await
            .map_err(|e| anyhow!("failed to create source provider: {e}"))?;
        let ledger = LedgerClient::new(&config.dst_ledger_api_url);

        Ok(Self {
            src_ics26_address: config.src_ics26_address,
            src_listener: eth_eureka::ChainListener::new(config.src_ics26_address, src_provider),
            dst_listener: canton::ChainListener::new(
                ledger.clone(),
                config.dst_relayer_party.clone(),
            ),
            ledger,
            config,
        })
    }

    /// The id of the single active `template` contract of the router matching `predicate`.
    async fn router_contract(
        &self,
        template: &str,
        predicate: impl Fn(&Value) -> bool + Send,
    ) -> Result<String> {
        let contracts = self
            .ledger
            .active_contracts(&self.config.dst_relayer_party, template)
            .await?;
        let mut matches = contracts.into_iter().map(|c| c.created_event).filter(|c| {
            c.create_argument["operator"] == self.config.dst_operator_party
                && predicate(&c.create_argument)
        });
        match (matches.next(), matches.next()) {
            (Some(contract), None) => Ok(contract.contract_id),
            (None, _) => bail!("no matching {template} contract"),
            (Some(_), Some(_)) => bail!("more than one matching {template} contract"),
        }
    }

    async fn packet_commitment(&self, packet: &Packet) -> Result<String> {
        // Daml encodes `Int` as a decimal string.
        let sequence = packet.sequence.to_string();
        self.router_contract(PACKET_COMMITMENT_TEMPLATE, |commitment| {
            commitment["packet"]["sourceClient"] == packet.sourceClient
                && commitment["packet"]["sequence"].as_str() == Some(&sequence)
        })
        .await
    }

    /// The contract a GMP packet calls, as the app context and its disclosure. Daml cannot
    /// derive a contract id from packet data, so the relayer picks a contract signed by the
    /// receiver party and the GMP app checks that choice.
    async fn gmp_receiver(&self, packet: &Packet) -> Result<(Value, Value)> {
        let data = AbiGmpPacketData::abi_decode(&packet.payloads[0].value)?;
        let receiver = self
            .ledger
            .active_interface_contracts(&self.config.dst_gmp_party, GMP_RECEIVER_INTERFACE)
            .await?
            .into_iter()
            .find(|c| c.created_event.signatories.contains(&data.receiver))
            .ok_or_else(|| anyhow!("no GMP receiver contract for {}", data.receiver))?;
        Ok((
            json!(receiver.created_event.contract_id),
            receiver.disclosure(),
        ))
    }

    async fn relay_events(
        &self,
        src_events: Vec<EurekaEventWithHeight>,
        target_events: Vec<EurekaEventWithHeight>,
        request: &api::RelayByTxRequest,
    ) -> Result<(Vec<u8>, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let selected = |seqs: &[u64], seq: u64| seqs.is_empty() || seqs.contains(&seq);

        let router = self.router_contract(ROUTER_TEMPLATE, |_| true).await?;
        let client = self
            .router_contract(CLIENT_TEMPLATE, |client| {
                client["clientId"] == request.dst_client_id
            })
            .await?;
        let relayer = &self.config.dst_relayer_party;

        let mut commands = Vec::new();
        let mut disclosed = Vec::new();
        let mut recv_count = 0;
        for EurekaEventWithHeight { event, height } in src_events {
            let (choice, argument) = match event {
                EurekaEvent::SendPacket(packet)
                    if packet.timeoutTimestamp > now
                        && packet.sourceClient == request.src_client_id
                        && packet.destClient == request.dst_client_id
                        && selected(&request.src_packet_sequences, packet.sequence) =>
                {
                    // Receiving consumes the client contract, so a second receive in the same
                    // transaction would need the id of a contract that does not exist yet.
                    recv_count += 1;
                    anyhow::ensure!(recv_count == 1, "only one packet can be received per relay");

                    let mut context = Vec::new();
                    if packet.payloads.len() == 1 && packet.payloads[0].destPort == GMP_PORT_ID {
                        let (receiver, disclosure) = self.gmp_receiver(&packet).await?;
                        context.push(receiver);
                        disclosed.push(disclosure);
                    }
                    (
                        "Router_RecvPacket",
                        json!({
                            "relayer": relayer,
                            "clientCid": client,
                            "packet": DamlPacket::from(&packet),
                            "proofCommitment": "",
                            "proofHeight": height.to_string(),
                            "context": context,
                        }),
                    )
                }
                EurekaEvent::WriteAcknowledgement(packet, acks)
                    if packet.sourceClient == request.dst_client_id
                        && packet.destClient == request.src_client_id
                        && selected(&request.dst_packet_sequences, packet.sequence) =>
                {
                    let ack = acks.first().ok_or_else(|| {
                        anyhow!("packet {} has no acknowledgements", packet.sequence)
                    })?;
                    (
                        "Router_AckPacket",
                        json!({
                            "relayer": relayer,
                            "clientCid": client,
                            "commitmentCid": self.packet_commitment(&packet).await?,
                            "packet": DamlPacket::from(&packet),
                            "acknowledgement": hex::encode(ack),
                            "proofAcked": "",
                            "proofHeight": height.to_string(),
                        }),
                    )
                }
                _ => continue,
            };
            commands.push(exercise(&router, choice, &argument));
        }

        for EurekaEventWithHeight { event, height } in target_events {
            let EurekaEvent::SendPacket(packet) = event else {
                continue;
            };
            if now >= packet.timeoutTimestamp
                && packet.sourceClient == request.dst_client_id
                && packet.destClient == request.src_client_id
                && selected(&request.dst_packet_sequences, packet.sequence)
            {
                let argument = json!({
                    "relayer": relayer,
                    "clientCid": client,
                    "commitmentCid": self.packet_commitment(&packet).await?,
                    "packet": DamlPacket::from(&packet),
                    "proofTimeout": "",
                    "proofHeight": height.to_string(),
                });
                commands.push(exercise(&router, "Router_TimeoutPacket", &argument));
            }
        }

        let tx = json!({ "commands": commands, "disclosedContracts": disclosed });
        Ok((serde_json::to_vec(&tx)?, router))
    }
}

fn exercise(router: &str, choice: &str, argument: &Value) -> Value {
    json!({ "ExerciseCommand": {
        "templateId": ROUTER_TEMPLATE,
        "contractId": router,
        "choice": choice,
        "choiceArgument": argument,
    }})
}

fn to_tonic_status(e: anyhow::Error) -> tonic::Status {
    tonic::Status::from_error(e.into())
}

#[tonic::async_trait]
impl ProofApiService for EthToCantonProofApiModuleService {
    async fn info(
        &self,
        request: Request<api::InfoRequest>,
    ) -> Result<Response<api::InfoResponse>, tonic::Status> {
        Ok(Response::new(api::InfoResponse {
            target_chain: None,
            source_chain: Some(api::Chain {
                chain_id: request.into_inner().src_chain,
                ibc_version: "2".to_string(),
                ibc_contract: self.src_ics26_address.to_string(),
            }),
            metadata: HashMap::default(),
        }))
    }

    async fn relay_by_tx(
        &self,
        request: Request<api::RelayByTxRequest>,
    ) -> Result<Response<api::RelayByTxResponse>, tonic::Status> {
        tracing::info!("Handling relay by tx request for Eth to Canton...");
        let inner_req = request.into_inner();

        let src_txs = inner_req
            .source_tx_ids
            .iter()
            .map(|tx| TryInto::<[u8; 32]>::try_into(tx.as_slice()).map(TxHash::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| tonic::Status::invalid_argument(format!("invalid tx hash: {e}")))?;
        // Canton transactions are identified by their update id, a string.
        let timeout_txs = inner_req
            .timeout_tx_ids
            .iter()
            .map(|tx| String::from_utf8(tx.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| tonic::Status::invalid_argument(format!("invalid update id: {e}")))?;

        let src_events = self
            .src_listener
            .fetch_tx_events(src_txs)
            .await
            .map_err(to_tonic_status)?;
        let target_events = self
            .dst_listener
            .fetch_tx_events(timeout_txs)
            .await
            .map_err(to_tonic_status)?;
        tracing::info!(
            "Fetched {} events from Eth and {} events from Canton.",
            src_events.len(),
            target_events.len()
        );

        let (tx, address) = self
            .relay_events(src_events, target_events, &inner_req)
            .await
            .map_err(to_tonic_status)?;

        Ok(Response::new(api::RelayByTxResponse { tx, address }))
    }

    async fn create_client(
        &self,
        _request: Request<api::CreateClientRequest>,
    ) -> Result<Response<api::CreateClientResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Eth to Canton only relays for a mock light client",
        ))
    }

    async fn update_client(
        &self,
        _request: Request<api::UpdateClientRequest>,
    ) -> Result<Response<api::UpdateClientResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Eth to Canton only relays for a mock light client",
        ))
    }
}

#[tonic::async_trait]
impl ProofApiModule for EthToCantonProofApiModule {
    fn name(&self) -> &'static str {
        "eth_to_canton"
    }

    async fn create_service(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<Box<dyn ProofApiService>> {
        let config: EthToCantonConfig = serde_json::from_value(config)?;
        let service = EthToCantonProofApiModuleService::new(config).await?;
        Ok(Box::new(service))
    }
}
