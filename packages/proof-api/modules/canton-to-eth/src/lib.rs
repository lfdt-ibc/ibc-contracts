// SPDX-License-Identifier: Apache-2.0

//! This is a one-sided proof API module from Canton to Ethereum.
//!
//! Only a mock mode exists: packets are relayed with empty proofs, for an Ethereum side that
//! tracks Canton with a light client accepting every proof.

#![deny(clippy::nursery, clippy::pedantic, warnings, unused_crate_dependencies)]
#![allow(unused_crate_dependencies, missing_docs)]

use std::collections::HashMap;

use alloy::{
    primitives::{Address, TxHash},
    providers::{Provider, RootProvider},
    sol_types::SolCall,
};
use ibc_eureka_solidity_types::{
    ibc_multicall::multicall_calldata,
    ics26::{router::routerCalls, IICS02ClientMsgs::Height},
};
use proof_api_core::{
    api::{self, proof_api_service_server::ProofApiService},
    modules::ProofApiModule,
};
use proof_api_lib::{
    listener::{canton, eth_eureka, ChainListenerService},
    utils::{canton::LedgerClient, eth_eureka as eth_utils},
};
use tonic::{Request, Response};

/// The `CantonToEthProofApiModule` struct defines the Canton to Ethereum proof API module.
#[derive(Clone, Copy, Debug)]
pub struct CantonToEthProofApiModule;

/// The `CantonToEthProofApiModuleService` defines the proof API service from Canton to Ethereum.
struct CantonToEthProofApiModuleService {
    /// The chain listener for Canton.
    src_listener: canton::ChainListener,
    /// The chain listener for Ethereum.
    dst_listener: eth_eureka::ChainListener<RootProvider>,
    /// The destination ICS26 address.
    dst_ics26_address: Address,
    /// The destination `IBCMulticall` address that relay transactions are submitted to.
    dst_ibc_multicall_address: Address,
}

/// The configuration for the Canton to Ethereum proof API module.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CantonToEthConfig {
    /// The URL of the JSON Ledger API of a Canton participant.
    pub src_ledger_api_url: String,
    /// The Canton party whose view of the ledger is read. It must be a relayer of the router.
    pub src_party: String,
    /// The destination Ethereum RPC URL.
    pub dst_rpc_url: String,
    /// The destination ICS26 address.
    pub dst_ics26_address: Address,
    /// The destination `IBCMulticall` address that relay transactions are submitted to.
    pub dst_ibc_multicall_address: Address,
}

impl CantonToEthProofApiModuleService {
    async fn new(config: CantonToEthConfig) -> anyhow::Result<Self> {
        let dst_provider = RootProvider::builder()
            .connect(&config.dst_rpc_url)
            .await
            .map_err(|e| anyhow::anyhow!("failed to create destination provider: {e}"))?;

        Ok(Self {
            src_listener: canton::ChainListener::new(
                LedgerClient::new(&config.src_ledger_api_url),
                config.src_party,
            ),
            dst_listener: eth_eureka::ChainListener::new(config.dst_ics26_address, dst_provider),
            dst_ics26_address: config.dst_ics26_address,
            dst_ibc_multicall_address: config.dst_ibc_multicall_address,
        })
    }
}

fn to_tonic_status(e: anyhow::Error) -> tonic::Status {
    tonic::Status::from_error(e.into())
}

#[tonic::async_trait]
impl ProofApiService for CantonToEthProofApiModuleService {
    async fn info(
        &self,
        request: Request<api::InfoRequest>,
    ) -> Result<Response<api::InfoResponse>, tonic::Status> {
        Ok(Response::new(api::InfoResponse {
            target_chain: Some(api::Chain {
                chain_id: self
                    .dst_listener
                    .chain_id()
                    .await
                    .map_err(to_tonic_status)?,
                ibc_version: "2".to_string(),
                ibc_contract: self.dst_ics26_address.to_string(),
            }),
            source_chain: Some(api::Chain {
                chain_id: request.into_inner().src_chain,
                ibc_version: "2".to_string(),
                ibc_contract: String::new(),
            }),
            metadata: HashMap::default(),
        }))
    }

    async fn relay_by_tx(
        &self,
        request: Request<api::RelayByTxRequest>,
    ) -> Result<Response<api::RelayByTxResponse>, tonic::Status> {
        tracing::info!("Handling relay by tx request for Canton to Eth...");
        let inner_req = request.into_inner();

        // Canton transactions are identified by their update id, a string.
        let src_txs = inner_req
            .source_tx_ids
            .into_iter()
            .map(String::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| tonic::Status::invalid_argument(format!("invalid update id: {e}")))?;
        let timeout_txs = inner_req
            .timeout_tx_ids
            .into_iter()
            .map(|tx| TryInto::<[u8; 32]>::try_into(tx).map(TxHash::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|tx| tonic::Status::invalid_argument(format!("invalid tx hash: {tx:?}")))?;

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
            "Fetched {} events from Canton and {} events from Eth.",
            src_events.len(),
            target_events.len()
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| to_tonic_status(e.into()))?;
        // Canton heights are record times in unix microseconds.
        let height = Height {
            revisionNumber: 0,
            revisionHeight: u64::try_from(now.as_micros())
                .map_err(|e| to_tonic_status(e.into()))?,
        };

        let timeout_msgs = eth_utils::target_events_to_timeout_msgs(
            target_events,
            &inner_req.src_client_id,
            &inner_req.dst_client_id,
            &inner_req.dst_packet_sequences,
            &height,
            now.as_secs(),
        );
        let recv_and_ack_msgs = eth_utils::src_events_to_recv_and_ack_msgs(
            src_events,
            &inner_req.src_client_id,
            &inner_req.dst_client_id,
            &inner_req.src_packet_sequences,
            &inner_req.dst_packet_sequences,
            &height,
            now.as_secs(),
        )
        .map_err(to_tonic_status)?;

        let calls = recv_and_ack_msgs
            .into_iter()
            .chain(timeout_msgs)
            .map(|call| match call {
                routerCalls::ackPacket(call) => call.abi_encode(),
                routerCalls::recvPacket(call) => call.abi_encode(),
                routerCalls::timeoutPacket(call) => call.abi_encode(),
                _ => unreachable!("only ack, recv and timeout msgs are built"),
            })
            .map(Into::into);

        Ok(Response::new(api::RelayByTxResponse {
            tx: multicall_calldata(self.dst_ics26_address, calls, 0),
            address: self.dst_ibc_multicall_address.to_string(),
        }))
    }

    async fn create_client(
        &self,
        _request: Request<api::CreateClientRequest>,
    ) -> Result<Response<api::CreateClientResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Canton to Eth only relays for a mock light client",
        ))
    }

    async fn update_client(
        &self,
        _request: Request<api::UpdateClientRequest>,
    ) -> Result<Response<api::UpdateClientResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Canton to Eth only relays for a mock light client",
        ))
    }
}

#[tonic::async_trait]
impl ProofApiModule for CantonToEthProofApiModule {
    fn name(&self) -> &'static str {
        "canton_to_eth"
    }

    async fn create_service(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<Box<dyn ProofApiService>> {
        let config: CantonToEthConfig = serde_json::from_value(config)?;
        let service = CantonToEthProofApiModuleService::new(config).await?;
        Ok(Box::new(service))
    }
}
