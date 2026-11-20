// SPDX-License-Identifier: Apache-2.0

pub mod artifact;
pub mod backend;
pub mod bootstrap;
pub mod config;
pub mod dedup;
pub mod destination;
pub mod engine;
pub(crate) mod http;
pub mod packet;
pub mod rpc;
pub mod server;
pub mod state;
pub mod storage;
pub mod trust;
#[cfg(feature = "sp1")]
pub(crate) mod witness;

#[allow(clippy::all, clippy::pedantic)]
pub mod proto {
    tonic::include_proto!("ibc.v2.prover");
}

use proto::{Client, PacketProofsRequest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    InvalidRequest(String),
    UnknownClient,
    Unavailable(String),
    ResourceExhausted(String),
    Backend(String),
    Internal(String),
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(formatter, "invalid request: {message}"),
            Self::UnknownClient => formatter.write_str("unknown client"),
            Self::Unavailable(message) => write!(formatter, "temporarily unavailable: {message}"),
            Self::ResourceExhausted(message) => write!(formatter, "resource exhausted: {message}"),
            Self::Backend(message) => write!(formatter, "proof backend failure: {message}"),
            Self::Internal(message) => write!(formatter, "internal failure: {message}"),
        }
    }
}

impl std::error::Error for EngineError {}

pub trait ProofEngine: Send + Sync + 'static {
    fn latest_provable_height(&self, client: &Client) -> Result<(u64, u64), EngineError>;
    fn trust_update_proof(&self, client: &Client) -> Result<Vec<u8>, EngineError>;
    fn state_proof(&self, client: &Client, height: u64) -> Result<Vec<u8>, EngineError>;
    fn packet_proofs(&self, request: &PacketProofsRequest) -> Result<Vec<Vec<u8>>, EngineError>;
}

#[cfg(test)]
mod tests {
    use super::EngineError;

    #[test]
    fn engine_errors_have_stable_operator_facing_messages() {
        assert_eq!(
            EngineError::InvalidRequest("bad".into()).to_string(),
            "invalid request: bad"
        );
        assert_eq!(EngineError::UnknownClient.to_string(), "unknown client");
        assert_eq!(
            EngineError::Unavailable("wait".into()).to_string(),
            "temporarily unavailable: wait"
        );
        assert_eq!(
            EngineError::ResourceExhausted("full".into()).to_string(),
            "resource exhausted: full"
        );
        assert_eq!(
            EngineError::Backend("failed".into()).to_string(),
            "proof backend failure: failed"
        );
        assert_eq!(
            EngineError::Internal("failed".into()).to_string(),
            "internal failure: failed"
        );
    }
}
