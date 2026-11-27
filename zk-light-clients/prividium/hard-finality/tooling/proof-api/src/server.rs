// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::ClientConfig,
    proto::{
        prover_service_server::{ProverService, ProverServiceServer},
        LatestProvableHeightRequest, LatestProvableHeightResponse, PacketProofsRequest,
        PacketProofsResponse, StateProofRequest, StateProofResponse, TrustUpdateProofRequest,
    },
    EngineError, ProofEngine,
};
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::sync::Semaphore;
use tonic::{metadata::MetadataMap, transport::Server, Request, Response, Status};

#[derive(Clone)]
pub struct ProofApi<E> {
    engine: Arc<E>,
    client: ClientConfig,
    authorization: Option<Arc<str>>,
    request_slots: Arc<Semaphore>,
    queue_slots: Arc<Semaphore>,
    height_slots: Arc<Semaphore>,
}

impl<E> ProofApi<E>
where
    E: ProofEngine,
{
    #[must_use]
    pub fn new(
        engine: Arc<E>,
        client: ClientConfig,
        authorization: Option<String>,
        max_concurrent_requests: usize,
        max_queued_requests: usize,
        max_concurrent_height_requests: usize,
    ) -> Self {
        Self {
            engine,
            client,
            authorization: authorization.map(Arc::from),
            request_slots: Arc::new(Semaphore::new(max_concurrent_requests)),
            queue_slots: Arc::new(Semaphore::new(max_queued_requests)),
            height_slots: Arc::new(Semaphore::new(max_concurrent_height_requests)),
        }
    }

    #[allow(clippy::result_large_err)]
    fn authorize(&self, metadata: &MetadataMap) -> Result<(), Status> {
        let Some(expected) = &self.authorization else {
            return Ok(());
        };
        let supplied = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if constant_time_eq(expected.as_bytes(), supplied.as_bytes()) {
            Ok(())
        } else {
            Err(Status::unauthenticated("missing or invalid bearer token"))
        }
    }

    #[allow(clippy::result_large_err)]
    fn check_client(&self, client: Option<&crate::proto::Client>) -> Result<(), Status> {
        let client = client.ok_or_else(|| Status::invalid_argument("client is required"))?;
        if client.chain_id != self.client.chain_id || client.client_id != self.client.client_id {
            return Err(Status::not_found("unknown client"));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    async fn request_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let queue_permit = Arc::clone(&self.queue_slots)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("proof request queue is full"))?;
        let execution_permit = Arc::clone(&self.request_slots)
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("proof request executor is shutting down"))?;
        drop(queue_permit);
        Ok(execution_permit)
    }
}

#[tonic::async_trait]
impl<E> ProverService for ProofApi<E>
where
    E: ProofEngine,
{
    async fn latest_provable_height(
        &self,
        request: Request<LatestProvableHeightRequest>,
    ) -> Result<Response<LatestProvableHeightResponse>, Status> {
        self.authorize(request.metadata())?;
        self.check_client(request.get_ref().client.as_ref())?;
        let permit = Arc::clone(&self.height_slots)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("height request capacity is full"))?;
        let input = request.into_inner();
        let client = input
            .client
            .ok_or_else(|| Status::invalid_argument("client is required"))?;
        let engine = Arc::clone(&self.engine);
        let (height, timestamp) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.latest_provable_height(&client)
        })
        .await
        .map_err(|error| Status::internal(format!("worker failed: {error}")))?
        .map_err(engine_status)?;
        if height == 0 || timestamp == 0 {
            return Err(Status::failed_precondition(
                "engine returned a zero height or timestamp",
            ));
        }
        Ok(Response::new(LatestProvableHeightResponse {
            height,
            timestamp,
        }))
    }

    async fn trust_update_proof(
        &self,
        request: Request<TrustUpdateProofRequest>,
    ) -> Result<Response<StateProofResponse>, Status> {
        self.authorize(request.metadata())?;
        self.check_client(request.get_ref().client.as_ref())?;
        let permit = self.request_permit().await?;
        let client = request
            .into_inner()
            .client
            .ok_or_else(|| Status::invalid_argument("client is required"))?;
        let engine = Arc::clone(&self.engine);
        let proof = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.trust_update_proof(&client)
        })
        .await
        .map_err(|error| Status::internal(format!("worker failed: {error}")))?
        .map_err(engine_status)?;
        if proof.is_empty() {
            return Err(Status::internal(
                "engine returned an empty Trust Update proof",
            ));
        }
        Ok(Response::new(StateProofResponse { proof }))
    }

    async fn state_proof(
        &self,
        request: Request<StateProofRequest>,
    ) -> Result<Response<StateProofResponse>, Status> {
        self.authorize(request.metadata())?;
        self.check_client(request.get_ref().client.as_ref())?;
        if request.get_ref().height == 0 {
            return Err(Status::invalid_argument("height must be nonzero"));
        }
        let permit = self.request_permit().await?;
        let input = request.into_inner();
        let client = input
            .client
            .ok_or_else(|| Status::invalid_argument("client is required"))?;
        let engine = Arc::clone(&self.engine);
        let proof = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.state_proof(&client, input.height)
        })
        .await
        .map_err(|error| Status::internal(format!("worker failed: {error}")))?
        .map_err(engine_status)?;
        if proof.is_empty() {
            return Err(Status::internal("engine returned an empty state proof"));
        }
        Ok(Response::new(StateProofResponse { proof }))
    }

    async fn packet_proofs(
        &self,
        request: Request<PacketProofsRequest>,
    ) -> Result<Response<PacketProofsResponse>, Status> {
        self.authorize(request.metadata())?;
        self.check_client(request.get_ref().client.as_ref())?;
        if request.get_ref().height == 0 {
            return Err(Status::invalid_argument("height must be nonzero"));
        }
        if request.get_ref().packets.is_empty() {
            return Ok(Response::new(PacketProofsResponse { proofs: Vec::new() }));
        }
        let permit = self.request_permit().await?;
        let input = request.into_inner();
        let expected = input.packets.len();
        let engine = Arc::clone(&self.engine);
        let proofs = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.packet_proofs(&input)
        })
        .await
        .map_err(|error| Status::internal(format!("worker failed: {error}")))?
        .map_err(engine_status)?;
        if proofs.len() != expected || proofs.iter().any(Vec::is_empty) {
            return Err(Status::internal(
                "engine returned missing, extra, or empty packet proofs",
            ));
        }
        Ok(Response::new(PacketProofsResponse { proofs }))
    }
}

pub async fn serve<E, F>(
    bind_address: SocketAddr,
    service: ProofApi<E>,
    shutdown: F,
) -> Result<(), tonic::transport::Error>
where
    E: ProofEngine,
    F: Future<Output = ()> + Send + 'static,
{
    Server::builder()
        .add_service(ProverServiceServer::new(service))
        .serve_with_shutdown(bind_address, shutdown)
        .await
}

fn engine_status(error: EngineError) -> Status {
    match error {
        EngineError::InvalidRequest(message) => Status::invalid_argument(message),
        EngineError::UnknownClient => Status::not_found("unknown client"),
        EngineError::Unavailable(message) => Status::failed_precondition(message),
        EngineError::ResourceExhausted(message) => Status::resource_exhausted(message),
        EngineError::Backend(message) => Status::unavailable(message),
        EngineError::Internal(message) => Status::internal(message),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::proto::{Client, Packet};

    struct FakeEngine;

    impl ProofEngine for FakeEngine {
        fn latest_provable_height(&self, _client: &Client) -> Result<(u64, u64), EngineError> {
            Ok((5, 99))
        }

        fn trust_update_proof(&self, _client: &Client) -> Result<Vec<u8>, EngineError> {
            Ok(vec![6])
        }

        fn state_proof(&self, _client: &Client, height: u64) -> Result<Vec<u8>, EngineError> {
            Ok(vec![u8::try_from(height).unwrap_or_default()])
        }

        fn packet_proofs(
            &self,
            request: &PacketProofsRequest,
        ) -> Result<Vec<Vec<u8>>, EngineError> {
            Ok(request.packets.iter().map(|_| vec![7]).collect())
        }
    }

    fn api() -> ProofApi<FakeEngine> {
        ProofApi::new(
            Arc::new(FakeEngine),
            ClientConfig {
                chain_id: "partior-1".into(),
                client_id: "prividium-0".into(),
                counterparty_client_id: "partior-0".into(),
                counterparty_merkle_prefix: vec!["0x".into()],
            },
            None,
            1,
            2,
            2,
        )
    }

    fn client() -> Client {
        Client {
            chain_id: "partior-1".into(),
            client_id: "prividium-0".into(),
        }
    }

    #[tokio::test]
    async fn validates_scope_and_preserves_packet_proof_cardinality() {
        let service = api();
        let wrong = ProverService::latest_provable_height(
            &service,
            Request::new(LatestProvableHeightRequest {
                client: Some(Client {
                    chain_id: "wrong".into(),
                    client_id: "prividium-0".into(),
                }),
            }),
        )
        .await;
        assert!(wrong.is_err());

        let response = ProverService::packet_proofs(
            &service,
            Request::new(PacketProofsRequest {
                client: Some(client()),
                height: 5,
                kind: 1,
                packets: vec![Packet::default(), Packet::default()],
            }),
        )
        .await;
        assert!(response.is_ok());
        if let Ok(value) = response {
            assert_eq!(value.into_inner().proofs, vec![vec![7], vec![7]]);
        }
    }

    #[tokio::test]
    async fn serves_height_trust_state_and_empty_packet_requests() {
        let service = api();
        let height = ProverService::latest_provable_height(
            &service,
            Request::new(LatestProvableHeightRequest {
                client: Some(client()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!((height.height, height.timestamp), (5, 99));

        let trust = ProverService::trust_update_proof(
            &service,
            Request::new(TrustUpdateProofRequest {
                client: Some(client()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(trust.proof, vec![6]);

        let state = ProverService::state_proof(
            &service,
            Request::new(StateProofRequest {
                client: Some(client()),
                height: 8,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(state.proof, vec![8]);

        let empty = ProverService::packet_proofs(
            &service,
            Request::new(PacketProofsRequest {
                client: Some(client()),
                height: 8,
                kind: 1,
                packets: vec![],
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(empty.proofs.is_empty());
    }

    #[tokio::test]
    async fn authentication_and_request_validation_fail_closed() {
        let service = ProofApi::new(
            Arc::new(FakeEngine),
            api().client,
            Some("Bearer secret".into()),
            1,
            1,
            1,
        );
        let missing = ProverService::latest_provable_height(
            &service,
            Request::new(LatestProvableHeightRequest {
                client: Some(client()),
            }),
        )
        .await;
        assert_eq!(missing.unwrap_err().code(), tonic::Code::Unauthenticated);

        let mut request = Request::new(StateProofRequest {
            client: Some(client()),
            height: 0,
        });
        request
            .metadata_mut()
            .insert("authorization", "Bearer secret".parse().unwrap());
        assert_eq!(
            ProverService::state_proof(&service, request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );

        let no_client = Request::new(LatestProvableHeightRequest { client: None });
        assert_eq!(
            ProverService::latest_provable_height(&api(), no_client)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn token_comparison_handles_equal_and_different_lengths() {
        assert!(constant_time_eq(b"Bearer abc", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer abc", b"Bearer abd"));
        assert!(!constant_time_eq(b"Bearer abc", b"Bearer abc0"));
    }

    #[test]
    fn overload_maps_to_resource_exhausted() {
        assert_eq!(
            engine_status(EngineError::ResourceExhausted("full".into())).code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            engine_status(EngineError::InvalidRequest("bad".into())).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            engine_status(EngineError::UnknownClient).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            engine_status(EngineError::Unavailable("wait".into())).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            engine_status(EngineError::Backend("backend".into())).code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            engine_status(EngineError::Internal("internal".into())).code(),
            tonic::Code::Internal
        );
    }
}
