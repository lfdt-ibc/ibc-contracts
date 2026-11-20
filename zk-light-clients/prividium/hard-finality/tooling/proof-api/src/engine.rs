// SPDX-License-Identifier: Apache-2.0

use crate::{
    artifact::{
        composite_update_envelope, membership_batch_artifacts, non_membership_envelope,
        settlement_envelope, trust_update_envelope, trust_update_envelope_and_state,
    },
    backend::ProofBackend,
    bootstrap::BootstrapMaterial,
    config::{ClientConfig, ResolvedIbcStorage},
    destination::{DestinationStateSource, TrustUpdateRegistrar},
    packet::validate_packets,
    proto::{Client, PacketProofsRequest, ProofKind},
    rpc::ProvableHeightSource,
    state::StateEvidenceSource,
    storage::PacketEvidenceSource,
    trust::TrustEvidenceSource,
    EngineError, ProofEngine,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ArtifactBindings {
    pub source_profile_id: [u8; 32],
    pub ibc: ResolvedIbcStorage,
    pub slots_per_sync_committee_period: u64,
    pub max_automatic_trust_updates: usize,
}
#[derive(Clone)]
pub struct ChainSources<H, P, S, D, R> {
    pub height: H,
    pub packet_evidence: P,
    pub state_evidence: S,
    pub destination_state: D,
    pub trust_update_registrar: R,
    pub trust_evidence: Arc<dyn TrustEvidenceSource>,
}

#[derive(Clone)]
pub struct PrividiumEngine<B, H, P, S, D, R> {
    scope: ClientConfig,
    backend: B,
    height_source: H,
    packet_evidence_source: P,
    state_evidence_source: S,
    destination_state_source: D,
    trust_update_registrar: R,
    trust_evidence_source: Arc<dyn TrustEvidenceSource>,
    bootstrap: Arc<BootstrapMaterial>,
    artifact_bindings: ArtifactBindings,
}

impl<
        B: ProofBackend,
        H: ProvableHeightSource,
        P: PacketEvidenceSource,
        S: StateEvidenceSource,
        D: DestinationStateSource,
        R: TrustUpdateRegistrar,
    > PrividiumEngine<B, H, P, S, D, R>
{
    pub fn new(
        scope: ClientConfig,
        backend: B,
        sources: ChainSources<H, P, S, D, R>,
        bootstrap: Arc<BootstrapMaterial>,
        artifact_bindings: ArtifactBindings,
    ) -> Self {
        Self {
            scope,
            backend,
            height_source: sources.height,
            packet_evidence_source: sources.packet_evidence,
            state_evidence_source: sources.state_evidence,
            destination_state_source: sources.destination_state,
            trust_update_registrar: sources.trust_update_registrar,
            trust_evidence_source: sources.trust_evidence,
            bootstrap,
            artifact_bindings,
        }
    }

    pub fn check_backend(&self) -> Result<(), EngineError> {
        self.backend.ready()
    }

    fn require_client(&self, client: &Client) -> Result<(), EngineError> {
        if client.chain_id == self.scope.chain_id && client.client_id == self.scope.client_id {
            Ok(())
        } else {
            Err(EngineError::UnknownClient)
        }
    }
}

impl<
        B: ProofBackend,
        H: ProvableHeightSource,
        P: PacketEvidenceSource,
        S: StateEvidenceSource,
        D: DestinationStateSource,
        R: TrustUpdateRegistrar,
    > ProofEngine for PrividiumEngine<B, H, P, S, D, R>
{
    fn latest_provable_height(&self, client: &Client) -> Result<(u64, u64), EngineError> {
        self.require_client(client)?;
        let _destination = self.destination_state_source.current_trust()?;
        self.height_source.latest_provable_height()
    }

    fn trust_update_proof(&self, client: &Client) -> Result<Vec<u8>, EngineError> {
        self.require_client(client)?;
        let trust_before = self.destination_state_source.current_trust()?;
        let evidence = self.trust_evidence_source.collect(&trust_before)?;
        let artifact =
            self.backend
                .trust_update(client, &self.bootstrap, &trust_before, &evidence)?;
        let envelope = trust_update_envelope(
            &artifact,
            self.artifact_bindings.source_profile_id,
            &trust_before,
        )?;
        let trust_after = self.destination_state_source.current_trust()?;
        require_unchanged_trust(trust_before, trust_after)?;
        Ok(envelope)
    }

    fn state_proof(&self, client: &Client, height: u64) -> Result<Vec<u8>, EngineError> {
        self.require_client(client)?;
        if height == 0 {
            return Err(EngineError::InvalidRequest("height must be nonzero".into()));
        }
        let trust_before = self.destination_state_source.current_trust()?;
        let mut stored_trust = trust_before;
        let evidence = self.state_evidence_source.collect(height)?;
        let signature_slot = optimistic_signature_slot(&evidence)?;
        let mut proving_trust = trust_before;
        let mut updates: Vec<Vec<u8>> = Vec::new();
        let mut update_states: Vec<crate::destination::TrustSnapshot> = Vec::new();
        while !signature_period_is_reachable(
            &proving_trust.state,
            signature_slot,
            self.artifact_bindings.slots_per_sync_committee_period,
        )? {
            if updates.len() >= self.artifact_bindings.max_automatic_trust_updates {
                let mut previous = stored_trust;
                for (update, next) in updates.iter().zip(&update_states) {
                    self.trust_update_registrar
                        .register_trust_update(update, &previous, next)?;
                    previous = *next;
                }
                let confirmed = self.destination_state_source.current_trust()?;
                if confirmed.digest != proving_trust.digest {
                    return Err(EngineError::Unavailable(
                        "automatic Trust Updates did not produce the expected destination trust"
                            .into(),
                    ));
                }
                stored_trust = confirmed;
                proving_trust.block_number = confirmed.block_number;
                updates.clear();
                update_states.clear();
            }
            let trust_evidence = self.trust_evidence_source.collect(&proving_trust)?;
            let trust_artifact = self.backend.trust_update(
                client,
                &self.bootstrap,
                &proving_trust,
                &trust_evidence,
            )?;
            let (envelope, next_state) = trust_update_envelope_and_state(
                &trust_artifact,
                self.artifact_bindings.source_profile_id,
                &proving_trust,
            )?;
            let next_digest = crate::destination::consensus_trust_digest(&next_state);
            if next_digest == proving_trust.digest {
                return Err(EngineError::Unavailable(
                    "Trust Update did not advance trust toward the Settlement signature period"
                        .into(),
                ));
            }
            updates.push(envelope);
            proving_trust = crate::destination::TrustSnapshot {
                block_number: trust_before.block_number,
                digest: next_digest,
                state: next_state,
            };
            update_states.push(proving_trust);
        }
        let signing_committee = self
            .trust_evidence_source
            .signing_committee(&proving_trust, signature_slot)?;
        let artifact = self.backend.state_proof(
            client,
            height,
            &self.bootstrap,
            &proving_trust,
            &signing_committee,
            &evidence,
        )?;
        let settlement = settlement_envelope(
            &artifact,
            self.artifact_bindings.source_profile_id,
            proving_trust.digest,
            &evidence,
        )?;
        let trust_after = self.destination_state_source.current_trust()?;
        require_unchanged_trust(stored_trust, trust_after)?;
        if updates.is_empty() {
            Ok(settlement)
        } else {
            updates.push(settlement);
            composite_update_envelope(&updates)
        }
    }

    fn packet_proofs(&self, request: &PacketProofsRequest) -> Result<Vec<Vec<u8>>, EngineError> {
        let client = request
            .client
            .as_ref()
            .ok_or_else(|| EngineError::InvalidRequest("client is required".into()))?;
        self.require_client(client)?;
        if request.height == 0 {
            return Err(EngineError::InvalidRequest("height must be nonzero".into()));
        }
        validate_packets(
            request,
            &self.scope.client_id,
            &self.scope.counterparty_client_id,
        )?;
        let _destination_before = self.destination_state_source.current_trust()?;
        let evidence = self
            .packet_evidence_source
            .collect(request, &self.scope.counterparty_client_id)?;
        if evidence.len() != request.packets.len() {
            return Err(EngineError::Internal(
                "packet evidence cardinality does not match request".into(),
            ));
        }
        let artifacts = self.backend.packet_proofs(request, &evidence)?;
        let kind = ProofKind::try_from(request.kind)
            .map_err(|_| EngineError::InvalidRequest("unsupported proof kind".into()))?;
        if matches!(
            kind,
            ProofKind::PacketCommitment | ProofKind::Acknowledgement
        ) {
            if artifacts.len() != 1 {
                return Err(EngineError::Backend(
                    "backend must return one shared Membership proof".into(),
                ));
            }
            let batch = membership_batch_artifacts(
                &artifacts[0],
                self.artifact_bindings.source_profile_id,
                self.artifact_bindings.ibc.store_address,
                request.height,
                &evidence,
            )?;
            if batch.relay_proofs.len() != request.packets.len() {
                return Err(EngineError::Backend(
                    "membership branch cardinality does not match request".into(),
                ));
            }
            let _destination_after = self.destination_state_source.current_trust()?;
            return Ok(batch.relay_proofs);
        }
        if artifacts.len() != request.packets.len() {
            return Err(EngineError::Backend(
                "backend returned incorrect Non-Membership proof cardinality".into(),
            ));
        }
        let envelopes = artifacts
            .iter()
            .zip(&evidence)
            .map(|(artifact, proof_evidence)| {
                non_membership_envelope(
                    artifact,
                    self.artifact_bindings.source_profile_id,
                    self.artifact_bindings.ibc.store_address,
                    self.artifact_bindings.ibc.absence_profile_id,
                    request.height,
                    proof_evidence,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let _destination_after = self.destination_state_source.current_trust()?;
        Ok(envelopes)
    }
}

fn optimistic_signature_slot(
    evidence: &crate::state::StateProofEvidence,
) -> Result<u64, EngineError> {
    let value = evidence
        .optimistic_update
        .pointer("/data/signature_slot")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| EngineError::Unavailable("optimistic update lacks signature slot".into()))?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EngineError::Unavailable(
            "optimistic update signature slot is not a canonical decimal u64".into(),
        ));
    }
    value.parse().map_err(|_| {
        EngineError::Unavailable("optimistic update signature slot exceeds u64".into())
    })
}

fn signature_period_is_reachable(
    trust: &crate::destination::ConsensusTrustState,
    signature_slot: u64,
    slots_per_period: u64,
) -> Result<bool, EngineError> {
    if slots_per_period == 0 {
        return Err(EngineError::Internal(
            "sync committee period contains zero slots".into(),
        ));
    }
    let trusted_period = trust.finalized_beacon_slot / slots_per_period;
    let signature_period = signature_slot / slots_per_period;
    if signature_period < trusted_period {
        return Err(EngineError::Unavailable(
            "optimistic update signature period is older than destination trust".into(),
        ));
    }
    Ok(signature_period == trusted_period
        || (signature_period == trusted_period.saturating_add(1)
            && trust.next_sync_committee_known))
}

fn require_unchanged_trust(
    before: crate::destination::TrustSnapshot,
    after: crate::destination::TrustSnapshot,
) -> Result<(), EngineError> {
    if after.digest != before.digest {
        return Err(EngineError::Unavailable(format!(
            "destination trust changed while proving (blocks {}..{}); retry",
            before.block_number, after.block_number
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        artifact::ProofArtifact,
        destination::{ConsensusTrustState, TrustSnapshot},
        proto::{Packet, Payload},
        state::StateProofEvidence,
        storage::PacketProofEvidence,
        trust::TrustUpdateEvidence,
    };
    use sha3::{Digest as _, Keccak256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    #[derive(Clone)]
    struct Backend;
    impl ProofBackend for Backend {
        fn ready(&self) -> Result<(), EngineError> {
            Ok(())
        }
        fn trust_update(
            &self,
            _: &Client,
            _: &BootstrapMaterial,
            _: &TrustSnapshot,
            _: &TrustUpdateEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            Err(EngineError::Backend("stop after trust evidence".into()))
        }
        fn state_proof(
            &self,
            _: &Client,
            _: u64,
            _: &BootstrapMaterial,
            _: &TrustSnapshot,
            _: &crate::bootstrap::SyncCommittee,
            _: &StateProofEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            Err(EngineError::Backend("stop after state evidence".into()))
        }
        fn packet_proofs(
            &self,
            _: &PacketProofsRequest,
            _: &[PacketProofEvidence],
        ) -> Result<Vec<ProofArtifact>, EngineError> {
            Ok(vec![])
        }
    }

    #[derive(Clone)]
    struct Height;
    impl ProvableHeightSource for Height {
        fn latest_provable_height(&self) -> Result<(u64, u64), EngineError> {
            Ok((99, 100))
        }
    }

    #[derive(Clone)]
    struct Packets;
    impl PacketEvidenceSource for Packets {
        fn collect(
            &self,
            _: &PacketProofsRequest,
            _: &str,
        ) -> Result<Vec<PacketProofEvidence>, EngineError> {
            Ok(vec![])
        }
    }

    #[derive(Clone)]
    struct State;
    impl StateEvidenceSource for State {
        fn collect(&self, _: u64) -> Result<StateProofEvidence, EngineError> {
            Err(EngineError::Unavailable("state fixture stop".into()))
        }
    }

    #[derive(Clone)]
    struct Destination;
    impl DestinationStateSource for Destination {
        fn current_trust(&self) -> Result<TrustSnapshot, EngineError> {
            Ok(snapshot())
        }
    }

    #[derive(Clone)]
    struct Registrar;
    impl TrustUpdateRegistrar for Registrar {
        fn register_trust_update(
            &self,
            _: &[u8],
            _: &TrustSnapshot,
            _: &TrustSnapshot,
        ) -> Result<(), EngineError> {
            Ok(())
        }
    }

    struct Trust;
    impl TrustEvidenceSource for Trust {
        fn collect(&self, _: &TrustSnapshot) -> Result<TrustUpdateEvidence, EngineError> {
            Err(EngineError::Unavailable("trust fixture stop".into()))
        }

        fn signing_committee(
            &self,
            _: &TrustSnapshot,
            _: u64,
        ) -> Result<crate::bootstrap::SyncCommittee, EngineError> {
            Err(EngineError::Unavailable("committee fixture stop".into()))
        }
    }

    fn snapshot() -> TrustSnapshot {
        TrustSnapshot {
            block_number: 10,
            digest: [0x11; 32],
            state: ConsensusTrustState {
                finalized_beacon_slot: 1,
                finalized_beacon_header_root: [1; 32],
                current_sync_committee_root: [2; 32],
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: false,
            },
        }
    }

    fn engine() -> PrividiumEngine<Backend, Height, Packets, State, Destination, Registrar> {
        PrividiumEngine::new(
            ClientConfig {
                chain_id: "1337".into(),
                client_id: "6565".into(),
                counterparty_client_id: "1337".into(),
                counterparty_merkle_prefix: vec!["0x00".into()],
            },
            Backend,
            ChainSources {
                height: Height,
                packet_evidence: Packets,
                state_evidence: State,
                destination_state: Destination,
                trust_update_registrar: Registrar,
                trust_evidence: Arc::new(Trust),
            },
            Arc::new(BootstrapMaterial::Lighthouse {
                response: serde_json::json!({}),
            }),
            ArtifactBindings {
                source_profile_id: [1; 32],
                ibc: ResolvedIbcStorage {
                    store_address: [2; 20],
                    mapping_base_slot: [3; 32],
                    native_root_probe_slot: [4; 32],
                    absence_profile_id: 1,
                    max_client_id_bytes: 128,
                },
                slots_per_sync_committee_period: 8,
                max_automatic_trust_updates: 8,
            },
        )
    }

    fn client() -> Client {
        Client {
            chain_id: "1337".into(),
            client_id: "6565".into(),
        }
    }

    fn packet() -> Packet {
        Packet {
            sequence: 1,
            source_client: "1337".into(),
            destination_client: "6565".into(),
            timeout_timestamp: 100,
            payloads: vec![Payload {
                source_port: "transfer".into(),
                destination_port: "transfer".into(),
                version: "1".into(),
                encoding: "bytes".into(),
                value: vec![1],
            }],
        }
    }

    fn push_u64(output: &mut Vec<u8>, value: u64) {
        output.extend_from_slice(&[0; 24]);
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn push_word(output: &mut Vec<u8>, value: [u8; 32]) {
        output.extend_from_slice(&value);
    }

    #[derive(Clone)]
    struct HappyBackend;
    impl ProofBackend for HappyBackend {
        fn ready(&self) -> Result<(), EngineError> {
            Ok(())
        }
        fn trust_update(
            &self,
            _: &Client,
            _: &BootstrapMaterial,
            trust: &TrustSnapshot,
            _: &TrustUpdateEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            let mut values = vec![];
            push_u64(&mut values, 1);
            push_u64(&mut values, 1);
            push_word(&mut values, [1; 32]);
            push_word(&mut values, trust.digest);
            push_u64(&mut values, 10);
            push_u64(&mut values, 8);
            push_word(&mut values, [3; 32]);
            push_word(&mut values, [4; 32]);
            push_word(&mut values, [0; 32]);
            push_u64(&mut values, 0);
            Ok(ProofArtifact {
                program: "trust-update".into(),
                source_profile_id: [1; 32],
                public_values: values,
                proof: vec![1],
            })
        }
        fn state_proof(
            &self,
            _: &Client,
            _: u64,
            _: &BootstrapMaterial,
            trust: &TrustSnapshot,
            _: &crate::bootstrap::SyncCommittee,
            evidence: &StateProofEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            let mut values = vec![];
            push_u64(&mut values, 1);
            push_u64(&mut values, 3);
            push_word(&mut values, [1; 32]);
            push_word(&mut values, trust.digest);
            push_u64(&mut values, evidence.target_l2_block);
            push_u64(&mut values, evidence.candidate_batch);
            push_word(&mut values, [5; 32]);
            push_u64(&mut values, evidence.l2_batch_timestamp);
            Ok(ProofArtifact {
                program: "settlement-update".into(),
                source_profile_id: [1; 32],
                public_values: values,
                proof: vec![2],
            })
        }
        fn packet_proofs(
            &self,
            request: &PacketProofsRequest,
            evidence: &[PacketProofEvidence],
        ) -> Result<Vec<ProofArtifact>, EngineError> {
            let item = evidence
                .first()
                .ok_or_else(|| EngineError::Internal("missing evidence".into()))?;
            let path = hex::decode(item.logical_path.trim_start_matches("0x")).unwrap();
            let value: [u8; 32] = hex::decode(
                item.expected_application_value
                    .as_deref()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap()
            .try_into()
            .unwrap();
            let mut leaf_preimage = vec![];
            push_word(&mut leaf_preimage, *b"PRIVIDIUM_MEMBERSHIP_LEAF_V1____");
            push_u64(&mut leaf_preimage, 0);
            push_word(&mut leaf_preimage, Keccak256::digest(path).into());
            push_word(&mut leaf_preimage, Keccak256::digest(value).into());
            let batch_root: [u8; 32] = Keccak256::digest(leaf_preimage).into();
            let mut values = vec![];
            push_u64(&mut values, 1);
            push_u64(&mut values, 2);
            push_word(&mut values, [1; 32]);
            push_u64(&mut values, request.height);
            push_u64(&mut values, item.l1_batch_number);
            push_word(&mut values, [6; 32]);
            let mut address = [0; 32];
            address[12..].copy_from_slice(&[2; 20]);
            push_word(&mut values, address);
            push_u64(&mut values, 1);
            push_word(&mut values, batch_root);
            let digest: [u8; 32] = Keccak256::digest(&values).into();
            push_word(&mut values, digest);
            Ok(vec![ProofArtifact {
                program: "membership".into(),
                source_profile_id: [1; 32],
                public_values: values,
                proof: vec![3],
            }])
        }
    }

    #[derive(Clone)]
    struct HappyState;
    impl StateEvidenceSource for HappyState {
        fn collect(&self, _: u64) -> Result<StateProofEvidence, EngineError> {
            Ok(StateProofEvidence {
                candidate_batch: 1,
                target_l2_block: 2,
                l2_batch_timestamp: 3,
                settlement_storage_slot: format!("0x{}", "11".repeat(32)),
                total_batches_executed_slot: format!("0x{}", "12".repeat(32)),
                native_root_proof: serde_json::json!({}),
                optimistic_update: serde_json::json!({"data":{"signature_slot":"2"}}),
                settlement_account_proof: serde_json::json!({}),
            })
        }
    }

    #[derive(Clone)]
    struct NextPeriodState;
    impl StateEvidenceSource for NextPeriodState {
        fn collect(&self, _: u64) -> Result<StateProofEvidence, EngineError> {
            let mut evidence = HappyState.collect(1)?;
            evidence.optimistic_update = serde_json::json!({"data":{"signature_slot":"9"}});
            Ok(evidence)
        }
    }

    #[derive(Clone)]
    struct HappyPackets;
    impl PacketEvidenceSource for HappyPackets {
        fn collect(
            &self,
            request: &PacketProofsRequest,
            counterparty: &str,
        ) -> Result<Vec<PacketProofEvidence>, EngineError> {
            let mut path = counterparty.as_bytes().to_vec();
            path.push(1);
            path.extend_from_slice(&request.packets[0].sequence.to_be_bytes());
            Ok(vec![PacketProofEvidence {
                l2_block_number: 2,
                l1_batch_number: 1,
                logical_path: format!("0x{}", hex::encode(path)),
                storage_slot: format!("0x{}", "11".repeat(32)),
                expected_application_value: Some(format!("0x{}", "22".repeat(32))),
                zks_get_proof: serde_json::json!({}),
            }])
        }
    }

    struct HappyTrust;
    impl TrustEvidenceSource for HappyTrust {
        fn collect(&self, _: &TrustSnapshot) -> Result<TrustUpdateEvidence, EngineError> {
            Ok(TrustUpdateEvidence {
                start_period: 0,
                signing_sync_committee: crate::bootstrap::SyncCommittee {
                    pubkeys: vec![],
                    aggregate_pubkey: "0x".into(),
                },
                update: serde_json::json!({}),
            })
        }

        fn signing_committee(
            &self,
            _: &TrustSnapshot,
            _: u64,
        ) -> Result<crate::bootstrap::SyncCommittee, EngineError> {
            Ok(crate::bootstrap::SyncCommittee {
                pubkeys: vec![],
                aggregate_pubkey: "0x".into(),
            })
        }
    }

    #[derive(Clone)]
    struct AdvancingDestination(Arc<Mutex<TrustSnapshot>>);
    impl DestinationStateSource for AdvancingDestination {
        fn current_trust(&self) -> Result<TrustSnapshot, EngineError> {
            self.0
                .lock()
                .map(|state| *state)
                .map_err(|_| EngineError::Internal("test trust lock poisoned".into()))
        }
    }

    #[derive(Clone)]
    struct CatchUpRegistrar {
        state: Arc<Mutex<TrustSnapshot>>,
        submissions: Arc<AtomicUsize>,
    }
    impl TrustUpdateRegistrar for CatchUpRegistrar {
        fn register_trust_update(
            &self,
            _: &[u8],
            expected_before: &TrustSnapshot,
            expected_after: &TrustSnapshot,
        ) -> Result<(), EngineError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| EngineError::Internal("test registrar lock poisoned".into()))?;
            if state.digest != expected_before.digest {
                return Err(EngineError::Unavailable("test trust changed".into()));
            }
            *state = *expected_after;
            self.submissions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct AdvancingBackend;
    impl ProofBackend for AdvancingBackend {
        fn ready(&self) -> Result<(), EngineError> {
            Ok(())
        }

        fn trust_update(
            &self,
            _: &Client,
            _: &BootstrapMaterial,
            trust: &TrustSnapshot,
            _: &TrustUpdateEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            let period = trust.state.finalized_beacon_slot / 8 + 1;
            let finalized_slot = period * 8;
            let marker = u8::try_from(period).unwrap();
            let mut values = vec![];
            push_u64(&mut values, 1);
            push_u64(&mut values, 1);
            push_word(&mut values, [1; 32]);
            push_word(&mut values, trust.digest);
            push_u64(&mut values, finalized_slot + 1);
            push_u64(&mut values, finalized_slot);
            push_word(&mut values, [marker; 32]);
            push_word(&mut values, [marker.saturating_add(16); 32]);
            push_word(&mut values, [0; 32]);
            push_u64(&mut values, 0);
            Ok(ProofArtifact {
                program: "trust-update".into(),
                source_profile_id: [1; 32],
                public_values: values,
                proof: vec![1],
            })
        }

        fn state_proof(
            &self,
            client: &Client,
            height: u64,
            bootstrap: &BootstrapMaterial,
            trust: &TrustSnapshot,
            signing_committee: &crate::bootstrap::SyncCommittee,
            evidence: &StateProofEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            HappyBackend.state_proof(
                client,
                height,
                bootstrap,
                trust,
                signing_committee,
                evidence,
            )
        }

        fn packet_proofs(
            &self,
            request: &PacketProofsRequest,
            evidence: &[PacketProofEvidence],
        ) -> Result<Vec<ProofArtifact>, EngineError> {
            HappyBackend.packet_proofs(request, evidence)
        }
    }

    #[derive(Clone)]
    struct FarPeriodState;
    impl StateEvidenceSource for FarPeriodState {
        fn collect(&self, _: u64) -> Result<StateProofEvidence, EngineError> {
            let mut evidence = HappyState.collect(1)?;
            evidence.optimistic_update = serde_json::json!({"data":{"signature_slot":"25"}});
            Ok(evidence)
        }
    }

    #[test]
    fn stale_trust_is_rejected_but_block_advancement_is_allowed() {
        let state = ConsensusTrustState {
            finalized_beacon_slot: 1,
            finalized_beacon_header_root: [1; 32],
            current_sync_committee_root: [2; 32],
            next_sync_committee_root: [0; 32],
            next_sync_committee_known: false,
        };
        let before = crate::destination::TrustSnapshot {
            block_number: 10,
            digest: [0x11; 32],
            state,
        };
        let same_trust = crate::destination::TrustSnapshot {
            block_number: 12,
            digest: before.digest,
            state,
        };
        assert_eq!(require_unchanged_trust(before, same_trust), Ok(()));

        let changed = crate::destination::TrustSnapshot {
            block_number: 13,
            digest: [0x12; 32],
            state,
        };
        assert!(require_unchanged_trust(before, changed).is_err());
    }

    #[test]
    fn signature_period_reachability_is_strict() {
        let mut trust = snapshot().state;
        assert_eq!(signature_period_is_reachable(&trust, 7, 8), Ok(true));
        assert_eq!(signature_period_is_reachable(&trust, 8, 8), Ok(false));
        trust.next_sync_committee_known = true;
        trust.next_sync_committee_root = [3; 32];
        assert_eq!(signature_period_is_reachable(&trust, 8, 8), Ok(true));
        assert!(signature_period_is_reachable(&trust, 16, 8).is_ok_and(|value| !value));

        trust.finalized_beacon_slot = 8;
        assert!(signature_period_is_reachable(&trust, 7, 8).is_err());
        assert!(signature_period_is_reachable(&trust, 8, 0).is_err());

        let mut evidence = HappyState.collect(1).unwrap();
        for invalid in ["", "01", "-1", "18446744073709551616"] {
            evidence.optimistic_update = serde_json::json!({"data":{"signature_slot":invalid}});
            assert!(optimistic_signature_slot(&evidence).is_err());
        }
    }

    #[test]
    fn engine_routes_all_requests_through_scope_and_evidence_guards() {
        let engine = engine();
        assert!(engine.check_backend().is_ok());
        assert_eq!(engine.latest_provable_height(&client()), Ok((99, 100)));
        let wrong = Client {
            chain_id: "wrong".into(),
            client_id: "6565".into(),
        };
        assert_eq!(
            engine.latest_provable_height(&wrong),
            Err(EngineError::UnknownClient)
        );
        assert!(engine.trust_update_proof(&client()).is_err());
        assert!(engine.state_proof(&client(), 0).is_err());
        assert!(engine.state_proof(&client(), 1).is_err());

        let missing = PacketProofsRequest {
            client: None,
            height: 1,
            kind: ProofKind::PacketCommitment as i32,
            packets: vec![packet()],
        };
        assert!(engine.packet_proofs(&missing).is_err());
        let zero = PacketProofsRequest {
            client: Some(client()),
            height: 0,
            ..missing.clone()
        };
        assert!(engine.packet_proofs(&zero).is_err());
        let valid = PacketProofsRequest {
            client: Some(client()),
            height: 1,
            kind: ProofKind::PacketCommitment as i32,
            packets: vec![packet()],
        };
        assert!(engine.packet_proofs(&valid).is_err());
    }

    #[test]
    fn successful_engine_flow_builds_all_three_envelope_kinds() {
        let engine = PrividiumEngine::new(
            ClientConfig {
                chain_id: "1337".into(),
                client_id: "6565".into(),
                counterparty_client_id: "1337".into(),
                counterparty_merkle_prefix: vec!["0x00".into()],
            },
            HappyBackend,
            ChainSources {
                height: Height,
                packet_evidence: HappyPackets,
                state_evidence: HappyState,
                destination_state: Destination,
                trust_update_registrar: Registrar,
                trust_evidence: Arc::new(HappyTrust),
            },
            Arc::new(BootstrapMaterial::Lighthouse {
                response: serde_json::json!({}),
            }),
            ArtifactBindings {
                source_profile_id: [1; 32],
                ibc: ResolvedIbcStorage {
                    store_address: [2; 20],
                    mapping_base_slot: [3; 32],
                    native_root_probe_slot: [4; 32],
                    absence_profile_id: 1,
                    max_client_id_bytes: 128,
                },
                slots_per_sync_committee_period: 8,
                max_automatic_trust_updates: 8,
            },
        );
        assert!(!engine.trust_update_proof(&client()).unwrap().is_empty());
        assert!(!engine.state_proof(&client(), 1).unwrap().is_empty());
        let request = PacketProofsRequest {
            client: Some(client()),
            height: 2,
            kind: ProofKind::PacketCommitment as i32,
            packets: vec![packet()],
        };
        let proofs = engine.packet_proofs(&request).unwrap();
        assert_eq!(proofs.len(), 1);
        assert!(!proofs[0].is_empty());
    }

    #[test]
    fn state_proof_bundles_required_trust_update_for_standard_relayer_flow() {
        let engine = PrividiumEngine::new(
            ClientConfig {
                chain_id: "1337".into(),
                client_id: "6565".into(),
                counterparty_client_id: "1337".into(),
                counterparty_merkle_prefix: vec!["0x00".into()],
            },
            HappyBackend,
            ChainSources {
                height: Height,
                packet_evidence: HappyPackets,
                state_evidence: NextPeriodState,
                destination_state: Destination,
                trust_update_registrar: Registrar,
                trust_evidence: Arc::new(HappyTrust),
            },
            Arc::new(BootstrapMaterial::Lighthouse {
                response: serde_json::json!({}),
            }),
            ArtifactBindings {
                source_profile_id: [1; 32],
                ibc: ResolvedIbcStorage {
                    store_address: [2; 20],
                    mapping_base_slot: [3; 32],
                    native_root_probe_slot: [4; 32],
                    absence_profile_id: 1,
                    max_client_id_bytes: 128,
                },
                slots_per_sync_committee_period: 8,
                max_automatic_trust_updates: 1,
            },
        );

        let envelope = engine.state_proof(&client(), 1).unwrap();
        assert_eq!(&envelope[24..32], &2_u64.to_be_bytes());
    }

    #[test]
    fn state_proof_submits_bounded_catch_up_chunks_before_settlement() {
        let state = Arc::new(Mutex::new(snapshot()));
        let submissions = Arc::new(AtomicUsize::new(0));
        let registrar = CatchUpRegistrar {
            state: state.clone(),
            submissions: submissions.clone(),
        };
        let engine = PrividiumEngine::new(
            ClientConfig {
                chain_id: "1337".into(),
                client_id: "6565".into(),
                counterparty_client_id: "1337".into(),
                counterparty_merkle_prefix: vec!["0x00".into()],
            },
            AdvancingBackend,
            ChainSources {
                height: Height,
                packet_evidence: HappyPackets,
                state_evidence: FarPeriodState,
                destination_state: AdvancingDestination(state.clone()),
                trust_update_registrar: registrar,
                trust_evidence: Arc::new(HappyTrust),
            },
            Arc::new(BootstrapMaterial::Lighthouse {
                response: serde_json::json!({}),
            }),
            ArtifactBindings {
                source_profile_id: [1; 32],
                ibc: ResolvedIbcStorage {
                    store_address: [2; 20],
                    mapping_base_slot: [3; 32],
                    native_root_probe_slot: [4; 32],
                    absence_profile_id: 1,
                    max_client_id_bytes: 128,
                },
                slots_per_sync_committee_period: 8,
                max_automatic_trust_updates: 1,
            },
        );

        let envelope = engine.state_proof(&client(), 1).unwrap();
        assert!(!envelope.is_empty());
        assert_eq!(submissions.load(Ordering::SeqCst), 2);
        assert_eq!(state.lock().unwrap().state.finalized_beacon_slot, 16);
    }
}
