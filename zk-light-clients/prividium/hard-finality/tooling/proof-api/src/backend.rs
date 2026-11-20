// SPDX-License-Identifier: Apache-2.0

use crate::{
    artifact::ProofArtifact,
    bootstrap::{BootstrapMaterial, SyncCommittee},
    destination::TrustSnapshot,
    proto,
    state::StateProofEvidence,
    storage::PacketProofEvidence,
    trust::TrustUpdateEvidence,
    EngineError,
};

pub trait ProofBackend: Send + Sync + 'static {
    fn ready(&self) -> Result<(), EngineError>;
    fn trust_update(
        &self,
        client: &proto::Client,
        bootstrap: &BootstrapMaterial,
        trust: &TrustSnapshot,
        evidence: &TrustUpdateEvidence,
    ) -> Result<ProofArtifact, EngineError>;
    fn state_proof(
        &self,
        client: &proto::Client,
        height: u64,
        bootstrap: &BootstrapMaterial,
        trust: &TrustSnapshot,
        signing_committee: &SyncCommittee,
        evidence: &StateProofEvidence,
    ) -> Result<ProofArtifact, EngineError>;
    fn packet_proofs(
        &self,
        request: &proto::PacketProofsRequest,
        evidence: &[PacketProofEvidence],
    ) -> Result<Vec<ProofArtifact>, EngineError>;
}

#[cfg(feature = "sp1")]
mod direct {
    use super::{
        proto, BootstrapMaterial, EngineError, PacketProofEvidence, ProofArtifact, ProofBackend,
        StateProofEvidence, SyncCommittee, TrustSnapshot, TrustUpdateEvidence,
    };
    use crate::{
        config::{ResolvedDestination, ResolvedProver},
        proto::ProofKind,
        witness::{
            membership_witness, non_membership_witnesses, settlement_witness, trust_update_witness,
            validate_membership_kind,
        },
    };
    use serde::Serialize;
    use sp1_sdk::{
        blocking::{NetworkProver, ProveRequest, Prover, ProverClient, SP1Stdin},
        include_elf, Elf, HashableKey, ProvingKey, SP1ProvingKey,
    };
    use std::{sync::Arc, time::Instant};

    const TRUST_UPDATE_ELF: Elf = include_elf!("prividium-trust-update-program");
    const SETTLEMENT_UPDATE_ELF: Elf = include_elf!("prividium-settlement-update-program");
    const MEMBERSHIP_ELF: Elf = include_elf!("prividium-membership-program");
    const NON_MEMBERSHIP_ELF: Elf = include_elf!("prividium-non-membership-program");

    #[derive(Clone)]
    pub struct Sp1Backend {
        inner: Arc<Sp1BackendInner>,
    }

    struct Sp1BackendInner {
        prover: NetworkProver,
        trust_update: Program,
        settlement_update: Program,
        membership: Program,
        non_membership: Program,
        source_profile_id: [u8; 32],
        proof_timeout: std::time::Duration,
    }

    struct Program {
        name: &'static str,
        proving_key: SP1ProvingKey,
        vkey: [u8; 32],
    }

    impl Sp1Backend {
        pub fn new(
            config: &ResolvedProver,
            destination: &ResolvedDestination,
            source_profile_id: [u8; 32],
        ) -> Result<Self, EngineError> {
            let started = Instant::now();
            let prover = ProverClient::builder()
                .hosted()
                .rpc_url(config.network_rpc_url.as_str())
                .private_key(&config.network_private_key)
                .build();
            let trust_update = setup_program(&prover, "trust-update", TRUST_UPDATE_ELF)?;
            let settlement_update =
                setup_program(&prover, "settlement-update", SETTLEMENT_UPDATE_ELF)?;
            let membership = setup_program(&prover, "membership", MEMBERSHIP_ELF)?;
            let non_membership = setup_program(&prover, "non-membership", NON_MEMBERSHIP_ELF)?;
            let actual = [
                trust_update.vkey,
                settlement_update.vkey,
                membership.vkey,
                non_membership.vkey,
            ];
            let expected = [
                destination.trust_update_vkey,
                destination.settlement_update_vkey,
                destination.membership_vkey,
                destination.non_membership_vkey,
            ];
            if actual != expected {
                return Err(EngineError::Internal(format!(
                    "embedded ELF VKeys do not match destination configuration: trust=0x{}, settlement=0x{}, membership=0x{}, non-membership=0x{}",
                    hex::encode(actual[0]),
                    hex::encode(actual[1]),
                    hex::encode(actual[2]),
                    hex::encode(actual[3])
                )));
            }
            eprintln!(
                "SP1 timing: stage=backend-initialize elapsed={:.3}s",
                started.elapsed().as_secs_f64()
            );
            Ok(Self {
                inner: Arc::new(Sp1BackendInner {
                    prover,
                    trust_update,
                    settlement_update,
                    membership,
                    non_membership,
                    source_profile_id,
                    proof_timeout: config.proof_timeout,
                }),
            })
        }

        fn prove<T: Serialize>(
            &self,
            program: &Program,
            witness: &T,
        ) -> Result<ProofArtifact, EngineError> {
            let witness_started = Instant::now();
            let mut stdin = SP1Stdin::new();
            stdin.write(witness);
            eprintln!(
                "SP1 timing: program={} stage=witness-encode elapsed={:.3}s",
                program.name,
                witness_started.elapsed().as_secs_f64()
            );
            let proving_started = Instant::now();
            let proof = self
                .inner
                .prover
                .prove(&program.proving_key, stdin)
                .groth16()
                .timeout(self.inner.proof_timeout)
                .run()
                .map_err(|error| {
                    EngineError::Backend(format!("{} SP1 proving failed: {error}", program.name))
                })?;
            eprintln!(
                "SP1 timing: program={} stage=prove-groth16 elapsed={:.3}s",
                program.name,
                proving_started.elapsed().as_secs_f64()
            );
            let verify_started = Instant::now();
            self.inner
                .prover
                .verify(&proof, program.proving_key.verifying_key(), None)
                .map_err(|error| {
                    EngineError::Backend(format!(
                        "{} local SP1 verification failed: {error}",
                        program.name
                    ))
                })?;
            eprintln!(
                "SP1 timing: program={} stage=local-verify elapsed={:.3}s",
                program.name,
                verify_started.elapsed().as_secs_f64()
            );
            let public_values = proof.public_values.as_slice().to_vec();
            let proof = proof.bytes();
            if public_values.is_empty() || proof.is_empty() {
                return Err(EngineError::Backend(format!(
                    "{} prover returned an empty proof artifact",
                    program.name
                )));
            }
            Ok(ProofArtifact {
                program: program.name.into(),
                source_profile_id: self.inner.source_profile_id,
                public_values,
                proof,
            })
        }
    }

    impl ProofBackend for Sp1Backend {
        fn ready(&self) -> Result<(), EngineError> {
            self.inner
                .prover
                .get_balance()
                .map(|_| ())
                .map_err(|error| {
                    EngineError::Unavailable(format!("SP1 gateway is not ready: {error}"))
                })
        }

        fn trust_update(
            &self,
            _client: &proto::Client,
            _bootstrap: &BootstrapMaterial,
            trust: &TrustSnapshot,
            evidence: &TrustUpdateEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            self.prove(
                &self.inner.trust_update,
                &trust_update_witness(trust, evidence)?,
            )
        }

        fn state_proof(
            &self,
            _client: &proto::Client,
            _height: u64,
            _bootstrap: &BootstrapMaterial,
            trust: &TrustSnapshot,
            signing_committee: &SyncCommittee,
            evidence: &StateProofEvidence,
        ) -> Result<ProofArtifact, EngineError> {
            self.prove(
                &self.inner.settlement_update,
                &settlement_witness(trust, signing_committee, evidence)?,
            )
        }

        fn packet_proofs(
            &self,
            request: &proto::PacketProofsRequest,
            evidence: &[PacketProofEvidence],
        ) -> Result<Vec<ProofArtifact>, EngineError> {
            let kind = ProofKind::try_from(request.kind)
                .map_err(|_| EngineError::InvalidRequest("unsupported proof kind".into()))?;
            if matches!(kind, ProofKind::ReceiptAbsence) {
                return non_membership_witnesses(request, evidence)?
                    .iter()
                    .map(|witness| self.prove(&self.inner.non_membership, witness))
                    .collect();
            }
            validate_membership_kind(request)?;
            Ok(vec![self.prove(
                &self.inner.membership,
                &membership_witness(request, evidence)?,
            )?])
        }
    }

    fn setup_program(
        prover: &NetworkProver,
        name: &'static str,
        elf: Elf,
    ) -> Result<Program, EngineError> {
        let started = Instant::now();
        let proving_key = prover.setup(elf).map_err(|error| {
            EngineError::Internal(format!("set up {name} SP1 program: {error}"))
        })?;
        let value = proving_key.verifying_key().bytes32();
        let body = value.strip_prefix("0x").unwrap_or(&value);
        let vkey: [u8; 32] = hex::decode(body)
            .map_err(|_| EngineError::Internal(format!("{name} VKey is invalid hex")))?
            .try_into()
            .map_err(|_| EngineError::Internal(format!("{name} VKey must be 32 bytes")))?;
        eprintln!(
            "SP1 timing: program={name} stage=setup elapsed={:.3}s vkey=0x{}",
            started.elapsed().as_secs_f64(),
            hex::encode(vkey)
        );
        Ok(Program {
            name,
            proving_key,
            vkey,
        })
    }
}

#[cfg(feature = "sp1")]
pub use direct::Sp1Backend;
