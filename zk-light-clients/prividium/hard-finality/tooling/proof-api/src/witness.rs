// SPDX-License-Identifier: Apache-2.0

use crate::{
    bootstrap::SyncCommittee as BootstrapCommittee,
    destination::TrustSnapshot,
    proto::{PacketProofsRequest, ProofKind},
    state::StateProofEvidence,
    storage::PacketProofEvidence,
    trust::{validate_settlement_attested_header, TrustUpdateEvidence},
    EngineError,
};
use prividium_types::{
    BeaconBlockHeader, ConsensusTrustState, EvmStorageProofWitness,
    ExecutionPayloadHeaderFuluCompatibility, FixedBytes, ForkExecutionPayloadHeader,
    LightClientHeader, LightClientUpdateWitness, MembershipEntryWitness, MembershipWitness,
    NonMembershipWitness, OptimisticUpdateWitness, SettlementWitness, SyncAggregate, SyncCommittee,
    TrustUpdateWitness,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned<T> {
    version: String,
    data: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrustUpdate {
    attested_header: RawLightClientHeader,
    finalized_header: RawLightClientHeader,
    finality_branch: Vec<String>,
    next_sync_committee: RawSyncCommittee,
    next_sync_committee_branch: Vec<String>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOptimisticUpdate {
    attested_header: RawLightClientHeader,
    sync_aggregate: RawSyncAggregate,
    signature_slot: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLightClientHeader {
    beacon: RawBeaconHeader,
    execution: RawExecutionPayloadHeader,
    execution_branch: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBeaconHeader {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
    body_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecutionPayloadHeader {
    parent_hash: String,
    fee_recipient: String,
    state_root: String,
    receipts_root: String,
    logs_bloom: String,
    prev_randao: String,
    block_number: String,
    gas_limit: String,
    gas_used: String,
    timestamp: String,
    extra_data: String,
    base_fee_per_gas: String,
    block_hash: String,
    transactions_root: String,
    withdrawals_root: String,
    blob_gas_used: String,
    excess_blob_gas: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSyncAggregate {
    sync_committee_bits: String,
    sync_committee_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSyncCommittee {
    pubkeys: Vec<String>,
    aggregate_pubkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: serde_json::Value,
    result: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EthGetProof {
    address: String,
    account_proof: Vec<String>,
    balance: String,
    code_hash: String,
    nonce: String,
    storage_hash: String,
    storage_proof: Vec<EthStorageProof>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EthStorageProof {
    key: String,
    proof: Vec<String>,
    value: String,
}

pub(crate) fn trust_update_witness(
    previous: &TrustSnapshot,
    evidence: &TrustUpdateEvidence,
) -> Result<TrustUpdateWitness, EngineError> {
    let raw: Versioned<RawTrustUpdate> = serde_json::from_value(evidence.update.clone())
        .map_err(|error| EngineError::InvalidRequest(format!("Beacon Trust Update: {error}")))?;
    require_fulu(&raw.version)?;
    Ok(TrustUpdateWitness {
        schema_version: 1,
        previous_trust: circuit_trust(previous),
        full_signing_sync_committee: circuit_committee(&evidence.signing_sync_committee)?,
        update: LightClientUpdateWitness {
            attested_header: light_client_header(raw.data.attested_header)?,
            finalized_header: light_client_header(raw.data.finalized_header)?,
            finality_branch: hashes("finality branch", &raw.data.finality_branch)?,
            next_sync_committee: raw_committee(raw.data.next_sync_committee)?,
            next_sync_committee_branch: hashes(
                "next sync committee branch",
                &raw.data.next_sync_committee_branch,
            )?,
            sync_aggregate: sync_aggregate(&raw.data.sync_aggregate)?,
            signature_slot: decimal_u64("signature slot", &raw.data.signature_slot)?,
        },
    })
}

pub(crate) fn settlement_witness(
    previous: &TrustSnapshot,
    signing_committee: &BootstrapCommittee,
    evidence: &StateProofEvidence,
) -> Result<SettlementWitness, EngineError> {
    let raw: Versioned<RawOptimisticUpdate> =
        serde_json::from_value(evidence.optimistic_update.clone()).map_err(|error| {
            EngineError::InvalidRequest(format!("Beacon optimistic update: {error}"))
        })?;
    require_fulu(&raw.version)?;
    let attested_header = light_client_header(raw.data.attested_header)?;
    let attested_root =
        prividium_ssz::beacon_block_header_root(&attested_header.beacon).map_err(|error| {
            EngineError::InvalidRequest(format!("Beacon optimistic header: {error:?}"))
        })?;
    validate_settlement_attested_header(previous, attested_header.beacon.slot, attested_root)?;
    let zks_bytes = serde_json::to_vec(&evidence.native_root_proof)
        .map_err(|error| EngineError::Internal(format!("encode zks_getProof: {error}")))?;
    let zks = prividium_zksync_rpc::parse_zks_get_proof_response(&zks_bytes)
        .map_err(|error| EngineError::InvalidRequest(format!("zks_getProof: {error:?}")))?;
    if zks.proof.address != prividium_profile_constants::IBC_STORE_ADDRESS
        || zks.state_commitment_preimage.block_number != evidence.target_l2_block
        || zks.l1_verification_data.batch_number != evidence.candidate_batch
        || zks.state_commitment_preimage.last_block_timestamp != evidence.l2_batch_timestamp
    {
        return Err(EngineError::InvalidRequest(
            "Settlement native proof does not match the collected evidence".into(),
        ));
    }
    let slots = zks
        .proof
        .storage_proofs
        .iter()
        .map(|proof| proof.key)
        .collect::<Vec<_>>();
    if slots.is_empty() {
        return Err(EngineError::InvalidRequest(
            "Settlement native proof contains no storage proof".into(),
        ));
    }
    let native_root = zks
        .proof
        .verify(&zks.proof.address, &slots)
        .map_err(|error| EngineError::InvalidRequest(format!("native proof: {error:?}")))?
        .tree_root;
    let expected_slot = prividium_settlement::stored_batch_hash_slot(
        evidence.candidate_batch,
        prividium_profile_constants::STORED_BATCH_HASH_MAPPING_BASE_SLOT,
    );
    if fixed::<32>("settlement storage slot", &evidence.settlement_storage_slot)? != expected_slot {
        return Err(EngineError::InvalidRequest(
            "Settlement storage slot does not match the candidate batch".into(),
        ));
    }
    if fixed::<32>(
        "totalBatchesExecuted storage slot",
        &evidence.total_batches_executed_slot,
    )? != prividium_profile_constants::TOTAL_BATCHES_EXECUTED_SLOT
    {
        return Err(EngineError::InvalidRequest(
            "totalBatchesExecuted storage slot does not match the SourceProfile".into(),
        ));
    }
    let (account_proof, stored_batch_hash_proof, total_batches_executed_proof) =
        eth_storage_proofs(
            &evidence.settlement_account_proof,
            prividium_profile_constants::DIAMOND_PROXY_ADDRESS,
            [
                expected_slot,
                prividium_profile_constants::TOTAL_BATCHES_EXECUTED_SLOT,
            ],
        )?;
    Ok(SettlementWitness {
        schema_version: 1,
        previous_trust: circuit_trust(previous),
        full_signing_sync_committee: circuit_committee(signing_committee)?,
        optimistic_update: OptimisticUpdateWitness {
            attested_header,
            sync_aggregate: sync_aggregate(&raw.data.sync_aggregate)?,
            signature_slot: decimal_u64("signature slot", &raw.data.signature_slot)?,
        },
        prividium_native_root: native_root,
        settlement_account_proof: account_proof,
        stored_batch_hash_proof,
        total_batches_executed_proof,
        state_commitment_preimage: zks.state_commitment_preimage,
        l1_verification_data: zks.l1_verification_data,
    })
}

pub(crate) fn membership_witness(
    request: &PacketProofsRequest,
    evidence: &[PacketProofEvidence],
) -> Result<MembershipWitness<prividium_zksync_native::NativeProofBatch>, EngineError> {
    let first = evidence
        .first()
        .ok_or_else(|| EngineError::InvalidRequest("Membership evidence is empty".into()))?;
    let parsed = parse_packet_native_proof(first)?;
    require_common_packet_evidence(evidence, &parsed)?;
    let entries = evidence
        .iter()
        .map(|entry| {
            Ok(MembershipEntryWitness {
                logical_path: bytes("logical path", &entry.logical_path)?,
                expected_application_value: fixed::<32>(
                    "expected application value",
                    entry.expected_application_value.as_deref().ok_or_else(|| {
                        EngineError::InvalidRequest(
                            "Membership evidence is missing its application value".into(),
                        )
                    })?,
                )?,
            })
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    if entries.len() != request.packets.len() {
        return Err(EngineError::Internal(
            "Membership evidence cardinality does not match the packet request".into(),
        ));
    }
    let slots = evidence
        .iter()
        .map(|entry| fixed::<32>("storage slot", &entry.storage_slot))
        .collect::<Result<Vec<_>, _>>()?;
    let native_root = parsed
        .proof
        .verify(&parsed.proof.address, &slots)
        .map_err(|error| EngineError::InvalidRequest(format!("native proof: {error:?}")))?
        .tree_root;
    Ok(MembershipWitness {
        schema_version: 1,
        proof_height: request.height,
        l1_batch_number: first.l1_batch_number,
        prividium_native_root: native_root,
        entries,
        proof: parsed.proof,
    })
}

pub(crate) fn non_membership_witnesses(
    request: &PacketProofsRequest,
    evidence: &[PacketProofEvidence],
) -> Result<Vec<NonMembershipWitness<prividium_zksync_native::NativeProofBatch>>, EngineError> {
    let first = evidence
        .first()
        .ok_or_else(|| EngineError::InvalidRequest("Non-Membership evidence is empty".into()))?;
    let parsed = parse_packet_native_proof(first)?;
    require_common_packet_evidence(evidence, &parsed)?;
    if parsed.proof.storage_proofs.len() != evidence.len() {
        return Err(EngineError::Internal(
            "Non-Membership evidence/proof cardinality mismatch".into(),
        ));
    }
    evidence
        .iter()
        .zip(parsed.proof.storage_proofs)
        .map(|(entry, storage_proof)| {
            if entry.expected_application_value.is_some() {
                return Err(EngineError::InvalidRequest(
                    "Non-Membership evidence unexpectedly contains a value".into(),
                ));
            }
            let proof = prividium_zksync_native::NativeProofBatch {
                address: parsed.proof.address,
                storage_proofs: vec![storage_proof],
            };
            let slot = fixed::<32>("storage slot", &entry.storage_slot)?;
            let native_root = proof
                .verify(&proof.address, &[slot])
                .map_err(|error| EngineError::InvalidRequest(format!("native proof: {error:?}")))?
                .tree_root;
            Ok(NonMembershipWitness {
                schema_version: 1,
                proof_height: request.height,
                l1_batch_number: entry.l1_batch_number,
                prividium_native_root: native_root,
                logical_path: bytes("logical path", &entry.logical_path)?,
                proof,
            })
        })
        .collect()
}

fn parse_packet_native_proof(
    evidence: &PacketProofEvidence,
) -> Result<prividium_zksync_rpc::ParsedZksGetProof, EngineError> {
    let raw = serde_json::to_vec(&evidence.zks_get_proof)
        .map_err(|error| EngineError::Internal(format!("encode zks_getProof: {error}")))?;
    prividium_zksync_rpc::parse_zks_get_proof_response(&raw)
        .map_err(|error| EngineError::InvalidRequest(format!("zks_getProof: {error:?}")))
}

fn require_common_packet_evidence(
    evidence: &[PacketProofEvidence],
    parsed: &prividium_zksync_rpc::ParsedZksGetProof,
) -> Result<(), EngineError> {
    let first = evidence
        .first()
        .ok_or_else(|| EngineError::InvalidRequest("packet evidence is empty".into()))?;
    if parsed.proof.address != prividium_profile_constants::IBC_STORE_ADDRESS
        || parsed.state_commitment_preimage.block_number != first.l2_block_number
        || parsed.l1_verification_data.batch_number != first.l1_batch_number
        || evidence.iter().any(|entry| {
            entry.l2_block_number != first.l2_block_number
                || entry.l1_batch_number != first.l1_batch_number
                || entry.zks_get_proof != first.zks_get_proof
        })
    {
        return Err(EngineError::InvalidRequest(
            "packet native proof does not match the collected evidence".into(),
        ));
    }
    Ok(())
}

fn circuit_trust(value: &TrustSnapshot) -> ConsensusTrustState {
    ConsensusTrustState {
        finalized_beacon_slot: value.state.finalized_beacon_slot,
        finalized_beacon_header_root: value.state.finalized_beacon_header_root,
        current_sync_committee_root: value.state.current_sync_committee_root,
        next_sync_committee_root: value.state.next_sync_committee_root,
        next_sync_committee_known: value.state.next_sync_committee_known,
    }
}

pub(crate) fn circuit_committee(value: &BootstrapCommittee) -> Result<SyncCommittee, EngineError> {
    Ok(SyncCommittee {
        pubkeys: value
            .pubkeys
            .iter()
            .map(|key| fixed::<48>("sync committee public key", key).map(FixedBytes))
            .collect::<Result<Vec<_>, _>>()?,
        aggregate_pubkey: FixedBytes(fixed::<48>(
            "sync committee aggregate public key",
            &value.aggregate_pubkey,
        )?),
    })
}

fn raw_committee(value: RawSyncCommittee) -> Result<SyncCommittee, EngineError> {
    circuit_committee(&BootstrapCommittee {
        pubkeys: value.pubkeys,
        aggregate_pubkey: value.aggregate_pubkey,
    })
}

fn light_client_header(value: RawLightClientHeader) -> Result<LightClientHeader, EngineError> {
    let execution = value.execution;
    Ok(LightClientHeader {
        beacon: BeaconBlockHeader {
            slot: decimal_u64("beacon slot", &value.beacon.slot)?,
            proposer_index: decimal_u64("beacon proposer index", &value.beacon.proposer_index)?,
            parent_root: fixed::<32>("beacon parent root", &value.beacon.parent_root)?,
            state_root: fixed::<32>("beacon state root", &value.beacon.state_root)?,
            body_root: fixed::<32>("beacon body root", &value.beacon.body_root)?,
        },
        execution: ForkExecutionPayloadHeader::FuluCompatibilityV1(
            ExecutionPayloadHeaderFuluCompatibility {
                parent_hash: fixed::<32>("execution parent hash", &execution.parent_hash)?,
                fee_recipient: fixed::<20>("execution fee recipient", &execution.fee_recipient)?,
                state_root: fixed::<32>("execution state root", &execution.state_root)?,
                receipts_root: fixed::<32>("execution receipts root", &execution.receipts_root)?,
                logs_bloom: FixedBytes(fixed::<256>(
                    "execution logs bloom",
                    &execution.logs_bloom,
                )?),
                prev_randao: fixed::<32>("execution prev randao", &execution.prev_randao)?,
                block_number: decimal_u64("execution block number", &execution.block_number)?,
                gas_limit: decimal_u64("execution gas limit", &execution.gas_limit)?,
                gas_used: decimal_u64("execution gas used", &execution.gas_used)?,
                timestamp: decimal_u64("execution timestamp", &execution.timestamp)?,
                extra_data: bytes("execution extra data", &execution.extra_data)?,
                base_fee_per_gas_le: decimal_u256_le(
                    "execution base fee",
                    &execution.base_fee_per_gas,
                )?,
                block_hash: fixed::<32>("execution block hash", &execution.block_hash)?,
                transactions_root: fixed::<32>(
                    "execution transactions root",
                    &execution.transactions_root,
                )?,
                withdrawals_root: fixed::<32>(
                    "execution withdrawals root",
                    &execution.withdrawals_root,
                )?,
                blob_gas_used: decimal_u64("execution blob gas used", &execution.blob_gas_used)?,
                excess_blob_gas: decimal_u64(
                    "execution excess blob gas",
                    &execution.excess_blob_gas,
                )?,
            },
        ),
        execution_branch: hashes("execution branch", &value.execution_branch)?,
    })
}

fn sync_aggregate(value: &RawSyncAggregate) -> Result<SyncAggregate, EngineError> {
    Ok(SyncAggregate {
        sync_committee_bits: bytes("sync committee bits", &value.sync_committee_bits)?,
        sync_committee_signature: FixedBytes(fixed::<96>(
            "sync committee signature",
            &value.sync_committee_signature,
        )?),
    })
}

fn eth_storage_proofs(
    value: &serde_json::Value,
    expected_address: [u8; 20],
    expected_slots: [[u8; 32]; 2],
) -> Result<(Vec<Vec<u8>>, EvmStorageProofWitness, EvmStorageProofWitness), EngineError> {
    let envelope: RpcEnvelope<EthGetProof> = serde_json::from_value(value.clone())
        .map_err(|error| EngineError::InvalidRequest(format!("eth_getProof: {error}")))?;
    if envelope.jsonrpc != "2.0" || envelope.id.is_null() {
        return Err(EngineError::InvalidRequest(
            "eth_getProof has an invalid JSON-RPC envelope".into(),
        ));
    }
    let proof = envelope.result;
    if fixed::<20>("eth_getProof address", &proof.address)? != expected_address
        || proof.storage_proof.len() != 2
        || fixed::<32>("eth_getProof storage key", &proof.storage_proof[0].key)?
            != expected_slots[0]
        || fixed::<32>(
            "eth_getProof execution-counter key",
            &proof.storage_proof[1].key,
        )? != expected_slots[1]
    {
        return Err(EngineError::InvalidRequest(
            "eth_getProof does not match the configured settlement account and slot".into(),
        ));
    }
    quantity("eth_getProof balance", &proof.balance)?;
    quantity("eth_getProof nonce", &proof.nonce)?;
    fixed::<32>("eth_getProof code hash", &proof.code_hash)?;
    fixed::<32>("eth_getProof storage hash", &proof.storage_hash)?;
    quantity("eth_getProof storage value", &proof.storage_proof[0].value)?;
    quantity(
        "eth_getProof totalBatchesExecuted",
        &proof.storage_proof[1].value,
    )?;
    Ok((
        nodes("eth_getProof account proof", &proof.account_proof)?,
        EvmStorageProofWitness {
            slot: expected_slots[0],
            proof_nodes: nodes(
                "eth_getProof stored-batch proof",
                &proof.storage_proof[0].proof,
            )?,
        },
        EvmStorageProofWitness {
            slot: expected_slots[1],
            proof_nodes: nodes(
                "eth_getProof totalBatchesExecuted proof",
                &proof.storage_proof[1].proof,
            )?,
        },
    ))
}

fn require_fulu(version: &str) -> Result<(), EngineError> {
    if version == "fulu" {
        Ok(())
    } else {
        Err(EngineError::InvalidRequest(format!(
            "unsupported Beacon response fork {version}"
        )))
    }
}

fn decimal_u64(field: &str, value: &str) -> Result<u64, EngineError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EngineError::InvalidRequest(format!(
            "{field} is not a canonical decimal u64"
        )));
    }
    value
        .parse()
        .map_err(|_| EngineError::InvalidRequest(format!("{field} exceeds u64")))
}

fn decimal_u256_le(field: &str, value: &str) -> Result<[u8; 32], EngineError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EngineError::InvalidRequest(format!(
            "{field} is not a canonical decimal uint256"
        )));
    }
    let mut output = [0_u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in &mut output {
            let next = u16::from(*byte) * 10 + carry;
            let [low, high] = next.to_le_bytes();
            *byte = low;
            carry = u16::from(high);
        }
        if carry != 0 {
            return Err(EngineError::InvalidRequest(format!(
                "{field} exceeds uint256"
            )));
        }
    }
    Ok(output)
}

fn hashes(field: &str, values: &[String]) -> Result<Vec<[u8; 32]>, EngineError> {
    if values.is_empty() {
        return Err(EngineError::InvalidRequest(format!("{field} is empty")));
    }
    values
        .iter()
        .map(|value| fixed::<32>(field, value))
        .collect()
}

fn nodes(field: &str, values: &[String]) -> Result<Vec<Vec<u8>>, EngineError> {
    if values.is_empty() {
        return Err(EngineError::InvalidRequest(format!("{field} is empty")));
    }
    values.iter().map(|value| bytes(field, value)).collect()
}

fn bytes(field: &str, value: &str) -> Result<Vec<u8>, EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::InvalidRequest(format!("{field} lacks 0x prefix")))?;
    if body.len() % 2 != 0 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError::InvalidRequest(format!(
            "{field} is invalid hex"
        )));
    }
    hex::decode(body).map_err(|_| EngineError::InvalidRequest(format!("{field} is invalid hex")))
}

fn fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], EngineError> {
    bytes(field, value)?
        .try_into()
        .map_err(|_| EngineError::InvalidRequest(format!("{field} must be {N} bytes")))
}

fn quantity(field: &str, value: &str) -> Result<(), EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::InvalidRequest(format!("{field} lacks 0x prefix")))?;
    if body.is_empty()
        || (body.len() > 1 && body.starts_with('0'))
        || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EngineError::InvalidRequest(format!(
            "{field} is not a canonical hexadecimal quantity"
        )));
    }
    Ok(())
}

pub(crate) fn validate_membership_kind(request: &PacketProofsRequest) -> Result<(), EngineError> {
    let kind = ProofKind::try_from(request.kind)
        .map_err(|_| EngineError::InvalidRequest("unsupported proof kind".into()))?;
    if matches!(
        kind,
        ProofKind::PacketCommitment | ProofKind::Acknowledgement
    ) {
        Ok(())
    } else {
        Err(EngineError::InvalidRequest(
            "Membership proving requires packet or acknowledgement commitments".into(),
        ))
    }
}
