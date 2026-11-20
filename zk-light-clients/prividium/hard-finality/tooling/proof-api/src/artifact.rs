// SPDX-License-Identifier: Apache-2.0

use crate::{
    state::StateProofEvidence,
    storage::{derive_native_tree_key, PacketProofEvidence},
    EngineError,
};
use serde::Deserialize;
use sha3::{Digest as _, Keccak256};

const WORD_BYTES: usize = 32;
const TRUST_UPDATE_WORDS: usize = 10;
const SETTLEMENT_WORDS: usize = 8;
const MEMBERSHIP_WORDS: usize = 10;
const PACKET_WORDS: usize = 12;
const MAX_COMPOSITE_UPDATES: usize = 9;
const MAX_MEMBERSHIP_BATCH_ENTRIES: usize = 64;
const MEMBERSHIP_ENVELOPE_FULL: u8 = 1;
const MEMBERSHIP_ENVELOPE_CACHED: u8 = 2;
const MEMBERSHIP_LEAF_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_LEAF_V1____";
const MEMBERSHIP_NODE_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_NODE_V1____";
const MEMBERSHIP_EMPTY_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_EMPTY_V1___";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofArtifact {
    pub program: String,
    pub source_profile_id: [u8; 32],
    pub public_values: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipBatchArtifacts {
    pub relay_proofs: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireProofArtifact {
    program: String,
    source_profile_id: String,
    public_values: String,
    proof: String,
}

impl WireProofArtifact {
    pub fn decode(self) -> Result<ProofArtifact, EngineError> {
        if self.program.is_empty() || self.program.len() > 64 {
            return Err(EngineError::Backend(
                "artifact program must contain 1..=64 bytes".into(),
            ));
        }
        Ok(ProofArtifact {
            program: self.program,
            source_profile_id: decode_fixed_hex(
                "artifact sourceProfileId",
                &self.source_profile_id,
            )?,
            public_values: decode_nonempty_hex("artifact publicValues", &self.public_values)?,
            proof: decode_nonempty_hex("artifact proof", &self.proof)?,
        })
    }
}
pub fn trust_update_envelope(
    artifact: &ProofArtifact,
    expected_profile: [u8; 32],
    previous: &crate::destination::TrustSnapshot,
) -> Result<Vec<u8>, EngineError> {
    trust_update_envelope_and_state(artifact, expected_profile, previous)
        .map(|(envelope, _)| envelope)
}

pub fn trust_update_envelope_and_state(
    artifact: &ProofArtifact,
    expected_profile: [u8; 32],
    previous: &crate::destination::TrustSnapshot,
) -> Result<(Vec<u8>, crate::destination::ConsensusTrustState), EngineError> {
    require_artifact(
        artifact,
        "trust-update",
        expected_profile,
        TRUST_UPDATE_WORDS,
        1,
    )?;
    let words = Words::new(&artifact.public_values, TRUST_UPDATE_WORDS)?;
    if words.word(3) != previous.digest {
        return Err(EngineError::Backend(
            "Trust Update public values do not match the destination trust state".into(),
        ));
    }
    let signature_slot = words.u64(4)?;
    let finalized_slot = words.u64(5)?;
    let finalized_root = words.word(6);
    if signature_slot <= finalized_slot
        || finalized_slot < previous.state.finalized_beacon_slot
        || (finalized_slot == previous.state.finalized_beacon_slot
            && finalized_root != previous.state.finalized_beacon_header_root)
    {
        return Err(EngineError::Backend(
            "Trust Update public values contain an invalid finalized transition".into(),
        ));
    }
    require_nonzero("new finalized Beacon header root", finalized_root)?;
    require_nonzero("new current sync committee root", words.word(7))?;
    let next_root = words.word(8);
    let next_known = words.boolean(9)?;
    if next_known {
        require_nonzero("new next sync committee root", next_root)?;
    } else if next_root != [0_u8; 32] {
        return Err(EngineError::Backend(
            "unknown next sync committee must use the zero root".into(),
        ));
    }
    let next = crate::destination::ConsensusTrustState {
        finalized_beacon_slot: finalized_slot,
        finalized_beacon_header_root: finalized_root,
        current_sync_committee_root: words.word(7),
        next_sync_committee_root: next_root,
        next_sync_committee_known: next_known,
    };
    Ok((
        encode_update_envelope(0, &artifact.public_values, &artifact.proof)?,
        next,
    ))
}

pub fn composite_update_envelope(updates: &[Vec<u8>]) -> Result<Vec<u8>, EngineError> {
    if updates.len() < 2
        || updates.len() > MAX_COMPOSITE_UPDATES
        || updates.iter().any(Vec::is_empty)
    {
        return Err(EngineError::Internal(
            "composite update requires 2..=9 nonempty updates".into(),
        ));
    }
    let payload = encode_bytes_array(updates)?;
    encode_update_envelope(2, &payload, &[])
}

pub fn settlement_envelope(
    artifact: &ProofArtifact,
    expected_profile: [u8; 32],
    expected_trust_digest: [u8; 32],
    evidence: &StateProofEvidence,
) -> Result<Vec<u8>, EngineError> {
    require_artifact(artifact, "settlement-update", expected_profile, 8, 3)?;
    let words = Words::new(&artifact.public_values, SETTLEMENT_WORDS)?;
    if words.word(3) != expected_trust_digest {
        return Err(EngineError::Backend(
            "Settlement public values do not match the destination trust state".into(),
        ));
    }
    if words.u64(4)? != evidence.target_l2_block {
        return Err(EngineError::Backend(
            "Settlement public values do not match the authenticated L2 block".into(),
        ));
    }
    if words.u64(5)? != evidence.candidate_batch {
        return Err(EngineError::Backend(
            "Settlement public values do not match the requested batch".into(),
        ));
    }
    require_nonzero("Prividium native root", words.word(6))?;
    if words.u64(7)? != evidence.l2_batch_timestamp {
        return Err(EngineError::Backend(
            "Settlement public values do not match the authenticated batch timestamp".into(),
        ));
    }
    encode_update_envelope(1, &artifact.public_values, &artifact.proof)
}

pub fn non_membership_envelope(
    artifact: &ProofArtifact,
    expected_profile: [u8; 32],
    expected_store: [u8; 20],
    absence_profile_id: u32,
    height: u64,
    evidence: &PacketProofEvidence,
) -> Result<Vec<u8>, EngineError> {
    require_artifact(
        artifact,
        "non-membership",
        expected_profile,
        PACKET_WORDS,
        2,
    )?;
    let words = Words::new(&artifact.public_values, PACKET_WORDS)?;
    if height > evidence.l2_block_number {
        return Err(EngineError::Internal(
            "packet request is newer than the authenticated batch-end block".into(),
        ));
    }
    if words.u64(3)? != height {
        return Err(EngineError::Backend(
            "packet public values do not match the requested proof height".into(),
        ));
    }
    if words.u64(4)? != evidence.l1_batch_number {
        return Err(EngineError::Backend(
            "packet public values do not match the requested batch".into(),
        ));
    }
    require_nonzero("Prividium native root", words.word(5))?;
    if words.address(6)? != expected_store {
        return Err(EngineError::Backend(
            "packet public values contain the wrong IBC store".into(),
        ));
    }
    let path = decode_nonempty_hex("packet logical path", &evidence.logical_path)?;
    let path_digest: [u8; 32] = Keccak256::digest(path).into();
    if words.word(7) != path_digest {
        return Err(EngineError::Backend(
            "packet public values contain the wrong path digest".into(),
        ));
    }
    let slot = decode_fixed_hex::<32>("packet storage slot", &evidence.storage_slot)?;
    if words.word(8) != slot {
        return Err(EngineError::Backend(
            "packet public values contain the wrong storage slot".into(),
        ));
    }
    let expected_native_key = derive_native_tree_key(expected_store, slot);
    if words.word(9) != expected_native_key {
        return Err(EngineError::Backend(
            "packet public values contain the wrong native tree key".into(),
        ));
    }
    if evidence.expected_application_value.is_some() {
        return Err(EngineError::Internal(
            "non-membership evidence unexpectedly contains a value".into(),
        ));
    }
    if words.u32(10)? != absence_profile_id {
        return Err(EngineError::Backend(
            "Non-Membership public values contain the wrong absence profile".into(),
        ));
    }
    let request_digest: [u8; 32] =
        Keccak256::digest(&artifact.public_values[..11 * WORD_BYTES]).into();
    if words.word(11) != request_digest {
        return Err(EngineError::Backend(
            "packet public values contain the wrong request digest".into(),
        ));
    }
    encode_proof_envelope(&artifact.public_values, &artifact.proof)
}

pub fn membership_batch_artifacts(
    artifact: &ProofArtifact,
    expected_profile: [u8; 32],
    expected_store: [u8; 20],
    height: u64,
    evidence: &[PacketProofEvidence],
) -> Result<MembershipBatchArtifacts, EngineError> {
    require_artifact(
        artifact,
        "membership",
        expected_profile,
        MEMBERSHIP_WORDS,
        2,
    )?;
    if evidence.is_empty() || evidence.len() > MAX_MEMBERSHIP_BATCH_ENTRIES {
        return Err(EngineError::InvalidRequest(
            "membership batch must contain 1..=64 entries".into(),
        ));
    }
    let first = &evidence[0];
    if height > first.l2_block_number
        || evidence.iter().any(|entry| {
            entry.l1_batch_number != first.l1_batch_number
                || entry.l2_block_number != first.l2_block_number
        })
    {
        return Err(EngineError::InvalidRequest(
            "membership batch entries must use one authenticated source state".into(),
        ));
    }
    let words = Words::new(&artifact.public_values, MEMBERSHIP_WORDS)?;
    if words.u64(3)? != height || words.u64(4)? != first.l1_batch_number {
        return Err(EngineError::Backend(
            "membership public values contain the wrong height or batch".into(),
        ));
    }
    require_nonzero("Prividium native root", words.word(5))?;
    if words.address(6)? != expected_store {
        return Err(EngineError::Backend(
            "membership public values contain the wrong IBC store".into(),
        ));
    }
    let claim_count = u32::try_from(evidence.len())
        .map_err(|_| EngineError::Internal("membership claim count exceeds u32".into()))?;
    if words.u32(7)? != claim_count {
        return Err(EngineError::Backend(
            "membership public values contain the wrong entry count".into(),
        ));
    }
    let claims = evidence
        .iter()
        .map(|entry| {
            let path = decode_nonempty_hex("packet logical path", &entry.logical_path)?;
            let value = entry.expected_application_value.as_deref().ok_or_else(|| {
                EngineError::Internal("membership evidence is missing a value".into())
            })?;
            let value = decode_fixed_hex::<32>("authenticated application value", value)?;
            Ok(MembershipEntryCommitment {
                path_digest: Keccak256::digest(path).into(),
                value_hash: Keccak256::digest(value).into(),
            })
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    let (claims_root, branches) = membership_entry_tree(&claims)?;
    if words.word(8) != claims_root {
        return Err(EngineError::Backend(
            "membership public values contain the wrong batch root".into(),
        ));
    }
    let request_digest: [u8; 32] =
        Keccak256::digest(&artifact.public_values[..9 * WORD_BYTES]).into();
    if words.word(9) != request_digest {
        return Err(EngineError::Backend(
            "membership public values contain the wrong request digest".into(),
        ));
    }
    let relay_proofs = branches
        .iter()
        .enumerate()
        .map(|(index, siblings)| {
            let index = u32::try_from(index)
                .map_err(|_| EngineError::Internal("claim index exceeds u32".into()))?;
            let (mode, public_values, proof) = if index == 0 {
                (
                    MEMBERSHIP_ENVELOPE_FULL,
                    artifact.public_values.as_slice(),
                    artifact.proof.as_slice(),
                )
            } else {
                (MEMBERSHIP_ENVELOPE_CACHED, &[][..], &[][..])
            };
            encode_membership_batch_envelope(
                MembershipEnvelopePayload {
                    mode,
                    public_values,
                    proof,
                },
                first.l1_batch_number,
                claims_root,
                claim_count,
                index,
                siblings,
            )
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    Ok(MembershipBatchArtifacts { relay_proofs })
}

#[derive(Clone, Copy)]
struct MembershipEntryCommitment {
    path_digest: [u8; 32],
    value_hash: [u8; 32],
}

type MembershipTree = ([u8; 32], Vec<Vec<[u8; 32]>>);

fn membership_entry_tree(
    claims: &[MembershipEntryCommitment],
) -> Result<MembershipTree, EngineError> {
    if claims.is_empty() || claims.len() > MAX_MEMBERSHIP_BATCH_ENTRIES {
        return Err(EngineError::InvalidRequest(
            "membership batch must contain 1..=64 entries".into(),
        ));
    }
    let mut level = claims
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            Ok(membership_entry_leaf(
                u32::try_from(index)
                    .map_err(|_| EngineError::Internal("claim index exceeds u32".into()))?,
                *claim,
            ))
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    level.resize(
        level.len().next_power_of_two(),
        Keccak256::digest(MEMBERSHIP_EMPTY_DOMAIN).into(),
    );
    let mut levels = vec![level];
    while levels.last().is_some_and(|current| current.len() > 1) {
        let parent = levels
            .last()
            .ok_or_else(|| EngineError::Internal("missing membership level".into()))?
            .chunks_exact(2)
            .map(|pair| membership_entry_node(pair[0], pair[1]))
            .collect();
        levels.push(parent);
    }
    let root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or_else(|| EngineError::Internal("missing membership root".into()))?;
    let branches = (0..claims.len())
        .map(|index| {
            let mut position = index;
            let mut siblings = Vec::with_capacity(levels.len().saturating_sub(1));
            for level in levels.iter().take(levels.len().saturating_sub(1)) {
                siblings.push(level[position ^ 1]);
                position >>= 1;
            }
            siblings
        })
        .collect();
    Ok((root, branches))
}

fn membership_entry_leaf(index: u32, claim: MembershipEntryCommitment) -> [u8; 32] {
    let mut encoded = [0_u8; 4 * WORD_BYTES];
    write_word(&mut encoded, 0, MEMBERSHIP_LEAF_DOMAIN);
    write_u32_word(&mut encoded, 1, index);
    write_word(&mut encoded, 2, claim.path_digest);
    write_word(&mut encoded, 3, claim.value_hash);
    Keccak256::digest(encoded).into()
}

fn membership_entry_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 3 * WORD_BYTES];
    write_word(&mut encoded, 0, MEMBERSHIP_NODE_DOMAIN);
    write_word(&mut encoded, 1, left);
    write_word(&mut encoded, 2, right);
    Keccak256::digest(encoded).into()
}

#[derive(Clone, Copy)]
struct MembershipEnvelopePayload<'a> {
    mode: u8,
    public_values: &'a [u8],
    proof: &'a [u8],
}

fn encode_membership_batch_envelope(
    payload: MembershipEnvelopePayload<'_>,
    l1_batch_number: u64,
    batch_root: [u8; 32],
    entry_count: u32,
    entry_index: u32,
    siblings: &[[u8; 32]],
) -> Result<Vec<u8>, EngineError> {
    let tuple_offset = WORD_BYTES;
    let tuple_head = 8 * WORD_BYTES;
    let public_offset = tuple_head;
    let proof_offset = checked_add(public_offset, dynamic_size(payload.public_values.len())?)?;
    let siblings_offset = checked_add(proof_offset, dynamic_size(payload.proof.len())?)?;
    let siblings_size = checked_add(WORD_BYTES, siblings.len() * WORD_BYTES)?;
    let tuple_size = checked_add(siblings_offset, siblings_size)?;
    let mut encoded = Vec::with_capacity(checked_add(tuple_offset, tuple_size)?);
    push_usize_word(&mut encoded, tuple_offset)?;
    push_u64_word(&mut encoded, u64::from(payload.mode));
    push_usize_word(&mut encoded, public_offset)?;
    push_usize_word(&mut encoded, proof_offset)?;
    push_u64_word(&mut encoded, l1_batch_number);
    encoded.extend_from_slice(&batch_root);
    push_u64_word(&mut encoded, u64::from(entry_count));
    push_u64_word(&mut encoded, u64::from(entry_index));
    push_usize_word(&mut encoded, siblings_offset)?;
    push_dynamic(&mut encoded, payload.public_values)?;
    push_dynamic(&mut encoded, payload.proof)?;
    push_usize_word(&mut encoded, siblings.len())?;
    for sibling in siblings {
        encoded.extend_from_slice(sibling);
    }
    Ok(encoded)
}

fn require_artifact(
    artifact: &ProofArtifact,
    program: &str,
    profile: [u8; 32],
    word_count: usize,
    program_version: u32,
) -> Result<(), EngineError> {
    if artifact.program != program {
        return Err(EngineError::Backend(format!(
            "backend returned {} artifact for {program}",
            artifact.program
        )));
    }
    if artifact.source_profile_id != profile {
        return Err(EngineError::Backend(
            "artifact SourceProfile ID does not match configuration".into(),
        ));
    }
    let words = Words::new(&artifact.public_values, word_count)?;
    if words.u32(0)? != 1 || words.u32(1)? != program_version || words.word(2) != profile {
        return Err(EngineError::Backend(
            "artifact public-value version or SourceProfile binding is wrong".into(),
        ));
    }
    Ok(())
}

fn encode_update_envelope(
    kind: u8,
    public_values: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, EngineError> {
    let first = 3 * WORD_BYTES;
    let second = checked_add(first, dynamic_size(public_values.len())?)?;
    let mut output = Vec::with_capacity(checked_add(second, dynamic_size(proof.len())?)?);
    push_u64_word(&mut output, u64::from(kind));
    push_usize_word(&mut output, first)?;
    push_usize_word(&mut output, second)?;
    push_dynamic(&mut output, public_values)?;
    push_dynamic(&mut output, proof)?;
    Ok(output)
}

fn encode_proof_envelope(public_values: &[u8], proof: &[u8]) -> Result<Vec<u8>, EngineError> {
    let first = 2 * WORD_BYTES;
    let second = checked_add(first, dynamic_size(public_values.len())?)?;
    let mut output = Vec::with_capacity(checked_add(second, dynamic_size(proof.len())?)?);
    push_usize_word(&mut output, first)?;
    push_usize_word(&mut output, second)?;
    push_dynamic(&mut output, public_values)?;
    push_dynamic(&mut output, proof)?;
    Ok(output)
}

fn encode_bytes_array(values: &[Vec<u8>]) -> Result<Vec<u8>, EngineError> {
    let root_offset = WORD_BYTES;
    let head_size = values
        .len()
        .checked_mul(WORD_BYTES)
        .ok_or_else(|| EngineError::Internal("ABI array head overflow".into()))?;
    let mut tail_size = 0_usize;
    for value in values {
        tail_size = checked_add(tail_size, dynamic_size(value.len())?)?;
    }
    let capacity = checked_add(2 * WORD_BYTES, checked_add(head_size, tail_size)?)?;
    let mut output = Vec::with_capacity(capacity);
    push_usize_word(&mut output, root_offset)?;
    push_usize_word(&mut output, values.len())?;
    let mut offset = head_size;
    for value in values {
        push_usize_word(&mut output, offset)?;
        offset = checked_add(offset, dynamic_size(value.len())?)?;
    }
    for value in values {
        push_dynamic(&mut output, value)?;
    }
    Ok(output)
}

fn checked_add(left: usize, right: usize) -> Result<usize, EngineError> {
    left.checked_add(right)
        .ok_or_else(|| EngineError::Internal("ABI length overflow".into()))
}

fn dynamic_size(length: usize) -> Result<usize, EngineError> {
    checked_add(WORD_BYTES, padded_length(length)?)
}

fn padded_length(length: usize) -> Result<usize, EngineError> {
    checked_add(length, WORD_BYTES - 1).map(|value| value / WORD_BYTES * WORD_BYTES)
}

fn push_dynamic(output: &mut Vec<u8>, value: &[u8]) -> Result<(), EngineError> {
    push_usize_word(output, value.len())?;
    output.extend_from_slice(value);
    output.resize(
        checked_add(output.len(), padded_length(value.len())? - value.len())?,
        0,
    );
    Ok(())
}

fn push_usize_word(output: &mut Vec<u8>, value: usize) -> Result<(), EngineError> {
    push_u64_word(
        output,
        u64::try_from(value).map_err(|_| EngineError::Internal("ABI value exceeds u64".into()))?,
    );
    Ok(())
}

fn push_u64_word(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&[0_u8; 24]);
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_word(output: &mut [u8], index: usize, value: [u8; 32]) {
    let start = index * WORD_BYTES;
    output[start..start + WORD_BYTES].copy_from_slice(&value);
}

fn write_u32_word(output: &mut [u8], index: usize, value: u32) {
    let end = (index + 1) * WORD_BYTES;
    output[end - 4..end].copy_from_slice(&value.to_be_bytes());
}

fn require_nonzero(field: &str, value: [u8; 32]) -> Result<(), EngineError> {
    if value == [0_u8; 32] {
        Err(EngineError::Backend(format!("{field} must be nonzero")))
    } else {
        Ok(())
    }
}

fn decode_nonempty_hex(field: &str, value: &str) -> Result<Vec<u8>, EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Backend(format!("{field} lacks 0x prefix")))?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(EngineError::Backend(format!(
            "{field} must be non-empty even-length hex"
        )));
    }
    hex::decode(body).map_err(|_| EngineError::Backend(format!("{field} is invalid hex")))
}

fn decode_fixed_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], EngineError> {
    decode_nonempty_hex(field, value)?
        .try_into()
        .map_err(|_| EngineError::Backend(format!("{field} must be {N} bytes")))
}

struct Words<'a> {
    bytes: &'a [u8],
}

impl<'a> Words<'a> {
    fn new(bytes: &'a [u8], count: usize) -> Result<Self, EngineError> {
        let expected = count
            .checked_mul(WORD_BYTES)
            .ok_or_else(|| EngineError::Internal("public-value length overflow".into()))?;
        if bytes.len() != expected {
            return Err(EngineError::Backend(format!(
                "public values have {} bytes; expected {expected}",
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    fn word(&self, index: usize) -> [u8; 32] {
        let start = index * WORD_BYTES;
        let mut result = [0_u8; 32];
        result.copy_from_slice(&self.bytes[start..start + WORD_BYTES]);
        result
    }

    fn u32(&self, index: usize) -> Result<u32, EngineError> {
        let word = self.word(index);
        if word[..28].iter().any(|byte| *byte != 0) {
            return Err(EngineError::Backend(format!(
                "public-value word {index} is not a canonical u32"
            )));
        }
        let mut value = [0_u8; 4];
        value.copy_from_slice(&word[28..]);
        Ok(u32::from_be_bytes(value))
    }

    fn u64(&self, index: usize) -> Result<u64, EngineError> {
        let word = self.word(index);
        if word[..24].iter().any(|byte| *byte != 0) {
            return Err(EngineError::Backend(format!(
                "public-value word {index} is not a canonical u64"
            )));
        }
        let mut value = [0_u8; 8];
        value.copy_from_slice(&word[24..]);
        Ok(u64::from_be_bytes(value))
    }

    fn boolean(&self, index: usize) -> Result<bool, EngineError> {
        let word = self.word(index);
        if word[..31].iter().any(|byte| *byte != 0) {
            return Err(EngineError::Backend(format!(
                "public-value word {index} is not a canonical bool"
            )));
        }
        match word[31] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(EngineError::Backend(format!(
                "public-value word {index} is not a canonical bool"
            ))),
        }
    }

    fn address(&self, index: usize) -> Result<[u8; 20], EngineError> {
        let word = self.word(index);
        if word[..12].iter().any(|byte| *byte != 0) {
            return Err(EngineError::Backend(format!(
                "public-value word {index} is not a canonical address"
            )));
        }
        let mut value = [0_u8; 20];
        value.copy_from_slice(&word[12..]);
        Ok(value)
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn artifact(program: &str, profile: [u8; 32], values: Vec<u8>) -> ProofArtifact {
        ProofArtifact {
            program: program.into(),
            source_profile_id: profile,
            public_values: values,
            proof: vec![0xaa, 0xbb],
        }
    }

    #[test]
    fn composite_update_uses_canonical_abi_bytes_array_encoding() {
        let encoded =
            composite_update_envelope(&[vec![0xaa], vec![0xbb, 0xcc]]).unwrap_or_default();

        assert_eq!(&encoded[24..32], &2_u64.to_be_bytes());
        assert_eq!(&encoded[56..64], &96_u64.to_be_bytes());
        assert_eq!(&encoded[88..96], &384_u64.to_be_bytes());

        let payload_start = 96 + 32;
        assert_eq!(
            &encoded[payload_start + 24..payload_start + 32],
            &32_u64.to_be_bytes()
        );
        assert_eq!(
            &encoded[payload_start + 32 + 24..payload_start + 64],
            &2_u64.to_be_bytes()
        );
        assert_eq!(
            &encoded[payload_start + 64 + 24..payload_start + 96],
            &64_u64.to_be_bytes()
        );
        assert_eq!(
            &encoded[payload_start + 96 + 24..payload_start + 128],
            &128_u64.to_be_bytes()
        );
        assert_eq!(encoded[payload_start + 160], 0xaa);
        assert_eq!(
            &encoded[payload_start + 224..payload_start + 226],
            &[0xbb, 0xcc]
        );

        assert!(composite_update_envelope(&[vec![1]]).is_err());
        assert!(composite_update_envelope(&vec![vec![1]; 10]).is_err());
    }

    fn push_word(output: &mut Vec<u8>, value: [u8; 32]) {
        output.extend_from_slice(&value);
    }

    #[test]
    fn settlement_binding_and_update_envelope_are_strict() {
        let profile = [0x11; 32];
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 3);
        push_word(&mut values, profile);
        push_word(&mut values, [0x22; 32]);
        push_u64_word(&mut values, 8);
        push_u64_word(&mut values, 7);
        push_word(&mut values, [0x33; 32]);
        push_u64_word(&mut values, 99);
        let artifact = artifact("settlement-update", profile, values);
        let evidence = StateProofEvidence {
            candidate_batch: 7,
            target_l2_block: 8,
            l2_batch_timestamp: 99,
            settlement_storage_slot: format!("0x{}", "44".repeat(32)),
            total_batches_executed_slot: format!("0x{}", "45".repeat(32)),
            native_root_proof: serde_json::json!({}),
            optimistic_update: serde_json::json!({}),
            settlement_account_proof: serde_json::json!({}),
        };

        let encoded =
            settlement_envelope(&artifact, profile, [0x22; 32], &evidence).unwrap_or_default();
        assert_eq!(&encoded[31..32], &[1]);
        assert_eq!(&encoded[56..64], &96_u64.to_be_bytes());
        assert!(settlement_envelope(&artifact, [0x12; 32], [0x22; 32], &evidence).is_err());
        assert!(settlement_envelope(&artifact, profile, [0x23; 32], &evidence).is_err());

        let mut wrong_batch = artifact.clone();
        wrong_batch.public_values[5 * WORD_BYTES + 31] = 8;
        assert!(settlement_envelope(&wrong_batch, profile, [0x22; 32], &evidence).is_err());
    }

    #[test]
    fn membership_binding_checks_value_and_request_digest() {
        let profile = [0x10; 32];
        let store = [0x20; 20];
        let evidence = (0_u8..64)
            .map(|index| PacketProofEvidence {
                l2_block_number: 8,
                l1_batch_number: 7,
                logical_path: format!("0x{}", hex::encode([index; 9])),
                storage_slot: format!("0x{}", hex::encode([index; 32])),
                expected_application_value: Some(format!("0x{}", hex::encode([index; 32]))),
                zks_get_proof: serde_json::json!({}),
            })
            .collect::<Vec<_>>();
        let claims = evidence
            .iter()
            .enumerate()
            .map(|(index, entry)| MembershipEntryCommitment {
                path_digest: Keccak256::digest(
                    hex::decode(entry.logical_path.trim_start_matches("0x")).unwrap(),
                )
                .into(),
                value_hash: Keccak256::digest([u8::try_from(index).unwrap(); 32]).into(),
            })
            .collect::<Vec<_>>();
        let (root, _) = membership_entry_tree(&claims).unwrap();
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 2);
        push_word(&mut values, profile);
        push_u64_word(&mut values, 7);
        push_u64_word(&mut values, 7);
        push_word(&mut values, [0x50; 32]);
        let mut address = [0_u8; 32];
        address[12..].copy_from_slice(&store);
        push_word(&mut values, address);
        push_u64_word(&mut values, 64);
        push_word(&mut values, root);
        let digest: [u8; 32] = Keccak256::digest(&values).into();
        push_word(&mut values, digest);
        let batch = membership_batch_artifacts(
            &artifact("membership", profile, values),
            profile,
            store,
            7,
            &evidence,
        )
        .unwrap();
        assert_eq!(batch.relay_proofs.len(), 64);
        assert_eq!(batch.relay_proofs[0][63], MEMBERSHIP_ENVELOPE_FULL);
        assert!(batch.relay_proofs[1..]
            .iter()
            .all(|proof| proof[63] == MEMBERSHIP_ENVELOPE_CACHED));
    }
    #[test]
    fn trust_update_binding_and_transition_are_strict() {
        let profile = [0x11; 32];
        let state = crate::destination::ConsensusTrustState {
            finalized_beacon_slot: 7,
            finalized_beacon_header_root: [0x33; 32],
            current_sync_committee_root: [0x44; 32],
            next_sync_committee_root: [0_u8; 32],
            next_sync_committee_known: false,
        };
        let previous = crate::destination::TrustSnapshot {
            block_number: 10,
            digest: [0x22; 32],
            state,
        };
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 1);
        push_word(&mut values, profile);
        push_word(&mut values, previous.digest);
        push_u64_word(&mut values, 10);
        push_u64_word(&mut values, 8);
        push_word(&mut values, [0x55; 32]);
        push_word(&mut values, [0x66; 32]);
        push_word(&mut values, [0x77; 32]);
        push_u64_word(&mut values, 1);
        let artifact = artifact("trust-update", profile, values);

        let (encoded, next) =
            trust_update_envelope_and_state(&artifact, profile, &previous).unwrap();
        assert_eq!(&encoded[31..32], &[0]);
        assert_eq!(next.finalized_beacon_slot, 8);
        assert_eq!(next.finalized_beacon_header_root, [0x55; 32]);
        assert_eq!(next.current_sync_committee_root, [0x66; 32]);
        assert_eq!(next.next_sync_committee_root, [0x77; 32]);
        assert!(next.next_sync_committee_known);

        let mut wrong_digest = artifact.clone();
        wrong_digest.public_values[3 * WORD_BYTES] ^= 1;
        assert!(trust_update_envelope(&wrong_digest, profile, &previous).is_err());

        let mut noncanonical_bool = artifact.clone();
        noncanonical_bool.public_values[10 * WORD_BYTES - 1] = 2;
        assert!(trust_update_envelope(&noncanonical_bool, profile, &previous).is_err());
    }

    #[test]
    fn wire_artifact_rejects_empty_and_malformed_hex() {
        let malformed = WireProofArtifact {
            program: "membership".into(),
            source_profile_id: format!("0x{}", "11".repeat(32)),
            public_values: "0x".into(),
            proof: "0x01".into(),
        };
        assert!(malformed.decode().is_err());

        for program in [String::new(), "x".repeat(65)] {
            assert!(WireProofArtifact {
                program,
                source_profile_id: format!("0x{}", "11".repeat(32)),
                public_values: "0x01".into(),
                proof: "0x01".into(),
            }
            .decode()
            .is_err());
        }
        assert!(WireProofArtifact {
            program: "membership".into(),
            source_profile_id: "0x01".into(),
            public_values: "0x01".into(),
            proof: "0x01".into(),
        }
        .decode()
        .is_err());
        assert!(WireProofArtifact {
            program: "membership".into(),
            source_profile_id: format!("0x{}", "11".repeat(32)),
            public_values: "0x01".into(),
            proof: "0x".into(),
        }
        .decode()
        .is_err());
    }

    #[test]
    fn non_membership_envelope_binds_absence_profile() {
        let profile = [0x10; 32];
        let store = [0x20; 20];
        let path = b"client-0\x02\0\0\0\0\0\0\0\x07".to_vec();
        let slot = [0x30; 32];
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 2);
        push_word(&mut values, profile);
        push_u64_word(&mut values, 7);
        push_u64_word(&mut values, 7);
        push_word(&mut values, [0x50; 32]);
        let mut address = [0_u8; 32];
        address[12..].copy_from_slice(&store);
        push_word(&mut values, address);
        push_word(&mut values, Keccak256::digest(&path).into());
        push_word(&mut values, slot);
        push_word(&mut values, derive_native_tree_key(store, slot));
        push_u64_word(&mut values, 1);
        let digest: [u8; 32] = Keccak256::digest(&values).into();
        push_word(&mut values, digest);
        let artifact = artifact("non-membership", profile, values);
        let evidence = PacketProofEvidence {
            l2_block_number: 7,
            l1_batch_number: 7,
            logical_path: format!("0x{}", hex::encode(path)),
            storage_slot: format!("0x{}", hex::encode(slot)),
            expected_application_value: None,
            zks_get_proof: serde_json::json!({}),
        };
        assert!(non_membership_envelope(&artifact, profile, store, 1, 7, &evidence).is_ok());
        assert!(non_membership_envelope(&artifact, profile, store, 2, 7, &evidence).is_err());
    }

    #[test]
    fn abi_and_word_helpers_cover_canonical_and_rejected_encodings() {
        assert_eq!(padded_length(0), Ok(0));
        assert_eq!(padded_length(1), Ok(32));
        assert_eq!(dynamic_size(1), Ok(64));
        assert!(decode_nonempty_hex("value", "01").is_err());
        assert!(decode_nonempty_hex("value", "0x").is_err());
        assert!(decode_nonempty_hex("value", "0x0").is_err());
        assert!(decode_nonempty_hex("value", "0xzz").is_err());
        assert!(decode_fixed_hex::<2>("value", "0x01").is_err());
        assert!(require_nonzero("root", [0; 32]).is_err());

        let mut encoded = Vec::new();
        push_u64_word(&mut encoded, 7);
        let words = Words::new(&encoded, 1).unwrap();
        assert_eq!(words.u64(0), Ok(7));
        assert_eq!(words.u32(0), Ok(7));
        assert!(words.boolean(0).is_err());
        assert!(words.address(0).is_ok());
        let mut dirty = encoded;
        dirty[0] = 1;
        let words = Words::new(&dirty, 1).unwrap();
        assert!(words.u32(0).is_err());
        assert!(words.u64(0).is_err());
        assert!(words.address(0).is_err());
        assert!(Words::new(&[], 1).is_err());
    }

    fn non_membership_fixture() -> ([u8; 32], [u8; 20], ProofArtifact, PacketProofEvidence) {
        let profile = [0x10; 32];
        let store = [0x20; 20];
        let path = b"client-0\x02\0\0\0\0\0\0\0\x07".to_vec();
        let slot = [0x30; 32];
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 2);
        push_word(&mut values, profile);
        push_u64_word(&mut values, 7);
        push_u64_word(&mut values, 7);
        push_word(&mut values, [0x50; 32]);
        let mut address = [0_u8; 32];
        address[12..].copy_from_slice(&store);
        push_word(&mut values, address);
        push_word(&mut values, Keccak256::digest(&path).into());
        push_word(&mut values, slot);
        push_word(&mut values, derive_native_tree_key(store, slot));
        push_u64_word(&mut values, 1);
        let digest: [u8; 32] = Keccak256::digest(&values).into();
        push_word(&mut values, digest);
        (
            profile,
            store,
            artifact("non-membership", profile, values),
            PacketProofEvidence {
                l2_block_number: 7,
                l1_batch_number: 7,
                logical_path: format!("0x{}", hex::encode(path)),
                storage_slot: format!("0x{}", hex::encode(slot)),
                expected_application_value: None,
                zks_get_proof: serde_json::json!({}),
            },
        )
    }

    #[test]
    fn non_membership_rejects_every_mismatched_binding() {
        let (profile, store, valid, evidence) = non_membership_fixture();
        let call = |artifact: &ProofArtifact, evidence: &PacketProofEvidence, height| {
            non_membership_envelope(artifact, profile, store, 1, height, evidence)
        };

        assert!(call(&valid, &evidence, 8).is_err());
        for word_index in [3_usize, 4, 5, 6, 7, 8, 9, 11] {
            let mut changed = valid.clone();
            changed.public_values[word_index * WORD_BYTES + 31] ^= 1;
            assert!(call(&changed, &evidence, 7).is_err());
        }
        let mut with_value = evidence.clone();
        with_value.expected_application_value = Some(format!("0x{}", "11".repeat(32)));
        assert!(call(&valid, &with_value, 7).is_err());
        let mut bad_path = evidence.clone();
        bad_path.logical_path = "0x".into();
        assert!(call(&valid, &bad_path, 7).is_err());
        let mut bad_slot = evidence;
        bad_slot.storage_slot = "0x01".into();
        assert!(call(&valid, &bad_slot, 7).is_err());
    }

    fn membership_fixture() -> ([u8; 32], [u8; 20], ProofArtifact, PacketProofEvidence) {
        let profile = [0x10; 32];
        let store = [0x20; 20];
        let entry = PacketProofEvidence {
            l2_block_number: 8,
            l1_batch_number: 7,
            logical_path: "0x010203".into(),
            storage_slot: format!("0x{}", "30".repeat(32)),
            expected_application_value: Some(format!("0x{}", "40".repeat(32))),
            zks_get_proof: serde_json::json!({}),
        };
        let claim = MembershipEntryCommitment {
            path_digest: Keccak256::digest([1_u8, 2, 3]).into(),
            value_hash: Keccak256::digest([0x40; 32]).into(),
        };
        let (root, _) = membership_entry_tree(&[claim]).unwrap();
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 2);
        push_word(&mut values, profile);
        push_u64_word(&mut values, 7);
        push_u64_word(&mut values, 7);
        push_word(&mut values, [0x50; 32]);
        let mut address = [0_u8; 32];
        address[12..].copy_from_slice(&store);
        push_word(&mut values, address);
        push_u64_word(&mut values, 1);
        push_word(&mut values, root);
        let digest: [u8; 32] = Keccak256::digest(&values).into();
        push_word(&mut values, digest);
        (
            profile,
            store,
            artifact("membership", profile, values),
            entry,
        )
    }

    #[test]
    fn membership_rejects_every_mismatched_batch_binding() {
        let (profile, store, valid, entry) = membership_fixture();
        let call = |artifact: &ProofArtifact, entries: &[PacketProofEvidence], height| {
            membership_batch_artifacts(artifact, profile, store, height, entries)
        };
        assert!(call(&valid, &[], 7).is_err());
        assert!(call(&valid, &vec![entry.clone(); 65], 7).is_err());
        assert!(call(&valid, core::slice::from_ref(&entry), 9).is_err());

        let mut other_batch = entry.clone();
        other_batch.l1_batch_number = 8;
        assert!(call(&valid, &[entry.clone(), other_batch], 7).is_err());
        let mut other_block = entry.clone();
        other_block.l2_block_number = 9;
        assert!(call(&valid, &[entry.clone(), other_block], 7).is_err());
        for word_index in [3_usize, 4, 5, 6, 7, 8, 9] {
            let mut changed = valid.clone();
            changed.public_values[word_index * WORD_BYTES + 31] ^= 1;
            assert!(call(&changed, core::slice::from_ref(&entry), 7).is_err());
        }
        let mut missing_value = entry.clone();
        missing_value.expected_application_value = None;
        assert!(call(&valid, &[missing_value], 7).is_err());
        let mut malformed_value = entry;
        malformed_value.expected_application_value = Some("0x01".into());
        assert!(call(&valid, &[malformed_value], 7).is_err());
        assert!(membership_entry_tree(&[]).is_err());
    }

    #[test]
    fn artifact_identity_and_transition_checks_fail_closed() {
        let (profile, store, valid, entry) = membership_fixture();
        let mut wrong_program = valid.clone();
        wrong_program.program = "other".into();
        assert!(membership_batch_artifacts(
            &wrong_program,
            profile,
            store,
            7,
            core::slice::from_ref(&entry),
        )
        .is_err());
        let mut wrong_profile = valid.clone();
        wrong_profile.source_profile_id = [0x99; 32];
        assert!(membership_batch_artifacts(
            &wrong_profile,
            profile,
            store,
            7,
            core::slice::from_ref(&entry),
        )
        .is_err());
        let mut wrong_version = valid;
        wrong_version.public_values[WORD_BYTES + 31] = 3;
        assert!(membership_batch_artifacts(&wrong_version, profile, store, 7, &[entry]).is_err());

        let profile = [0x11; 32];
        let previous = crate::destination::TrustSnapshot {
            block_number: 10,
            digest: [0x22; 32],
            state: crate::destination::ConsensusTrustState {
                finalized_beacon_slot: 7,
                finalized_beacon_header_root: [0x33; 32],
                current_sync_committee_root: [0x44; 32],
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: false,
            },
        };
        let mut values = Vec::new();
        push_u64_word(&mut values, 1);
        push_u64_word(&mut values, 1);
        push_word(&mut values, profile);
        push_word(&mut values, previous.digest);
        push_u64_word(&mut values, 10);
        push_u64_word(&mut values, 8);
        push_word(&mut values, [0x55; 32]);
        push_word(&mut values, [0x66; 32]);
        push_word(&mut values, [0x77; 32]);
        push_u64_word(&mut values, 1);
        let valid = artifact("trust-update", profile, values);
        for word_index in [4_usize, 5] {
            let mut changed = valid.clone();
            changed.public_values[word_index * WORD_BYTES..(word_index + 1) * WORD_BYTES].fill(0);
            assert!(trust_update_envelope(&changed, profile, &previous).is_err());
        }
        for word_index in [6_usize, 7] {
            let mut changed = valid.clone();
            changed.public_values[word_index * WORD_BYTES..(word_index + 1) * WORD_BYTES].fill(0);
            assert!(trust_update_envelope(&changed, profile, &previous).is_err());
        }
        let mut unknown_nonzero = valid;
        unknown_nonzero.public_values[9 * WORD_BYTES + 31] = 0;
        assert!(trust_update_envelope(&unknown_nonzero, profile, &previous).is_err());
    }
}
