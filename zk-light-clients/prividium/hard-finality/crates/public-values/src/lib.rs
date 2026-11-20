// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use prividium_crypto::keccak256;
use prividium_types::{
    ConsensusTrustState, MembershipEntryPublicValues, MembershipPublicValues,
    NonMembershipPublicValues, SettlementPublicValues, TrustUpdatePublicValues,
    MAX_MEMBERSHIP_BATCH_ENTRIES,
};

pub const ABI_WORD_BYTES: usize = 32;
pub const TRUST_UPDATE_WORDS: usize = 10;
pub const SETTLEMENT_WORDS: usize = 8;
pub const MEMBERSHIP_WORDS: usize = 10;
pub const NON_MEMBERSHIP_WORDS: usize = 12;

pub const MEMBERSHIP_LEAF_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_LEAF_V1____";
pub const MEMBERSHIP_NODE_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_NODE_V1____";
pub const MEMBERSHIP_EMPTY_DOMAIN: [u8; 32] = *b"PRIVIDIUM_MEMBERSHIP_EMPTY_V1___";

pub trait StrictAbiCodec: Sized {
    fn abi_encode(&self) -> Vec<u8>;
    fn abi_decode(bytes: &[u8]) -> Result<Self, AbiError>;
}

impl StrictAbiCodec for TrustUpdatePublicValues {
    fn abi_encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(TRUST_UPDATE_WORDS * ABI_WORD_BYTES);
        push_u32(&mut output, self.schema_version);
        push_u32(&mut output, self.program_version);
        push_word(&mut output, &self.source_profile_id);
        push_word(&mut output, &self.previous_consensus_trust_digest);
        push_u64(&mut output, self.last_signature_slot);
        push_u64(&mut output, self.new_finalized_beacon_slot);
        push_word(&mut output, &self.new_finalized_beacon_header_root);
        push_word(&mut output, &self.new_current_sync_committee_root);
        push_word(&mut output, &self.new_next_sync_committee_root);
        push_bool(&mut output, self.new_next_sync_committee_known);
        output
    }

    fn abi_decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let words = Words::new(bytes, TRUST_UPDATE_WORDS)?;
        Ok(Self {
            schema_version: words.u32(0)?,
            program_version: words.u32(1)?,
            source_profile_id: words.word(2),
            previous_consensus_trust_digest: words.word(3),
            last_signature_slot: words.u64(4)?,
            new_finalized_beacon_slot: words.u64(5)?,
            new_finalized_beacon_header_root: words.word(6),
            new_current_sync_committee_root: words.word(7),
            new_next_sync_committee_root: words.word(8),
            new_next_sync_committee_known: words.boolean(9)?,
        })
    }
}

impl StrictAbiCodec for SettlementPublicValues {
    fn abi_encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(SETTLEMENT_WORDS * ABI_WORD_BYTES);
        push_u32(&mut output, self.schema_version);
        push_u32(&mut output, self.program_version);
        push_word(&mut output, &self.source_profile_id);
        push_word(&mut output, &self.previous_consensus_trust_digest);
        push_u64(&mut output, self.l2_block_number);
        push_u64(&mut output, self.l1_batch_number);
        push_word(&mut output, &self.prividium_native_root);
        push_u64(&mut output, self.l2_batch_timestamp);
        output
    }

    fn abi_decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let words = Words::new(bytes, SETTLEMENT_WORDS)?;
        Ok(Self {
            schema_version: words.u32(0)?,
            program_version: words.u32(1)?,
            source_profile_id: words.word(2),
            previous_consensus_trust_digest: words.word(3),
            l2_block_number: words.u64(4)?,
            l1_batch_number: words.u64(5)?,
            prividium_native_root: words.word(6),
            l2_batch_timestamp: words.u64(7)?,
        })
    }
}

impl StrictAbiCodec for MembershipPublicValues {
    fn abi_encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MEMBERSHIP_WORDS * ABI_WORD_BYTES);
        push_u32(&mut output, self.schema_version);
        push_u32(&mut output, self.program_version);
        push_word(&mut output, &self.source_profile_id);
        push_u64(&mut output, self.proof_height);
        push_u64(&mut output, self.l1_batch_number);
        push_word(&mut output, &self.prividium_native_root);
        push_address(&mut output, &self.ibc_store);
        push_u32(&mut output, self.entry_count);
        push_word(&mut output, &self.batch_root);
        push_word(&mut output, &self.request_digest);
        output
    }

    fn abi_decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let words = Words::new(bytes, MEMBERSHIP_WORDS)?;
        Ok(Self {
            schema_version: words.u32(0)?,
            program_version: words.u32(1)?,
            source_profile_id: words.word(2),
            proof_height: words.u64(3)?,
            l1_batch_number: words.u64(4)?,
            prividium_native_root: words.word(5),
            ibc_store: words.address(6)?,
            entry_count: words.u32(7)?,
            batch_root: words.word(8),
            request_digest: words.word(9),
        })
    }
}

impl StrictAbiCodec for NonMembershipPublicValues {
    fn abi_encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(NON_MEMBERSHIP_WORDS * ABI_WORD_BYTES);
        push_u32(&mut output, self.schema_version);
        push_u32(&mut output, self.program_version);
        push_word(&mut output, &self.source_profile_id);
        push_u64(&mut output, self.proof_height);
        push_u64(&mut output, self.l1_batch_number);
        push_word(&mut output, &self.prividium_native_root);
        push_address(&mut output, &self.ibc_store);
        push_word(&mut output, &self.path_digest);
        push_word(&mut output, &self.solidity_storage_slot);
        push_word(&mut output, &self.native_tree_key);
        push_u32(&mut output, self.absence_profile_id);
        push_word(&mut output, &self.request_digest);
        output
    }

    fn abi_decode(bytes: &[u8]) -> Result<Self, AbiError> {
        let words = Words::new(bytes, NON_MEMBERSHIP_WORDS)?;
        Ok(Self {
            schema_version: words.u32(0)?,
            program_version: words.u32(1)?,
            source_profile_id: words.word(2),
            proof_height: words.u64(3)?,
            l1_batch_number: words.u64(4)?,
            prividium_native_root: words.word(5),
            ibc_store: words.address(6)?,
            path_digest: words.word(7),
            solidity_storage_slot: words.word(8),
            native_tree_key: words.word(9),
            absence_profile_id: words.u32(10)?,
            request_digest: words.word(11),
        })
    }
}

#[must_use]
pub fn consensus_trust_digest(state: &ConsensusTrustState) -> [u8; 32] {
    let mut encoded = [0_u8; 5 * ABI_WORD_BYTES];
    write_u64_word(&mut encoded, 0, state.finalized_beacon_slot);
    write_word(&mut encoded, 1, &state.finalized_beacon_header_root);
    write_word(&mut encoded, 2, &state.current_sync_committee_root);
    write_word(&mut encoded, 3, &state.next_sync_committee_root);
    write_bool_word(&mut encoded, 4, state.next_sync_committee_known);
    keccak256(&encoded)
}

/// Commits the complete authenticated membership batch.
#[must_use]
pub fn membership_request_digest(value: &MembershipPublicValues) -> [u8; 32] {
    let mut encoded = [0_u8; (MEMBERSHIP_WORDS - 1) * ABI_WORD_BYTES];
    write_u32_word(&mut encoded, 0, value.schema_version);
    write_u32_word(&mut encoded, 1, value.program_version);
    write_word(&mut encoded, 2, &value.source_profile_id);
    write_u64_word(&mut encoded, 3, value.proof_height);
    write_u64_word(&mut encoded, 4, value.l1_batch_number);
    write_word(&mut encoded, 5, &value.prividium_native_root);
    write_address_word(&mut encoded, 6, &value.ibc_store);
    write_u32_word(&mut encoded, 7, value.entry_count);
    write_word(&mut encoded, 8, &value.batch_root);
    keccak256(&encoded)
}

/// Commits one ordered claim. Including the index prevents reuse of a branch
/// at another position in the same batch.
#[must_use]
pub fn membership_leaf(index: u32, value: &MembershipEntryPublicValues) -> [u8; 32] {
    let mut encoded = [0_u8; 4 * ABI_WORD_BYTES];
    write_word(&mut encoded, 0, &MEMBERSHIP_LEAF_DOMAIN);
    write_u32_word(&mut encoded, 1, index);
    write_word(&mut encoded, 2, &value.path_digest);
    write_word(&mut encoded, 3, &value.value_hash);
    keccak256(&encoded)
}

#[must_use]
pub fn membership_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 3 * ABI_WORD_BYTES];
    write_word(&mut encoded, 0, &MEMBERSHIP_NODE_DOMAIN);
    write_word(&mut encoded, 1, left);
    write_word(&mut encoded, 2, right);
    keccak256(&encoded)
}

#[must_use]
pub fn empty_membership_leaf() -> [u8; 32] {
    keccak256(&MEMBERSHIP_EMPTY_DOMAIN)
}

#[must_use]
pub fn membership_root(values: &[MembershipEntryPublicValues]) -> Option<[u8; 32]> {
    if values.is_empty() || values.len() > MAX_MEMBERSHIP_BATCH_ENTRIES {
        return None;
    }
    let mut leaves = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        leaves.push(membership_leaf(u32::try_from(index).ok()?, value));
    }
    membership_root_from_leaves(leaves)
}

#[must_use]
pub fn membership_root_from_leaves(mut level: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    if level.is_empty() || level.len() > MAX_MEMBERSHIP_BATCH_ENTRIES {
        return None;
    }
    level.resize(level.len().next_power_of_two(), empty_membership_leaf());
    while level.len() > 1 {
        let parent = level
            .chunks_exact(2)
            .map(|pair| membership_node(&pair[0], &pair[1]))
            .collect();
        level = parent;
    }
    level.first().copied()
}

/// The v1 non-membership analogue of SPEC §12.6. It binds the same request
/// fields, replacing `valueHash` with `absenceProfileId`.
#[must_use]
pub fn non_membership_request_digest(value: &NonMembershipPublicValues) -> [u8; 32] {
    let mut encoded = [0_u8; (NON_MEMBERSHIP_WORDS - 1) * ABI_WORD_BYTES];
    write_u32_word(&mut encoded, 0, value.schema_version);
    write_u32_word(&mut encoded, 1, value.program_version);
    write_word(&mut encoded, 2, &value.source_profile_id);
    write_u64_word(&mut encoded, 3, value.proof_height);
    write_u64_word(&mut encoded, 4, value.l1_batch_number);
    write_word(&mut encoded, 5, &value.prividium_native_root);
    write_address_word(&mut encoded, 6, &value.ibc_store);
    write_word(&mut encoded, 7, &value.path_digest);
    write_word(&mut encoded, 8, &value.solidity_storage_slot);
    write_word(&mut encoded, 9, &value.native_tree_key);
    write_u32_word(&mut encoded, 10, value.absence_profile_id);
    keccak256(&encoded)
}

fn write_word(output: &mut [u8], index: usize, value: &[u8; 32]) {
    let start = index * ABI_WORD_BYTES;
    output[start..start + ABI_WORD_BYTES].copy_from_slice(value);
}

fn write_u32_word(output: &mut [u8], index: usize, value: u32) {
    let end = (index + 1) * ABI_WORD_BYTES;
    output[end - 4..end].copy_from_slice(&value.to_be_bytes());
}

fn write_u64_word(output: &mut [u8], index: usize, value: u64) {
    let end = (index + 1) * ABI_WORD_BYTES;
    output[end - 8..end].copy_from_slice(&value.to_be_bytes());
}

fn write_bool_word(output: &mut [u8], index: usize, value: bool) {
    output[(index + 1) * ABI_WORD_BYTES - 1] = u8::from(value);
}

fn write_address_word(output: &mut [u8], index: usize, value: &[u8; 20]) {
    let end = (index + 1) * ABI_WORD_BYTES;
    output[end - 20..end].copy_from_slice(value);
}

fn push_word(output: &mut Vec<u8>, value: &[u8; 32]) {
    output.extend_from_slice(value);
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&[0_u8; 28]);
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&[0_u8; 24]);
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_bool(output: &mut Vec<u8>, value: bool) {
    output.extend_from_slice(&[0_u8; 31]);
    output.push(u8::from(value));
}

fn push_address(output: &mut Vec<u8>, value: &[u8; 20]) {
    output.extend_from_slice(&[0_u8; 12]);
    output.extend_from_slice(value);
}

struct Words<'a> {
    bytes: &'a [u8],
}

impl<'a> Words<'a> {
    fn new(bytes: &'a [u8], expected_words: usize) -> Result<Self, AbiError> {
        let expected = expected_words
            .checked_mul(ABI_WORD_BYTES)
            .ok_or(AbiError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(AbiError::WrongLength {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    fn slice(&self, index: usize) -> &[u8] {
        let start = index * ABI_WORD_BYTES;
        &self.bytes[start..start + ABI_WORD_BYTES]
    }

    fn word(&self, index: usize) -> [u8; 32] {
        let mut output = [0_u8; 32];
        output.copy_from_slice(self.slice(index));
        output
    }

    fn u32(&self, index: usize) -> Result<u32, AbiError> {
        let word = self.slice(index);
        if word[..28].iter().any(|byte| *byte != 0) {
            return Err(AbiError::NonCanonicalInteger(index));
        }
        let mut value = [0_u8; 4];
        value.copy_from_slice(&word[28..]);
        Ok(u32::from_be_bytes(value))
    }

    fn u64(&self, index: usize) -> Result<u64, AbiError> {
        let word = self.slice(index);
        if word[..24].iter().any(|byte| *byte != 0) {
            return Err(AbiError::NonCanonicalInteger(index));
        }
        let mut value = [0_u8; 8];
        value.copy_from_slice(&word[24..]);
        Ok(u64::from_be_bytes(value))
    }

    fn boolean(&self, index: usize) -> Result<bool, AbiError> {
        let word = self.slice(index);
        if word[..31].iter().any(|byte| *byte != 0) {
            return Err(AbiError::NonCanonicalBoolean(index));
        }
        match word[31] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AbiError::NonCanonicalBoolean(index)),
        }
    }

    fn address(&self, index: usize) -> Result<[u8; 20], AbiError> {
        let word = self.slice(index);
        if word[..12].iter().any(|byte| *byte != 0) {
            return Err(AbiError::NonCanonicalAddress(index));
        }
        let mut value = [0_u8; 20];
        value.copy_from_slice(&word[12..]);
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    LengthOverflow,
    WrongLength { expected: usize, actual: usize },
    NonCanonicalInteger(usize),
    NonCanonicalBoolean(usize),
    NonCanonicalAddress(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership() -> MembershipPublicValues {
        MembershipPublicValues {
            schema_version: 1,
            program_version: 2,
            source_profile_id: [0x11; 32],
            proof_height: 99,
            l1_batch_number: 0x0102_0304_0506_0708,
            prividium_native_root: [0x22; 32],
            ibc_store: [0x33; 20],
            entry_count: 64,
            batch_root: [0x77; 32],
            request_digest: [0x88; 32],
        }
    }

    #[test]
    fn all_four_codecs_round_trip_exact_lengths() {
        let trust = TrustUpdatePublicValues {
            schema_version: 1,
            program_version: 1,
            source_profile_id: [1; 32],
            previous_consensus_trust_digest: [2; 32],
            last_signature_slot: 3,
            new_finalized_beacon_slot: 4,
            new_finalized_beacon_header_root: [5; 32],
            new_current_sync_committee_root: [6; 32],
            new_next_sync_committee_root: [7; 32],
            new_next_sync_committee_known: true,
        };
        let settlement = SettlementPublicValues {
            schema_version: 1,
            program_version: 3,
            source_profile_id: [1; 32],
            previous_consensus_trust_digest: [2; 32],
            l2_block_number: 3,
            l1_batch_number: 4,
            prividium_native_root: [5; 32],
            l2_batch_timestamp: 1_700_000_123,
        };
        let member = membership();
        let non_member = NonMembershipPublicValues {
            schema_version: 1,
            program_version: 2,
            source_profile_id: [1; 32],
            proof_height: 1,
            l1_batch_number: 2,
            prividium_native_root: [3; 32],
            ibc_store: [4; 20],
            path_digest: [5; 32],
            solidity_storage_slot: [6; 32],
            native_tree_key: [7; 32],
            absence_profile_id: 8,
            request_digest: [9; 32],
        };

        assert_eq!(trust.abi_encode().len(), 320);
        assert_eq!(
            TrustUpdatePublicValues::abi_decode(&trust.abi_encode()),
            Ok(trust)
        );
        assert_eq!(settlement.abi_encode().len(), 256);
        let mut invalid_nine_word_shape = settlement.abi_encode();
        invalid_nine_word_shape.extend_from_slice(&[0_u8; 32]);
        assert!(matches!(
            SettlementPublicValues::abi_decode(&invalid_nine_word_shape),
            Err(AbiError::WrongLength {
                expected: 256,
                actual: 288
            })
        ));
        assert_eq!(
            SettlementPublicValues::abi_decode(&settlement.abi_encode()),
            Ok(settlement)
        );
        assert_eq!(member.abi_encode().len(), 320);
        assert_eq!(
            MembershipPublicValues::abi_decode(&member.abi_encode()),
            Ok(member)
        );
        assert_eq!(non_member.abi_encode().len(), 384);
        assert_eq!(
            NonMembershipPublicValues::abi_decode(&non_member.abi_encode()),
            Ok(non_member)
        );
    }

    #[test]
    fn membership_layout_is_solidity_abi_static_tuple() {
        let encoded = membership().abi_encode();
        assert_eq!(&encoded[28..32], &1_u32.to_be_bytes());
        assert_eq!(&encoded[60..64], &2_u32.to_be_bytes());
        assert_eq!(&encoded[64..96], &[0x11; 32]);
        assert_eq!(&encoded[96..120], &[0_u8; 24]);
        assert_eq!(&encoded[120..128], &99_u64.to_be_bytes());
        assert_eq!(&encoded[152..160], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&encoded[192..204], &[0_u8; 12]);
        assert_eq!(&encoded[204..224], &[0x33; 20]);
    }

    #[test]
    fn strict_decoding_rejects_trailing_bytes_and_dirty_padding() {
        let mut trailing = membership().abi_encode();
        trailing.push(0);
        assert!(matches!(
            MembershipPublicValues::abi_decode(&trailing),
            Err(AbiError::WrongLength { .. })
        ));

        let mut dirty_address = membership().abi_encode();
        dirty_address[6 * 32] = 1;
        assert_eq!(
            MembershipPublicValues::abi_decode(&dirty_address),
            Err(AbiError::NonCanonicalAddress(6))
        );
    }

    #[test]
    fn strict_boolean_rejects_values_other_than_zero_or_one() {
        let trust = TrustUpdatePublicValues {
            schema_version: 1,
            program_version: 1,
            source_profile_id: [0; 32],
            previous_consensus_trust_digest: [0; 32],
            last_signature_slot: 0,
            new_finalized_beacon_slot: 0,
            new_finalized_beacon_header_root: [0; 32],
            new_current_sync_committee_root: [0; 32],
            new_next_sync_committee_root: [0; 32],
            new_next_sync_committee_known: false,
        };
        let mut bytes = trust.abi_encode();
        bytes[319] = 2;
        assert_eq!(
            TrustUpdatePublicValues::abi_decode(&bytes),
            Err(AbiError::NonCanonicalBoolean(9))
        );
    }

    #[test]
    fn request_digest_excludes_only_its_own_word() {
        let value = membership();
        let encoded = value.abi_encode();
        assert_eq!(
            membership_request_digest(&value),
            keccak256(&encoded[..9 * ABI_WORD_BYTES])
        );
        let mut changed = value;
        changed.request_digest = [0xaa; 32];
        assert_eq!(
            membership_request_digest(&value),
            membership_request_digest(&changed)
        );
        changed.batch_root[0] ^= 1;
        assert_ne!(
            membership_request_digest(&value),
            membership_request_digest(&changed)
        );
    }

    #[test]
    fn fixed_size_digest_encodings_match_the_canonical_abi_layout() {
        let trust = ConsensusTrustState {
            finalized_beacon_slot: 0x0102_0304_0506_0708,
            finalized_beacon_header_root: [0x11; 32],
            current_sync_committee_root: [0x22; 32],
            next_sync_committee_root: [0x33; 32],
            next_sync_committee_known: true,
        };
        let mut trust_abi = Vec::with_capacity(5 * ABI_WORD_BYTES);
        push_u64(&mut trust_abi, trust.finalized_beacon_slot);
        push_word(&mut trust_abi, &trust.finalized_beacon_header_root);
        push_word(&mut trust_abi, &trust.current_sync_committee_root);
        push_word(&mut trust_abi, &trust.next_sync_committee_root);
        push_bool(&mut trust_abi, trust.next_sync_committee_known);
        assert_eq!(consensus_trust_digest(&trust), keccak256(&trust_abi));

        let non_member = NonMembershipPublicValues {
            schema_version: 1,
            program_version: 2,
            source_profile_id: [0x11; 32],
            proof_height: 99,
            l1_batch_number: 0x0102_0304_0506_0708,
            prividium_native_root: [0x22; 32],
            ibc_store: [0x33; 20],
            path_digest: [0x44; 32],
            solidity_storage_slot: [0x55; 32],
            native_tree_key: [0x66; 32],
            absence_profile_id: 3,
            request_digest: [0x88; 32],
        };
        let encoded = non_member.abi_encode();
        assert_eq!(
            non_membership_request_digest(&non_member),
            keccak256(&encoded[..11 * ABI_WORD_BYTES])
        );
    }
}
