// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use prividium_crypto::keccak256;
use prividium_types::{Address, Hash32};
use prividium_zksync_native::{
    derive_native_tree_key, verify_native_absence_with_flat_key, NativeProofBatch, ProofError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// Terminal path discriminants defined by the pinned Eureka ICS24 host.
///
/// The historical type name is retained to avoid an unnecessary API-wide
/// rename; the byte encoding is the production Eureka encoding.
pub enum PocPathType {
    PacketCommitment = 0x01,
    Receipt = 0x02,
    AcknowledgementCommitment = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectWordStorageProfile {
    pub store_address: Address,
    pub mapping_base_slot: Hash32,
    pub max_client_id_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedStorageLocation {
    pub path_digest: Hash32,
    pub solidity_storage_slot: Hash32,
    pub native_tree_key: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMembership {
    pub location: DerivedStorageLocation,
    pub value_hash: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IbcStorageError {
    EmptyClientId,
    ClientIdTooLong { maximum: usize, actual: usize },
    ZeroMaximumClientIdLength,
    NativeProof(ProofError),
    NativeKeyAbsent,
    ValueMismatch { expected: Hash32, actual: Hash32 },
    LogicalPathTooShort,
    UnsupportedPathType(u8),
}

pub fn parse_poc_terminal_path(
    path: &[u8],
    maximum_client_id_bytes: usize,
) -> Result<(&[u8], PocPathType, u64), IbcStorageError> {
    if path.len() < 10 {
        return Err(IbcStorageError::LogicalPathTooShort);
    }
    let type_position = path.len() - 9;
    let client_id = &path[..type_position];
    let path_type = match path[type_position] {
        1 => PocPathType::PacketCommitment,
        2 => PocPathType::Receipt,
        3 => PocPathType::AcknowledgementCommitment,
        value => return Err(IbcStorageError::UnsupportedPathType(value)),
    };
    let mut sequence = [0_u8; 8];
    sequence.copy_from_slice(&path[type_position + 1..]);
    let sequence = u64::from_be_bytes(sequence);
    validate_client_id(client_id, maximum_client_id_bytes)?;
    Ok((client_id, path_type, sequence))
}

pub fn derive_poc_direct_word_location_from_path(
    profile: &DirectWordStorageProfile,
    path: &[u8],
) -> Result<DerivedStorageLocation, IbcStorageError> {
    parse_poc_terminal_path(path, profile.max_client_id_bytes)?;
    Ok(derive_location(profile, keccak256(path)))
}

impl From<ProofError> for IbcStorageError {
    fn from(value: ProofError) -> Self {
        Self::NativeProof(value)
    }
}

/// Implements the pinned Eureka ICS24 terminal-key formula:
/// `clientId || pathType || sequence.to_be_bytes()`.
pub fn canonicalize_poc_terminal_path(
    client_id: &[u8],
    path_type: PocPathType,
    sequence: u64,
    maximum_client_id_bytes: usize,
) -> Result<Vec<u8>, IbcStorageError> {
    validate_client_id(client_id, maximum_client_id_bytes)?;
    let mut path = Vec::with_capacity(client_id.len() + 9);
    path.extend_from_slice(client_id);
    path.push(path_type as u8);
    path.extend_from_slice(&sequence.to_be_bytes());
    Ok(path)
}

fn validate_client_id(
    client_id: &[u8],
    maximum_client_id_bytes: usize,
) -> Result<(), IbcStorageError> {
    if maximum_client_id_bytes == 0 {
        return Err(IbcStorageError::ZeroMaximumClientIdLength);
    }
    if client_id.is_empty() {
        return Err(IbcStorageError::EmptyClientId);
    }
    if client_id.len() > maximum_client_id_bytes {
        return Err(IbcStorageError::ClientIdTooLong {
            maximum: maximum_client_id_bytes,
            actual: client_id.len(),
        });
    }
    Ok(())
}

#[must_use]
pub fn direct_mapping_slot(application_key: Hash32, base_slot: Hash32) -> Hash32 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&application_key);
    preimage[32..].copy_from_slice(&base_slot);
    keccak256(&preimage)
}

pub fn derive_poc_direct_word_location(
    profile: &DirectWordStorageProfile,
    client_id: &[u8],
    path_type: PocPathType,
    sequence: u64,
) -> Result<DerivedStorageLocation, IbcStorageError> {
    let canonical_path = canonicalize_poc_terminal_path(
        client_id,
        path_type,
        sequence,
        profile.max_client_id_bytes,
    )?;
    let path_digest = keccak256(&canonical_path);
    Ok(derive_location(profile, path_digest))
}

fn derive_location(
    profile: &DirectWordStorageProfile,
    path_digest: Hash32,
) -> DerivedStorageLocation {
    let solidity_storage_slot = direct_mapping_slot(path_digest, profile.mapping_base_slot);
    let native_tree_key = derive_native_tree_key(&profile.store_address, &solidity_storage_slot);
    DerivedStorageLocation {
        path_digest,
        solidity_storage_slot,
        native_tree_key,
    }
}

pub fn verify_poc_direct_word_membership_path(
    profile: &DirectWordStorageProfile,
    accepted_native_root: Hash32,
    logical_path: &[u8],
    expected_value: Hash32,
    proof: &NativeProofBatch,
) -> Result<VerifiedMembership, IbcStorageError> {
    let location = derive_poc_direct_word_location_from_path(profile, logical_path)?;
    let actual = proof.verify_single_with_flat_key_against_root(
        &profile.store_address,
        &location.solidity_storage_slot,
        &location.native_tree_key,
        &accepted_native_root,
    )?;
    let Some(actual) = actual else {
        return Err(IbcStorageError::NativeKeyAbsent);
    };
    if actual != expected_value {
        return Err(IbcStorageError::ValueMismatch {
            expected: expected_value,
            actual,
        });
    }
    Ok(VerifiedMembership {
        location,
        value_hash: keccak256(&actual),
    })
}

/// Production absence rule `native-non-existing-only-v1`.
/// An existing zero word remains present and is rejected.
pub fn verify_native_non_existing_application_absence(
    profile: &DirectWordStorageProfile,
    accepted_native_root: Hash32,
    logical_path: &[u8],
    proof: &NativeProofBatch,
) -> Result<DerivedStorageLocation, IbcStorageError> {
    let location = derive_poc_direct_word_location_from_path(profile, logical_path)?;
    verify_native_absence_with_flat_key(
        proof,
        &profile.store_address,
        &location.solidity_storage_slot,
        &location.native_tree_key,
        &accepted_native_root,
    )?;
    Ok(location)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> DirectWordStorageProfile {
        DirectWordStorageProfile {
            store_address: [0x11; 20],
            mapping_base_slot: [0x22; 32],
            max_client_id_bytes: 128,
        }
    }

    #[test]
    fn terminal_path_uses_type_byte_and_big_endian_sequence() {
        assert_eq!(
            canonicalize_poc_terminal_path(
                b"client-0",
                PocPathType::AcknowledgementCommitment,
                0x0102_0304_0506_0708,
                128,
            ),
            Ok([b"client-0".as_slice(), &[0x03], &[1, 2, 3, 4, 5, 6, 7, 8]].concat())
        );
    }

    #[test]
    fn all_three_path_types_are_distinct() {
        let packet = derive_poc_direct_word_location(
            &profile(),
            b"client-0",
            PocPathType::PacketCommitment,
            7,
        );
        let receipt =
            derive_poc_direct_word_location(&profile(), b"client-0", PocPathType::Receipt, 7);
        let acknowledgement = derive_poc_direct_word_location(
            &profile(),
            b"client-0",
            PocPathType::AcknowledgementCommitment,
            7,
        );
        assert!(packet.is_ok() && receipt.is_ok() && acknowledgement.is_ok());
        assert_ne!(packet, receipt);
        assert_ne!(receipt, acknowledgement);
    }

    #[test]
    fn direct_mapping_and_native_key_bind_store_base_slot_and_path() {
        let first = derive_poc_direct_word_location(
            &profile(),
            b"client-0",
            PocPathType::PacketCommitment,
            7,
        );
        let mut changed_profile = profile();
        changed_profile.mapping_base_slot[31] ^= 1;
        let changed_slot = derive_poc_direct_word_location(
            &changed_profile,
            b"client-0",
            PocPathType::PacketCommitment,
            7,
        );
        changed_profile = profile();
        changed_profile.store_address[19] ^= 1;
        let changed_address = derive_poc_direct_word_location(
            &changed_profile,
            b"client-0",
            PocPathType::PacketCommitment,
            7,
        );
        assert!(first.is_ok() && changed_slot.is_ok() && changed_address.is_ok());
        assert_ne!(first, changed_slot);
        assert_ne!(first, changed_address);
    }

    #[test]
    fn eureka_paths_match_the_pinned_router_storage_slots() {
        let mut mapping_base_slot = [0_u8; 32];
        mapping_base_slot.copy_from_slice(&[
            0x12, 0x60, 0x94, 0x44, 0x89, 0x27, 0x29, 0x88, 0xd9, 0xdf, 0x28, 0x51, 0x49, 0xb5,
            0xaa, 0x1b, 0x0f, 0x48, 0xf2, 0x13, 0x6d, 0x6f, 0x41, 0x61, 0x59, 0xf8, 0x40, 0xa3,
            0xe0, 0x74, 0x76, 0x00,
        ]);
        let profile = DirectWordStorageProfile {
            store_address: [0x11; 20],
            mapping_base_slot,
            max_client_id_bytes: 128,
        };
        let vectors = [
            (
                PocPathType::PacketCommitment,
                "e74a80c507745c3804fb240cff1006b7435c5ff29997556156bf34d6de5694d4",
                "9365b9ec5fe3da89a989e7686d835737b58ee2c881d41bf07da00621564ad760",
            ),
            (
                PocPathType::Receipt,
                "db1f3cb0891c24222f18f3a1c783088c8f95340b6e22449a9055f2a93e9b6983",
                "bf66908fbc9c32050bc3208704f4d423dd6bb9207da87c79c9b36b690052f09e",
            ),
            (
                PocPathType::AcknowledgementCommitment,
                "9e5ea5a196b90ba5f8ecd92871d296001c111d073f2e08d1140d5bc8187cd6cc",
                "1965281590ac361dcf832475b27684f0c60bd41e61bc6b537603238041c0f7b8",
            ),
        ];

        for (kind, expected_digest, expected_slot) in vectors {
            let location = derive_poc_direct_word_location(&profile, b"07-tendermint-0", kind, 42)
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(location.path_digest, hex32(expected_digest));
            assert_eq!(location.solidity_storage_slot, hex32(expected_slot));
        }
    }

    #[test]
    fn client_id_length_is_bounded() {
        assert_eq!(
            canonicalize_poc_terminal_path(b"", PocPathType::Receipt, 0, 128),
            Err(IbcStorageError::EmptyClientId)
        );
        assert_eq!(
            canonicalize_poc_terminal_path(b"ab", PocPathType::Receipt, 0, 1),
            Err(IbcStorageError::ClientIdTooLong {
                maximum: 1,
                actual: 2
            })
        );
    }

    #[test]
    fn canonical_terminal_path_round_trips_strictly() {
        let path = canonicalize_poc_terminal_path(b"client-0", PocPathType::Receipt, 42, 128)
            .unwrap_or_default();
        assert_eq!(
            parse_poc_terminal_path(&path, 128),
            Ok((b"client-0".as_slice(), PocPathType::Receipt, 42))
        );
        let mut wrong_type = path;
        let type_position = wrong_type.len() - 9;
        wrong_type[type_position] = 4;
        assert_eq!(
            parse_poc_terminal_path(&wrong_type, 128),
            Err(IbcStorageError::UnsupportedPathType(4))
        );
    }

    fn hex32(value: &str) -> Hash32 {
        let mut output = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            output[index] = (high << 4) | low;
        }
        output
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => unreachable!(),
        }
    }
}
