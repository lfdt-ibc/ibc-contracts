// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use prividium_crypto::sha256_pair;
use prividium_types::{
    BeaconBlockHeader, ExecutionPayloadHeaderFuluCompatibility, ForkExecutionPayloadHeader, Hash32,
    SyncCommittee,
};

pub const BYTES_PER_CHUNK: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SszError {
    ArithmeticOverflow,
    EmptyLimit,
    TooManyChunks { limit: usize, actual: usize },
    WrongFixedBytesLength { expected: usize, actual: usize },
    InvalidGeneralizedIndex(u64),
    WrongBranchLength { expected: usize, actual: usize },
    RootMismatch,
    WrongCommitteeSize { expected: usize, actual: usize },
}

#[must_use]
pub fn uint64_root(value: u64) -> Hash32 {
    let mut root = [0_u8; 32];
    root[..8].copy_from_slice(&value.to_le_bytes());
    root
}

#[must_use]
pub fn uint256_root_le(value: &[u8; 32]) -> Hash32 {
    *value
}

pub fn fixed_bytes_root(bytes: &[u8], expected_len: usize) -> Result<Hash32, SszError> {
    if bytes.len() != expected_len {
        return Err(SszError::WrongFixedBytesLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    let limit = chunk_count(expected_len)?;
    let chunks = pack_bytes(bytes)?;
    merkleize(&chunks, limit)
}

pub fn byte_list_root(bytes: &[u8], max_len: usize) -> Result<Hash32, SszError> {
    if bytes.len() > max_len {
        return Err(SszError::WrongFixedBytesLength {
            expected: max_len,
            actual: bytes.len(),
        });
    }
    let limit = chunk_count(max_len)?;
    let chunks = pack_bytes(bytes)?;
    let contents = merkleize(&chunks, limit)?;
    mix_in_length(contents, bytes.len())
}

pub fn merkleize(chunks: &[Hash32], limit: usize) -> Result<Hash32, SszError> {
    if limit == 0 {
        return Err(SszError::EmptyLimit);
    }
    if chunks.len() > limit {
        return Err(SszError::TooManyChunks {
            limit,
            actual: chunks.len(),
        });
    }
    let leaf_count = limit
        .checked_next_power_of_two()
        .ok_or(SszError::ArithmeticOverflow)?;
    let mut layer = vec![[0_u8; 32]; leaf_count];
    layer[..chunks.len()].copy_from_slice(chunks);
    while layer.len() > 1 {
        let next_len = layer.len() / 2;
        for index in 0..next_len {
            layer[index] = sha256_pair(&layer[index * 2], &layer[index * 2 + 1]);
        }
        layer.truncate(next_len);
    }
    Ok(layer[0])
}

pub fn mix_in_length(root: Hash32, length: usize) -> Result<Hash32, SszError> {
    let length = u64::try_from(length).map_err(|_| SszError::ArithmeticOverflow)?;
    Ok(sha256_pair(&root, &uint64_root(length)))
}

pub fn container_root(field_roots: &[Hash32]) -> Result<Hash32, SszError> {
    merkleize(field_roots, field_roots.len())
}

pub fn beacon_block_header_root(header: &BeaconBlockHeader) -> Result<Hash32, SszError> {
    container_root(&[
        uint64_root(header.slot),
        uint64_root(header.proposer_index),
        header.parent_root,
        header.state_root,
        header.body_root,
    ])
}

pub fn sync_committee_root(
    committee: &SyncCommittee,
    expected_size: usize,
) -> Result<Hash32, SszError> {
    if committee.pubkeys.len() != expected_size {
        return Err(SszError::WrongCommitteeSize {
            expected: expected_size,
            actual: committee.pubkeys.len(),
        });
    }
    if expected_size == 0 {
        return Err(SszError::EmptyLimit);
    }
    let mut pubkey_roots = Vec::with_capacity(expected_size);
    for pubkey in &committee.pubkeys {
        pubkey_roots.push(fixed_bytes_root(pubkey.as_ref(), 48)?);
    }
    let pubkeys_root = merkleize(&pubkey_roots, expected_size)?;
    let aggregate_root = fixed_bytes_root(committee.aggregate_pubkey.as_ref(), 48)?;
    container_root(&[pubkeys_root, aggregate_root])
}

pub fn execution_payload_header_root(
    header: &ForkExecutionPayloadHeader,
) -> Result<Hash32, SszError> {
    match header {
        ForkExecutionPayloadHeader::FuluCompatibilityV1(value) => {
            fulu_compatibility_execution_payload_header_root(value)
        }
    }
}

pub fn fulu_compatibility_execution_payload_header_root(
    header: &ExecutionPayloadHeaderFuluCompatibility,
) -> Result<Hash32, SszError> {
    container_root(&[
        header.parent_hash,
        fixed_bytes_root(&header.fee_recipient, 20)?,
        header.state_root,
        header.receipts_root,
        fixed_bytes_root(header.logs_bloom.as_ref(), 256)?,
        header.prev_randao,
        uint64_root(header.block_number),
        uint64_root(header.gas_limit),
        uint64_root(header.gas_used),
        uint64_root(header.timestamp),
        byte_list_root(&header.extra_data, 32)?,
        uint256_root_le(&header.base_fee_per_gas_le),
        header.block_hash,
        header.transactions_root,
        header.withdrawals_root,
        uint64_root(header.blob_gas_used),
        uint64_root(header.excess_blob_gas),
    ])
}

#[must_use]
pub fn generalized_index_depth(gindex: u64) -> Option<usize> {
    if gindex <= 1 {
        return None;
    }
    usize::try_from(u64::BITS - 1 - gindex.leading_zeros()).ok()
}

pub fn calculate_branch_root(
    leaf: Hash32,
    branch: &[Hash32],
    gindex: u64,
) -> Result<Hash32, SszError> {
    let depth = generalized_index_depth(gindex).ok_or(SszError::InvalidGeneralizedIndex(gindex))?;
    if branch.len() != depth {
        return Err(SszError::WrongBranchLength {
            expected: depth,
            actual: branch.len(),
        });
    }
    let mut current = leaf;
    let mut index = gindex;
    for sibling in branch {
        current = if index & 1 == 0 {
            sha256_pair(&current, sibling)
        } else {
            sha256_pair(sibling, &current)
        };
        index >>= 1;
    }
    if index != 1 {
        return Err(SszError::InvalidGeneralizedIndex(gindex));
    }
    Ok(current)
}

pub fn verify_branch(
    leaf: Hash32,
    branch: &[Hash32],
    gindex: u64,
    expected_root: Hash32,
) -> Result<(), SszError> {
    if calculate_branch_root(leaf, branch, gindex)? != expected_root {
        return Err(SszError::RootMismatch);
    }
    Ok(())
}

pub fn fork_data_root(
    current_version: [u8; 4],
    genesis_validators_root: Hash32,
) -> Result<Hash32, SszError> {
    let mut version_root = [0_u8; 32];
    version_root[..4].copy_from_slice(&current_version);
    container_root(&[version_root, genesis_validators_root])
}

pub fn compute_domain(
    domain_type: [u8; 4],
    fork_version: [u8; 4],
    genesis_validators_root: Hash32,
) -> Result<Hash32, SszError> {
    let fork_root = fork_data_root(fork_version, genesis_validators_root)?;
    let mut domain = [0_u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..].copy_from_slice(&fork_root[..28]);
    Ok(domain)
}

pub fn signing_root(object_root: Hash32, domain: Hash32) -> Result<Hash32, SszError> {
    container_root(&[object_root, domain])
}

fn chunk_count(byte_len: usize) -> Result<usize, SszError> {
    byte_len
        .checked_add(BYTES_PER_CHUNK - 1)
        .ok_or(SszError::ArithmeticOverflow)
        .map(|value| value / BYTES_PER_CHUNK)
        .and_then(|count| {
            if count == 0 {
                Err(SszError::EmptyLimit)
            } else {
                Ok(count)
            }
        })
}

fn pack_bytes(bytes: &[u8]) -> Result<Vec<Hash32>, SszError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let count = chunk_count(bytes.len())?;
    let mut chunks = vec![[0_u8; 32]; count];
    for (index, byte) in bytes.iter().enumerate() {
        chunks[index / BYTES_PER_CHUNK][index % BYTES_PER_CHUNK] = *byte;
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint64_is_little_endian_in_one_chunk() {
        let root = uint64_root(0x0102_0304_0506_0708);
        assert_eq!(&root[..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&root[8..], &[0_u8; 24]);
    }

    #[test]
    fn bytes48_is_two_chunks_with_zero_padding() {
        let bytes = [0xabu8; 48];
        let mut second = [0_u8; 32];
        second[..16].copy_from_slice(&bytes[32..]);
        assert_eq!(
            fixed_bytes_root(&bytes, 48),
            Ok(sha256_pair(&[0xab; 32], &second))
        );
    }

    #[test]
    fn header_container_pads_five_fields_to_eight() {
        let header = BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [3; 32],
            state_root: [4; 32],
            body_root: [5; 32],
        };
        let left = sha256_pair(&uint64_root(1), &uint64_root(2));
        let middle = sha256_pair(&[3; 32], &[4; 32]);
        let upper_left = sha256_pair(&left, &middle);
        let upper_right = sha256_pair(
            &sha256_pair(&[5; 32], &[0; 32]),
            &sha256_pair(&[0; 32], &[0; 32]),
        );
        assert_eq!(
            beacon_block_header_root(&header),
            Ok(sha256_pair(&upper_left, &upper_right))
        );
    }

    #[test]
    fn branch_uses_gindex_bits_from_leaf_to_root() {
        let leaf = [1_u8; 32];
        let low_sibling = [2_u8; 32];
        let high_sibling = [3_u8; 32];
        // gindex 6 is binary 110: leaf is left at the low level, right at the high level.
        let expected = sha256_pair(&high_sibling, &sha256_pair(&leaf, &low_sibling));
        assert_eq!(
            calculate_branch_root(leaf, &[low_sibling, high_sibling], 6),
            Ok(expected)
        );
        assert_eq!(
            verify_branch(leaf, &[low_sibling, high_sibling], 6, expected),
            Ok(())
        );
    }

    #[test]
    fn branch_rejects_wrong_length_and_root() {
        assert_eq!(
            calculate_branch_root([0; 32], &[[0; 32]], 6),
            Err(SszError::WrongBranchLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            verify_branch([1; 32], &[[2; 32]], 2, [3; 32]),
            Err(SszError::RootMismatch)
        );
    }

    #[test]
    fn committee_root_binds_order_and_aggregate_key() {
        let committee = SyncCommittee {
            pubkeys: vec![[1; 48].into(), [2; 48].into()],
            aggregate_pubkey: [3; 48].into(),
        };
        let root = sync_committee_root(&committee, 2);
        let mut reordered = committee.clone();
        reordered.pubkeys.swap(0, 1);
        assert_ne!(root, sync_committee_root(&reordered, 2));
        let mut aggregate_changed = committee;
        aggregate_changed.aggregate_pubkey.0[0] ^= 1;
        assert_ne!(root, sync_committee_root(&aggregate_changed, 2));
    }

    #[test]
    fn domain_is_type_plus_first_28_fork_root_bytes() {
        let fork_root = fork_data_root([1, 2, 3, 4], [5; 32]).unwrap_or_default();
        let domain = compute_domain([7, 8, 9, 10], [1, 2, 3, 4], [5; 32]).unwrap_or_default();
        assert_eq!(&domain[..4], &[7, 8, 9, 10]);
        assert_eq!(&domain[4..], &fork_root[..28]);
    }

    #[test]
    fn captured_fulu_shape_binds_all_fields_and_extra_data_limit() {
        let header = ExecutionPayloadHeaderFuluCompatibility {
            parent_hash: [1; 32],
            fee_recipient: [2; 20],
            state_root: [3; 32],
            receipts_root: [4; 32],
            logs_bloom: [5; 256].into(),
            prev_randao: [6; 32],
            block_number: 7,
            gas_limit: 8,
            gas_used: 9,
            timestamp: 10,
            extra_data: vec![11; 32],
            base_fee_per_gas_le: [12; 32],
            block_hash: [13; 32],
            transactions_root: [14; 32],
            withdrawals_root: [15; 32],
            blob_gas_used: 16,
            excess_blob_gas: 17,
        };
        let root = fulu_compatibility_execution_payload_header_root(&header);
        let mut changed = header.clone();
        changed.excess_blob_gas = 18;
        assert_ne!(
            root,
            fulu_compatibility_execution_payload_header_root(&changed)
        );
        changed = header;
        changed.extra_data.push(0);
        assert_eq!(
            fulu_compatibility_execution_payload_header_root(&changed),
            Err(SszError::WrongFixedBytesLength {
                expected: 32,
                actual: 33
            })
        );
    }
}
