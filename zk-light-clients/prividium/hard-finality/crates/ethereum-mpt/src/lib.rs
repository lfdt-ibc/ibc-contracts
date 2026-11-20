// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use prividium_crypto::keccak256;
use prividium_types::{Address, Hash32};

pub const MAX_PROOF_NODES: usize = 65;
pub const MAX_NODE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieValue {
    Present(Vec<u8>),
    Absent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthereumAccount {
    pub nonce: u64,
    pub balance: Hash32,
    pub storage_root: Hash32,
    pub code_hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MptError {
    TooManyProofNodes,
    NodeTooLarge,
    MissingProofNode,
    ExtraProofNodes,
    NodeReferenceMismatch,
    InvalidNodeArity(usize),
    InvalidChildReference,
    InvalidCompactPath,
    PathOverrun,
    ArithmeticOverflow,
    RlpUnexpectedEnd,
    RlpTrailingBytes,
    RlpWrongKind,
    RlpNonCanonical,
    RlpLengthOverflow,
    InvalidAccountArity,
    InvalidAccountField,
    IntegerOverflow,
    NonCanonicalInteger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Data,
    List,
}

#[derive(Clone, Copy, Debug)]
struct Item<'a> {
    kind: Kind,
    raw: &'a [u8],
    payload: &'a [u8],
}

#[derive(Clone, Copy)]
enum NodeRef<'a> {
    Hash(Hash32),
    Inline(&'a [u8]),
}

#[must_use]
pub fn account_trie_key(address: &Address) -> Hash32 {
    keccak256(address)
}

#[must_use]
pub fn storage_trie_key(slot: &Hash32) -> Hash32 {
    keccak256(slot)
}

pub fn verify_trie_proof(
    root: Hash32,
    key: Hash32,
    proof: &[Vec<u8>],
) -> Result<TrieValue, MptError> {
    if proof.len() > MAX_PROOF_NODES {
        return Err(MptError::TooManyProofNodes);
    }
    if proof.is_empty() {
        return if root == keccak256(&[0x80]) {
            Ok(TrieValue::Absent)
        } else {
            Err(MptError::MissingProofNode)
        };
    }
    let path = to_nibbles(&key);
    let mut path_offset = 0_usize;
    let mut proof_offset = 0_usize;
    let mut expected = NodeRef::Hash(root);

    loop {
        let node_bytes = match expected {
            NodeRef::Hash(expected_hash) => {
                let node = proof.get(proof_offset).ok_or(MptError::MissingProofNode)?;
                if node.len() > MAX_NODE_BYTES {
                    return Err(MptError::NodeTooLarge);
                }
                if keccak256(node) != expected_hash {
                    return Err(MptError::NodeReferenceMismatch);
                }
                proof_offset = proof_offset
                    .checked_add(1)
                    .ok_or(MptError::ArithmeticOverflow)?;
                node.as_slice()
            }
            NodeRef::Inline(raw) => raw,
        };
        let node = decode_one(node_bytes)?;
        if node.raw.len() != node_bytes.len() {
            return Err(MptError::RlpTrailingBytes);
        }
        require_kind(node, Kind::List)?;
        let fields = decode_list_fields(node.payload)?;
        match fields.len() {
            17 => {
                if path_offset == path.len() {
                    let value = require_kind(fields[16], Kind::Data)?.payload;
                    let result = if value.is_empty() {
                        TrieValue::Absent
                    } else {
                        TrieValue::Present(value.to_vec())
                    };
                    require_all_proof_consumed(proof_offset, proof.len())?;
                    return Ok(result);
                }
                let nibble = usize::from(path[path_offset]);
                path_offset = path_offset
                    .checked_add(1)
                    .ok_or(MptError::ArithmeticOverflow)?;
                let Some(reference) = child_reference(fields[nibble])? else {
                    require_all_proof_consumed(proof_offset, proof.len())?;
                    return Ok(TrieValue::Absent);
                };
                expected = reference;
            }
            2 => {
                let compact = require_kind(fields[0], Kind::Data)?.payload;
                let (is_leaf, partial_path) = decode_compact_path(compact)?;
                let remaining = path.get(path_offset..).ok_or(MptError::PathOverrun)?;
                if !remaining.starts_with(&partial_path) {
                    require_all_proof_consumed(proof_offset, proof.len())?;
                    return Ok(TrieValue::Absent);
                }
                path_offset = path_offset
                    .checked_add(partial_path.len())
                    .ok_or(MptError::ArithmeticOverflow)?;
                if is_leaf {
                    if path_offset != path.len() {
                        require_all_proof_consumed(proof_offset, proof.len())?;
                        return Ok(TrieValue::Absent);
                    }
                    let value = require_kind(fields[1], Kind::Data)?.payload;
                    if value.is_empty() {
                        return Err(MptError::RlpNonCanonical);
                    }
                    require_all_proof_consumed(proof_offset, proof.len())?;
                    return Ok(TrieValue::Present(value.to_vec()));
                }
                if partial_path.is_empty() {
                    return Err(MptError::InvalidCompactPath);
                }
                let Some(reference) = child_reference(fields[1])? else {
                    return Err(MptError::InvalidChildReference);
                };
                expected = reference;
            }
            arity => return Err(MptError::InvalidNodeArity(arity)),
        }
    }
}

pub fn verify_account(
    state_root: Hash32,
    address: &Address,
    proof: &[Vec<u8>],
) -> Result<Option<EthereumAccount>, MptError> {
    match verify_trie_proof(state_root, account_trie_key(address), proof)? {
        TrieValue::Absent => Ok(None),
        TrieValue::Present(value) => decode_account(&value).map(Some),
    }
}

pub fn verify_storage_value(
    storage_root: Hash32,
    slot: &Hash32,
    proof: &[Vec<u8>],
) -> Result<Option<Hash32>, MptError> {
    match verify_trie_proof(storage_root, storage_trie_key(slot), proof)? {
        TrieValue::Absent => Ok(None),
        TrieValue::Present(encoded_value) => {
            let item = decode_one(&encoded_value)?;
            if item.raw.len() != encoded_value.len() {
                return Err(MptError::RlpTrailingBytes);
            }
            let value = require_kind(item, Kind::Data)?.payload;
            if value.len() > 32 {
                return Err(MptError::IntegerOverflow);
            }
            if value.first() == Some(&0) {
                return Err(MptError::NonCanonicalInteger);
            }
            let mut result = [0_u8; 32];
            result[32 - value.len()..].copy_from_slice(value);
            Ok(Some(result))
        }
    }
}

fn decode_account(encoded: &[u8]) -> Result<EthereumAccount, MptError> {
    let item = decode_one(encoded)?;
    if item.raw.len() != encoded.len() {
        return Err(MptError::RlpTrailingBytes);
    }
    let fields = decode_list_fields(require_kind(item, Kind::List)?.payload)?;
    if fields.len() != 4 {
        return Err(MptError::InvalidAccountArity);
    }
    Ok(EthereumAccount {
        nonce: decode_u64(fields[0])?,
        balance: decode_uint256(fields[1])?,
        storage_root: decode_hash(fields[2])?,
        code_hash: decode_hash(fields[3])?,
    })
}

fn decode_u64(item: Item<'_>) -> Result<u64, MptError> {
    let bytes = canonical_integer_bytes(item)?;
    if bytes.len() > 8 {
        return Err(MptError::IntegerOverflow);
    }
    let mut value = [0_u8; 8];
    value[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(value))
}

fn decode_uint256(item: Item<'_>) -> Result<Hash32, MptError> {
    let bytes = canonical_integer_bytes(item)?;
    if bytes.len() > 32 {
        return Err(MptError::IntegerOverflow);
    }
    let mut value = [0_u8; 32];
    value[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(value)
}

fn canonical_integer_bytes(item: Item<'_>) -> Result<&[u8], MptError> {
    let bytes = require_kind(item, Kind::Data)?.payload;
    if bytes.first() == Some(&0) {
        return Err(MptError::NonCanonicalInteger);
    }
    Ok(bytes)
}

fn decode_hash(item: Item<'_>) -> Result<Hash32, MptError> {
    let bytes = require_kind(item, Kind::Data)?.payload;
    if bytes.len() != 32 {
        return Err(MptError::InvalidAccountField);
    }
    let mut value = [0_u8; 32];
    value.copy_from_slice(bytes);
    Ok(value)
}

fn require_all_proof_consumed(consumed: usize, total: usize) -> Result<(), MptError> {
    if consumed != total {
        return Err(MptError::ExtraProofNodes);
    }
    Ok(())
}

fn child_reference(item: Item<'_>) -> Result<Option<NodeRef<'_>>, MptError> {
    match item.kind {
        Kind::Data if item.payload.is_empty() => Ok(None),
        Kind::Data if item.payload.len() == 32 => {
            let mut hash = [0_u8; 32];
            hash.copy_from_slice(item.payload);
            Ok(Some(NodeRef::Hash(hash)))
        }
        Kind::List if item.raw.len() < 32 => Ok(Some(NodeRef::Inline(item.raw))),
        _ => Err(MptError::InvalidChildReference),
    }
}

fn to_nibbles(key: &Hash32) -> [u8; 64] {
    let mut nibbles = [0_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        nibbles[index * 2] = byte >> 4;
        nibbles[index * 2 + 1] = byte & 0x0f;
    }
    nibbles
}

fn decode_compact_path(bytes: &[u8]) -> Result<(bool, Vec<u8>), MptError> {
    let first = *bytes.first().ok_or(MptError::InvalidCompactPath)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(MptError::InvalidCompactPath);
    }
    let odd = flag & 1 == 1;
    let is_leaf = flag & 2 == 2;
    if !odd && first & 0x0f != 0 {
        return Err(MptError::InvalidCompactPath);
    }
    let capacity = bytes
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_sub(if odd { 1 } else { 2 }))
        .ok_or(MptError::ArithmeticOverflow)?;
    let mut nibbles = Vec::with_capacity(capacity);
    if odd {
        nibbles.push(first & 0x0f);
    }
    for byte in &bytes[1..] {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

fn require_kind(item: Item<'_>, expected: Kind) -> Result<Item<'_>, MptError> {
    if item.kind != expected {
        return Err(MptError::RlpWrongKind);
    }
    Ok(item)
}

fn decode_list_fields(mut payload: &[u8]) -> Result<Vec<Item<'_>>, MptError> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let item = decode_one(payload)?;
        payload = &payload[item.raw.len()..];
        items.push(item);
        if items.len() > 17 {
            return Err(MptError::InvalidNodeArity(items.len()));
        }
    }
    Ok(items)
}

fn decode_one(input: &[u8]) -> Result<Item<'_>, MptError> {
    let prefix = *input.first().ok_or(MptError::RlpUnexpectedEnd)?;
    match prefix {
        0x00..=0x7f => Ok(Item {
            kind: Kind::Data,
            raw: &input[..1],
            payload: &input[..1],
        }),
        0x80..=0xb7 => {
            let length = usize::from(prefix - 0x80);
            let item = item_with_payload(input, Kind::Data, 1, length)?;
            if length == 1 && item.payload[0] < 0x80 {
                return Err(MptError::RlpNonCanonical);
            }
            Ok(item)
        }
        0xb8..=0xbf => decode_long(input, Kind::Data, usize::from(prefix - 0xb7)),
        0xc0..=0xf7 => item_with_payload(input, Kind::List, 1, usize::from(prefix - 0xc0)),
        0xf8..=0xff => decode_long(input, Kind::List, usize::from(prefix - 0xf7)),
    }
}

fn decode_long(input: &[u8], kind: Kind, length_of_length: usize) -> Result<Item<'_>, MptError> {
    let length_end = 1_usize
        .checked_add(length_of_length)
        .ok_or(MptError::RlpLengthOverflow)?;
    let length_bytes = input.get(1..length_end).ok_or(MptError::RlpUnexpectedEnd)?;
    if length_bytes.first() == Some(&0) || length_of_length > core::mem::size_of::<usize>() {
        return Err(MptError::RlpNonCanonical);
    }
    let mut length = 0_usize;
    for byte in length_bytes {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(MptError::RlpLengthOverflow)?;
    }
    if length <= 55 {
        return Err(MptError::RlpNonCanonical);
    }
    item_with_payload(input, kind, length_end, length)
}

fn item_with_payload(
    input: &[u8],
    kind: Kind,
    payload_start: usize,
    payload_len: usize,
) -> Result<Item<'_>, MptError> {
    let end = payload_start
        .checked_add(payload_len)
        .ok_or(MptError::RlpLengthOverflow)?;
    let raw = input.get(..end).ok_or(MptError::RlpUnexpectedEnd)?;
    let payload = input
        .get(payload_start..end)
        .ok_or(MptError::RlpUnexpectedEnd)?;
    Ok(Item { kind, raw, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_membership_and_neighbor_absence() {
        let key = [0x12_u8; 32];
        let value = rlp_data(&[0x2a]);
        let leaf = leaf_node(&to_nibbles(&key), &value);
        let root = keccak256(&leaf);
        assert_eq!(
            verify_trie_proof(root, key, core::slice::from_ref(&leaf)),
            Ok(TrieValue::Present(value))
        );
        let absent_key = [0x13_u8; 32];
        assert_eq!(
            verify_trie_proof(root, absent_key, &[leaf]),
            Ok(TrieValue::Absent)
        );
    }

    #[test]
    fn proof_binds_root_key_and_exact_node_count() {
        let key = [0x12_u8; 32];
        let value = rlp_data(&[1]);
        let leaf = leaf_node(&to_nibbles(&key), &value);
        assert_eq!(
            verify_trie_proof([0; 32], key, core::slice::from_ref(&leaf)),
            Err(MptError::NodeReferenceMismatch)
        );
        let root = keccak256(&leaf);
        assert_eq!(
            verify_trie_proof(root, key, &[leaf.clone(), leaf]),
            Err(MptError::ExtraProofNodes)
        );
    }

    #[test]
    fn empty_trie_is_an_authenticated_absence() {
        assert_eq!(
            verify_trie_proof(keccak256(&[0x80]), [1; 32], &[]),
            Ok(TrieValue::Absent)
        );
        assert_eq!(
            verify_trie_proof([0; 32], [1; 32], &[]),
            Err(MptError::MissingProofNode)
        );
    }

    #[test]
    fn compact_encoding_and_rlp_malleability_fail_closed() {
        assert_eq!(
            decode_compact_path(&[0x01]),
            Err(MptError::InvalidCompactPath)
        );
        assert!(matches!(
            decode_one(&[0x81, 0x01]),
            Err(MptError::RlpNonCanonical)
        ));
        assert!(matches!(
            decode_one(&[0xb8, 0x01, 0x80]),
            Err(MptError::RlpNonCanonical)
        ));
    }

    #[test]
    fn storage_value_is_inner_rlp_scalar() {
        let slot = [7_u8; 32];
        let key = storage_trie_key(&slot);
        let stored_rlp = rlp_data(&[0x12, 0x34]);
        let leaf = leaf_node(&to_nibbles(&key), &stored_rlp);
        let result = verify_storage_value(keccak256(&leaf), &slot, &[leaf]);
        let mut expected = [0_u8; 32];
        expected[30..].copy_from_slice(&[0x12, 0x34]);
        assert_eq!(result, Ok(Some(expected)));
    }

    #[test]
    fn account_value_decodes_canonical_fields() {
        let address = [8_u8; 20];
        let storage_root = [9_u8; 32];
        let code_hash = [10_u8; 32];
        let account = rlp_list(&[
            rlp_data(&[1]),
            rlp_data(&[2]),
            rlp_data(&storage_root),
            rlp_data(&code_hash),
        ]);
        let leaf = leaf_node(&to_nibbles(&account_trie_key(&address)), &account);
        assert_eq!(
            verify_account(keccak256(&leaf), &address, &[leaf]),
            Ok(Some(EthereumAccount {
                nonce: 1,
                balance: {
                    let mut value = [0_u8; 32];
                    value[31] = 2;
                    value
                },
                storage_root,
                code_hash,
            }))
        );
    }

    fn leaf_node(path: &[u8], value: &[u8]) -> Vec<u8> {
        let compact = compact_path(path, true);
        rlp_list(&[rlp_data(&compact), rlp_data(value)])
    }

    fn compact_path(nibbles: &[u8], leaf: bool) -> Vec<u8> {
        let odd = nibbles.len() % 2 == 1;
        let flag = if leaf { 2_u8 } else { 0 } + u8::from(odd);
        let mut output = Vec::with_capacity(nibbles.len() / 2 + 1);
        let mut offset = 0;
        if odd {
            output.push((flag << 4) | nibbles[0]);
            offset = 1;
        } else {
            output.push(flag << 4);
        }
        for pair in nibbles[offset..].chunks_exact(2) {
            output.push((pair[0] << 4) | pair[1]);
        }
        output
    }

    fn rlp_data(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return bytes.to_vec();
        }
        let mut output = Vec::new();
        if bytes.len() <= 55 {
            output.reserve(bytes.len() + 1);
            output.push(0x80 + u8::try_from(bytes.len()).unwrap_or_default());
        } else {
            let length_bytes = usize_be(bytes.len());
            output.reserve(bytes.len() + 1 + length_bytes.len());
            output.push(0xb7 + u8::try_from(length_bytes.len()).unwrap_or_default());
            output.extend_from_slice(&length_bytes);
        }
        output.extend_from_slice(bytes);
        output
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload_len = items.iter().map(Vec::len).sum::<usize>();
        if payload_len <= 55 {
            let mut output = Vec::with_capacity(payload_len + 1);
            output.push(0xc0 + u8::try_from(payload_len).unwrap_or_default());
            for item in items {
                output.extend_from_slice(item);
            }
            return output;
        }
        let length_bytes = usize_be(payload_len);
        let mut output = Vec::with_capacity(payload_len + 1 + length_bytes.len());
        output.push(0xf7 + u8::try_from(length_bytes.len()).unwrap_or_default());
        output.extend_from_slice(&length_bytes);
        for item in items {
            output.extend_from_slice(item);
        }
        output
    }

    fn usize_be(value: usize) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        bytes[first..].to_vec()
    }
}
