// SPDX-License-Identifier: Apache-2.0

use crate::Hash;

/// Hashes the exact v0.20.8 leaf preimage:
/// `key32 || value32 || U64_LE(next_index)`.
#[inline]
pub fn hash_leaf(key: &Hash, value: &Hash, next_index: u64) -> Hash {
    let mut preimage = [0_u8; 72];
    preimage[..32].copy_from_slice(key);
    preimage[32..64].copy_from_slice(value);
    preimage[64..].copy_from_slice(&next_index.to_le_bytes());
    prividium_crypto::blake2s(&preimage)
}
