// SPDX-License-Identifier: Apache-2.0

use crate::{Address, Hash};

/// Derives the v0.20.8 flat key as
/// `BLAKE2s(12 zero bytes || raw address20 || storage_slot32)`.
pub fn derive_native_tree_key(address: &Address, storage_slot: &Hash) -> Hash {
    let mut preimage = [0_u8; 64];
    preimage[12..32].copy_from_slice(address);
    preimage[32..].copy_from_slice(storage_slot);
    prividium_crypto::blake2s(&preimage)
}
