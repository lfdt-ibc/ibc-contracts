// SPDX-License-Identifier: Apache-2.0

use crate::Hash;
use prividium_types::StateCommitmentPreimage;

/// The v0.20.8 preimage layered over the reconstructed native tree root.
#[must_use]
pub fn state_commitment(tree_root: &Hash, value: &StateCommitmentPreimage) -> Hash {
    let mut preimage = [0_u8; 88];
    preimage[..32].copy_from_slice(tree_root);
    preimage[32..40].copy_from_slice(&value.next_free_slot.to_be_bytes());
    preimage[40..48].copy_from_slice(&value.block_number.to_be_bytes());
    preimage[48..80].copy_from_slice(&value.last_256_block_hashes_blake);
    preimage[80..].copy_from_slice(&value.last_block_timestamp.to_be_bytes());
    prividium_crypto::blake2s(&preimage)
}
