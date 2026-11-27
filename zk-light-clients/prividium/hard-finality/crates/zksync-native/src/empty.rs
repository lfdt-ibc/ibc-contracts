// SPDX-License-Identifier: Apache-2.0

use crate::{error::ProofError, hash::hash_branch, leaf::hash_leaf, Hash, TREE_DEPTH};

pub const MIN_GUARD_KEY: Hash = [0_u8; 32];
pub const MAX_GUARD_KEY: Hash = [0xff_u8; 32];

include!(concat!(env!("OUT_DIR"), "/empty_subtree_hashes.rs"));

/// Zero-sized accessor for the build-time-generated default subtree hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EmptySubtreeHashes;

impl EmptySubtreeHashes {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn at(&self, depth: u8) -> Result<Hash, ProofError> {
        EMPTY_SUBTREE_HASHES
            .get(usize::from(depth))
            .copied()
            .ok_or(ProofError::EmptyHashDepthOutOfRange { depth })
    }
}

impl Default for EmptySubtreeHashes {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns H(depth), where H(0) is the default-leaf hash and
/// H(d + 1) = BLAKE2s(H(d) || H(d)).
pub fn empty_subtree_hash(depth: u8) -> Result<Hash, ProofError> {
    EmptySubtreeHashes::new().at(depth)
}

/// Root of the initialized v0.20.8 tree containing only its two guard leaves.
pub fn empty_tree_root() -> Hash {
    let min_guard = hash_leaf(&MIN_GUARD_KEY, &[0_u8; 32], 1);
    let max_guard = hash_leaf(&MAX_GUARD_KEY, &[0_u8; 32], 1);
    let mut hash = hash_branch(&min_guard, &max_guard);
    for depth in 1..TREE_DEPTH {
        // The loop bound is fixed by TREE_DEPTH, so this lookup cannot fail.
        let empty = EMPTY_SUBTREE_HASHES[usize::from(depth)];
        hash = hash_branch(&hash, &empty);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_empty_hashes_match_the_protocol_recurrence() {
        assert_eq!(
            EMPTY_SUBTREE_HASHES[0],
            hash_leaf(&[0_u8; 32], &[0_u8; 32], 0)
        );
        for depth in 1..=usize::from(TREE_DEPTH) {
            assert_eq!(
                EMPTY_SUBTREE_HASHES[depth],
                hash_branch(
                    &EMPTY_SUBTREE_HASHES[depth - 1],
                    &EMPTY_SUBTREE_HASHES[depth - 1]
                )
            );
        }
    }
}
