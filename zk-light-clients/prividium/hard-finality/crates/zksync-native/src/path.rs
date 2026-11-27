// SPDX-License-Identifier: Apache-2.0

use crate::{
    empty::EmptySubtreeHashes, error::ProofError, hash::hash_branch, leaf::hash_leaf, Hash,
    TREE_DEPTH,
};

/// Reconstructs a v0.20.8 native tree root.
///
/// Explicit siblings are ordered leaf-to-root. Omitted trailing siblings are
/// expanded to the empty-subtree hash for their exact depth. The least
/// significant bit of `index` selects the leaf-level direction first.
pub fn reconstruct_root(
    leaf_key: &Hash,
    value: &Hash,
    next_index: u64,
    index: u64,
    siblings: &[Hash],
) -> Result<Hash, ProofError> {
    reconstruct_root_with_empty_hashes(
        leaf_key,
        value,
        next_index,
        index,
        siblings,
        &EmptySubtreeHashes::new(),
    )
}

/// Reconstructs a root using a shared table of default subtree hashes.
pub(crate) fn reconstruct_root_with_empty_hashes(
    leaf_key: &Hash,
    value: &Hash,
    next_index: u64,
    mut index: u64,
    siblings: &[Hash],
    empty_hashes: &EmptySubtreeHashes,
) -> Result<Hash, ProofError> {
    let maximum = usize::from(TREE_DEPTH - 1);
    if siblings.len() > maximum {
        return Err(ProofError::TooManySiblings {
            actual: siblings.len(),
            maximum,
        });
    }

    let mut hash = hash_leaf(leaf_key, value, next_index);
    for depth in 0..TREE_DEPTH {
        let sibling = match siblings.get(usize::from(depth)) {
            Some(sibling) => *sibling,
            None => empty_hashes.at(depth)?,
        };
        hash = if index.is_multiple_of(2) {
            hash_branch(&hash, &sibling)
        } else {
            hash_branch(&sibling, &hash)
        };
        index /= 2;
    }
    Ok(hash)
}
