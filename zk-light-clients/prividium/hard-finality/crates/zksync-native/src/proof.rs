// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::{
    empty::EmptySubtreeHashes, error::ProofError, path::reconstruct_root_with_empty_hashes,
    tree_key::derive_native_tree_key, Address, Hash,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEntry {
    /// Zero-based append-only leaf position; its low bit is consumed first.
    pub index: u64,
    pub value: Hash,
    /// Zero-based index of the lexicographically next leaf.
    pub next_index: u64,
    /// Explicit path prefix in leaf-to-root order.
    pub siblings: Vec<Hash>,
}

impl ProofEntry {
    fn root(&self, leaf_key: &Hash, empty_hashes: &EmptySubtreeHashes) -> Result<Hash, ProofError> {
        reconstruct_root_with_empty_hashes(
            leaf_key,
            &self.value,
            self.next_index,
            self.index,
            &self.siblings,
            empty_hashes,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEntryWithKey {
    pub entry: ProofEntry,
    pub leaf_key: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InnerStorageProof {
    Existing(ProofEntry),
    /// Source-defined tree absence: adjacent ordered leaves bracket the key.
    NonExisting {
        left_neighbor: ProofEntryWithKey,
        right_neighbor: ProofEntryWithKey,
    },
}

impl InnerStorageProof {
    fn verify(
        &self,
        queried_flat_key: &Hash,
        empty_hashes: &EmptySubtreeHashes,
    ) -> Result<(Hash, Option<Hash>), ProofError> {
        match self {
            Self::Existing(entry) => Ok((
                entry.root(queried_flat_key, empty_hashes)?,
                Some(entry.value),
            )),
            Self::NonExisting {
                left_neighbor,
                right_neighbor,
            } => {
                if left_neighbor.leaf_key >= *queried_flat_key {
                    return Err(ProofError::LeftNeighborNotLess);
                }
                if *queried_flat_key >= right_neighbor.leaf_key {
                    return Err(ProofError::RightNeighborNotGreater);
                }
                if left_neighbor.entry.next_index != right_neighbor.entry.index {
                    return Err(ProofError::NeighborsNotLinked {
                        left_next_index: left_neighbor.entry.next_index,
                        right_index: right_neighbor.entry.index,
                    });
                }

                let left_root = left_neighbor
                    .entry
                    .root(&left_neighbor.leaf_key, empty_hashes)?;
                let right_root = right_neighbor
                    .entry
                    .root(&right_neighbor.leaf_key, empty_hashes)?;
                if left_root != right_root {
                    return Err(ProofError::NeighborRootMismatch);
                }
                Ok((left_root, None))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSlotProof {
    /// Original address-scoped Solidity slot returned by `zks_getProof`.
    pub key: Hash,
    pub proof: InnerStorageProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeProofBatch {
    pub address: Address,
    pub storage_proofs: Vec<StorageSlotProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBatch {
    pub tree_root: Hash,
    /// `Some([0; 32])` is an existing zero-valued leaf; `None` is native absence.
    pub values: Vec<Option<Hash>>,
}

impl NativeProofBatch {
    pub fn verify(
        &self,
        queried_address: &Address,
        queried_slots: &[Hash],
    ) -> Result<VerifiedBatch, ProofError> {
        if queried_slots.is_empty() {
            return Err(ProofError::EmptyBatch);
        }
        if self.address != *queried_address {
            return Err(ProofError::AddressMismatch {
                expected: *queried_address,
                actual: self.address,
            });
        }
        if self.storage_proofs.len() != queried_slots.len() {
            return Err(ProofError::SlotCountMismatch {
                expected: queried_slots.len(),
                actual: self.storage_proofs.len(),
            });
        }

        let empty_hashes = EmptySubtreeHashes::new();
        let mut root = None;
        let mut values = Vec::with_capacity(self.storage_proofs.len());
        for (position, (proof, queried_slot)) in
            self.storage_proofs.iter().zip(queried_slots).enumerate()
        {
            if proof.key != *queried_slot {
                return Err(ProofError::SlotMismatch {
                    position,
                    expected: *queried_slot,
                    actual: proof.key,
                });
            }
            let flat_key = derive_native_tree_key(queried_address, queried_slot);
            let (proof_root, value) = proof.proof.verify(&flat_key, &empty_hashes)?;
            if let Some(expected) = root {
                if proof_root != expected {
                    return Err(ProofError::BatchRootMismatch { position });
                }
            } else {
                root = Some(proof_root);
            }
            values.push(value);
        }

        Ok(VerifiedBatch {
            // Safe because empty queried/proof batches were rejected above.
            tree_root: root.ok_or(ProofError::EmptyBatch)?,
            values,
        })
    }

    pub fn verify_against_root(
        &self,
        queried_address: &Address,
        queried_slots: &[Hash],
        expected_root: &Hash,
    ) -> Result<VerifiedBatch, ProofError> {
        let verified = self.verify(queried_address, queried_slots)?;
        if verified.tree_root != *expected_root {
            return Err(ProofError::ExpectedRootMismatch);
        }
        Ok(verified)
    }

    /// Verifies the circuit's common one-address / one-slot proof shape
    /// without allocating query or result vectors.
    fn verify_single_with_flat_key(
        &self,
        queried_address: &Address,
        queried_slot: &Hash,
        flat_key: &Hash,
    ) -> Result<(Hash, Option<Hash>), ProofError> {
        if self.address != *queried_address {
            return Err(ProofError::AddressMismatch {
                expected: *queried_address,
                actual: self.address,
            });
        }
        if self.storage_proofs.len() != 1 {
            return Err(ProofError::SlotCountMismatch {
                expected: 1,
                actual: self.storage_proofs.len(),
            });
        }
        let proof = &self.storage_proofs[0];
        if proof.key != *queried_slot {
            return Err(ProofError::SlotMismatch {
                position: 0,
                expected: *queried_slot,
                actual: proof.key,
            });
        }
        let empty_hashes = EmptySubtreeHashes::new();
        proof.proof.verify(flat_key, &empty_hashes)
    }

    pub fn verify_single_against_root(
        &self,
        queried_address: &Address,
        queried_slot: &Hash,
        expected_root: &Hash,
    ) -> Result<Option<Hash>, ProofError> {
        let flat_key = derive_native_tree_key(queried_address, queried_slot);
        self.verify_single_with_flat_key_against_root(
            queried_address,
            queried_slot,
            &flat_key,
            expected_root,
        )
    }

    /// Verifies a single proof using a flat key already derived from the same
    /// address and slot by the caller. This avoids hashing the fixed key
    /// preimage twice when the caller also exposes the derived key publicly.
    pub fn verify_single_with_flat_key_against_root(
        &self,
        queried_address: &Address,
        queried_slot: &Hash,
        flat_key: &Hash,
        expected_root: &Hash,
    ) -> Result<Option<Hash>, ProofError> {
        let (tree_root, value) =
            self.verify_single_with_flat_key(queried_address, queried_slot, flat_key)?;
        if tree_root != *expected_root {
            return Err(ProofError::ExpectedRootMismatch);
        }
        Ok(value)
    }
}
