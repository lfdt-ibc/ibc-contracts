// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

pub mod absence;
pub mod empty;
pub mod error;
pub mod hash;
pub mod leaf;
pub mod path;
pub mod proof;
pub mod state_commitment;
pub mod tree_key;

pub use absence::{verify_native_absence, verify_native_absence_with_flat_key};
pub use empty::{empty_subtree_hash, empty_tree_root, MAX_GUARD_KEY, MIN_GUARD_KEY};
pub use error::ProofError;
pub use hash::hash_branch;
pub use leaf::hash_leaf;
pub use path::reconstruct_root;
pub use prividium_types::StateCommitmentPreimage;
pub use proof::{
    InnerStorageProof, NativeProofBatch, ProofEntry, ProofEntryWithKey, StorageSlotProof,
    VerifiedBatch,
};
pub use state_commitment::state_commitment;
pub use tree_key::derive_native_tree_key;

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

/// The binary tree depth hard-coded by `BatchStorageProof::TREE_DEPTH` in
/// zksync-os-server v0.20.8.
pub const TREE_DEPTH: u8 = 64;
