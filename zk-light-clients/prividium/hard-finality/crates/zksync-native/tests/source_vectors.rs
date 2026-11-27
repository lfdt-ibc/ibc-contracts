// SPDX-License-Identifier: Apache-2.0

use prividium_zksync_native::{
    derive_native_tree_key, empty_subtree_hash, empty_tree_root, hash_branch, hash_leaf,
    state_commitment, verify_native_absence, InnerStorageProof, NativeProofBatch, ProofEntry,
    ProofEntryWithKey, ProofError, StateCommitmentPreimage, StorageSlotProof, MAX_GUARD_KEY,
    MIN_GUARD_KEY, TREE_DEPTH,
};

fn hash(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn initial_tree_absence(slot: [u8; 32], address: [u8; 20]) -> NativeProofBatch {
    let max_guard_hash = hash_leaf(&MAX_GUARD_KEY, &[0_u8; 32], 1);
    let min_guard_hash = hash_leaf(&MIN_GUARD_KEY, &[0_u8; 32], 1);
    NativeProofBatch {
        address,
        storage_proofs: vec![StorageSlotProof {
            key: slot,
            proof: InnerStorageProof::NonExisting {
                left_neighbor: ProofEntryWithKey {
                    leaf_key: MIN_GUARD_KEY,
                    entry: ProofEntry {
                        index: 0,
                        value: [0_u8; 32],
                        next_index: 1,
                        siblings: vec![max_guard_hash],
                    },
                },
                right_neighbor: ProofEntryWithKey {
                    leaf_key: MAX_GUARD_KEY,
                    entry: ProofEntry {
                        index: 1,
                        value: [0_u8; 32],
                        next_index: 1,
                        siblings: vec![min_guard_hash],
                    },
                },
            },
        }],
    }
}

fn single_insert_proof(value: [u8; 32]) -> InnerStorageProof {
    let min_guard_with_insert = hash_leaf(&MIN_GUARD_KEY, &[0_u8; 32], 2);
    let max_guard = hash_leaf(&MAX_GUARD_KEY, &[0_u8; 32], 1);
    InnerStorageProof::Existing(ProofEntry {
        index: 2,
        value,
        next_index: 1,
        siblings: vec![
            empty_subtree_hash(0).unwrap(),
            hash_branch(&min_guard_with_insert, &max_guard),
        ],
    })
}

#[test]
fn pinned_empty_and_guard_hash_vectors() {
    assert_eq!(
        empty_subtree_hash(0).unwrap(),
        hash("e3cdc93b3c2beb30f6a7c7cc45a32da012df9ae1be880e2c074885cb3f4e1e53")
    );
    assert_eq!(
        empty_subtree_hash(1).unwrap(),
        hash("c45bfaf4bb5d0fee27d3178b8475155a07a1fa8ada9a15133a9016f7d0435f0f")
    );
    assert_eq!(
        empty_subtree_hash(63).unwrap(),
        hash("b720fe53e6bd4e997d967b8649e10036802a4fd3aca6d7dcc43ed9671f41cb31")
    );
    assert_eq!(
        hash_leaf(&MIN_GUARD_KEY, &[0_u8; 32], 1),
        hash("9903897e51baa96a5ea51b4c194d3e0c6bcf20947cce9fd646dfb4bf754c8d28")
    );
    assert_eq!(
        hash_leaf(&MAX_GUARD_KEY, &[0_u8; 32], 1),
        hash("b35299e7564e05e335094c02064bccf83d58745b417874b1fee3f523ec2007a9")
    );
    assert_eq!(
        empty_tree_root(),
        hash("90a83ead2ba2194fbbb0f7cd2a017e36cfb4891513546d943a7282c2844d4b6b")
    );
}

#[test]
fn pinned_flat_key_vector() {
    assert_eq!(
        derive_native_tree_key(&[0x11; 20], &[0x22; 32]),
        hash("a03cce7e22ac7562e62a193a3971334cf65ad79512eb88d6a8b479f3b45309b2")
    );
}

#[test]
fn never_existing_key_uses_linked_neighbor_proof() {
    let address = [0x11; 20];
    let slot = [0x22; 32];
    let proof = initial_tree_absence(slot, address);
    let verified = proof.verify(&address, &[slot]).unwrap();
    assert_eq!(verified.tree_root, empty_tree_root());
    assert_eq!(verified.values, vec![None]);
    verify_native_absence(&proof, &address, &slot, &empty_tree_root()).unwrap();
}

#[test]
fn present_leaf_matches_pinned_single_insert_root() {
    let flat_key = [0x01; 32];
    let proof = single_insert_proof([0x10; 32]);
    let (root, value) = match proof {
        InnerStorageProof::Existing(entry) => {
            let batch = NativeProofBatch {
                address: [0_u8; 20],
                storage_proofs: vec![StorageSlotProof {
                    key: [0_u8; 32],
                    proof: InnerStorageProof::Existing(entry),
                }],
            };
            // Bypass address/slot derivation for this upstream flat-key vector by
            // reconstructing the path directly.
            let InnerStorageProof::Existing(entry) = &batch.storage_proofs[0].proof else {
                unreachable!()
            };
            (
                prividium_zksync_native::reconstruct_root(
                    &flat_key,
                    &entry.value,
                    entry.next_index,
                    entry.index,
                    &entry.siblings,
                )
                .unwrap(),
                entry.value,
            )
        }
        _ => unreachable!(),
    };
    assert_eq!(value, [0x10; 32]);
    assert_eq!(
        root,
        hash("08da20879eebed16fbd14e50b427bb97c8737aa860e6519877757e238df83a15")
    );
}

#[test]
fn existing_zero_value_is_not_native_absence() {
    let flat_key = derive_native_tree_key(&[0_u8; 20], &[0_u8; 32]);
    let proof = single_insert_proof([0_u8; 32]);
    let InnerStorageProof::Existing(entry) = proof else {
        unreachable!()
    };
    let root = prividium_zksync_native::reconstruct_root(
        &flat_key,
        &entry.value,
        entry.next_index,
        entry.index,
        &entry.siblings,
    )
    .unwrap();
    let batch = NativeProofBatch {
        address: [0_u8; 20],
        storage_proofs: vec![StorageSlotProof {
            key: [0_u8; 32],
            proof: InnerStorageProof::Existing(entry),
        }],
    };
    let verified = batch.verify(&[0_u8; 20], &[[0_u8; 32]]).unwrap();
    assert_eq!(verified.tree_root, root);
    assert_eq!(verified.values, vec![Some([0_u8; 32])]);
    assert_eq!(
        verify_native_absence(&batch, &[0_u8; 20], &[0_u8; 32], &root),
        Err(ProofError::ExpectedNativeAbsence)
    );
}

#[test]
fn compressed_trailing_empty_siblings_expand_deterministically() {
    let key = MIN_GUARD_KEY;
    let value = [0_u8; 32];
    let max_guard = hash_leaf(&MAX_GUARD_KEY, &value, 1);
    let compressed =
        prividium_zksync_native::reconstruct_root(&key, &value, 1, 0, &[max_guard]).unwrap();

    let mut expanded = vec![max_guard];
    for depth in 1..TREE_DEPTH - 1 {
        expanded.push(empty_subtree_hash(depth).unwrap());
    }
    let expanded =
        prividium_zksync_native::reconstruct_root(&key, &value, 1, 0, &expanded).unwrap();
    assert_eq!(compressed, expanded);
    assert_eq!(compressed, empty_tree_root());
}

#[test]
fn absence_rejects_non_adjacent_neighbors() {
    let address = [0x11; 20];
    let slot = [0x22; 32];
    let mut proof = initial_tree_absence(slot, address);
    let InnerStorageProof::NonExisting { left_neighbor, .. } = &mut proof.storage_proofs[0].proof
    else {
        unreachable!()
    };
    left_neighbor.entry.next_index = 7;
    assert!(matches!(
        proof.verify(&address, &[slot]),
        Err(ProofError::NeighborsNotLinked { .. })
    ));
}

#[test]
fn absence_rejects_mutated_neighbor_path() {
    let address = [0x11; 20];
    let slot = [0x22; 32];
    let mut proof = initial_tree_absence(slot, address);
    let InnerStorageProof::NonExisting { right_neighbor, .. } = &mut proof.storage_proofs[0].proof
    else {
        unreachable!()
    };
    right_neighbor.entry.siblings[0][0] ^= 1;
    assert_eq!(
        proof.verify(&address, &[slot]),
        Err(ProofError::NeighborRootMismatch)
    );
}

#[test]
fn exact_address_and_slot_are_bound() {
    let address = [0x11; 20];
    let slot = [0x22; 32];
    let proof = initial_tree_absence(slot, address);
    assert!(matches!(
        proof.verify(&[0x12; 20], &[slot]),
        Err(ProofError::AddressMismatch { .. })
    ));
    assert!(matches!(
        proof.verify(&address, &[[0x23; 32]]),
        Err(ProofError::SlotMismatch { .. })
    ));
}

#[test]
fn verifier_rejects_64_explicit_siblings_like_pinned_source() {
    let error = prividium_zksync_native::reconstruct_root(
        &[1_u8; 32],
        &[2_u8; 32],
        1,
        2,
        &vec![[0_u8; 32]; usize::from(TREE_DEPTH)],
    )
    .unwrap_err();
    assert_eq!(
        error,
        ProofError::TooManySiblings {
            actual: 64,
            maximum: 63
        }
    );
}

#[test]
fn state_commitment_uses_big_endian_u64_fields() {
    let root = hash("08da20879eebed16fbd14e50b427bb97c8737aa860e6519877757e238df83a15");
    let preimage = StateCommitmentPreimage {
        next_free_slot: 3,
        block_number: 7,
        last_256_block_hashes_blake: [0x33; 32],
        last_block_timestamp: 11,
    };
    assert_eq!(
        state_commitment(&root, &preimage),
        hash("6f1bb09506da5316b991a2173b6bec282bdc1a275d7c90b415d8b363018c9fee")
    );
}

#[test]
fn every_structural_rejection_is_fail_closed() {
    let address = [0x11; 20];
    let slot = [0x22; 32];
    let flat_key = derive_native_tree_key(&address, &slot);

    let empty = NativeProofBatch {
        address,
        storage_proofs: vec![],
    };
    assert_eq!(empty.verify(&address, &[]), Err(ProofError::EmptyBatch));

    let proof = initial_tree_absence(slot, address);
    assert!(matches!(
        proof.verify(&address, &[slot, [0x23; 32]]),
        Err(ProofError::SlotCountMismatch { .. })
    ));
    assert_eq!(
        proof.verify_against_root(&address, &[slot], &[0x44; 32]),
        Err(ProofError::ExpectedRootMismatch)
    );
    assert_eq!(
        empty_subtree_hash(TREE_DEPTH + 1),
        Err(ProofError::EmptyHashDepthOutOfRange { depth: 65 })
    );

    let mut bad_left = initial_tree_absence(slot, address);
    let InnerStorageProof::NonExisting { left_neighbor, .. } =
        &mut bad_left.storage_proofs[0].proof
    else {
        unreachable!()
    };
    left_neighbor.leaf_key = flat_key;
    assert_eq!(
        bad_left.verify(&address, &[slot]),
        Err(ProofError::LeftNeighborNotLess)
    );

    let mut bad_right = initial_tree_absence(slot, address);
    let InnerStorageProof::NonExisting { right_neighbor, .. } =
        &mut bad_right.storage_proofs[0].proof
    else {
        unreachable!()
    };
    right_neighbor.leaf_key = flat_key;
    assert_eq!(
        bad_right.verify(&address, &[slot]),
        Err(ProofError::RightNeighborNotGreater)
    );
}

#[test]
fn multiple_slots_must_reconstruct_one_root() {
    let address = [0x11; 20];
    let first_slot = [0x22; 32];
    let second_slot = [0x23; 32];
    let first_key = derive_native_tree_key(&address, &first_slot);
    let second_key = derive_native_tree_key(&address, &second_slot);
    assert_ne!(first_key, second_key);

    let entry = ProofEntry {
        index: 2,
        value: [0x10; 32],
        next_index: 1,
        siblings: vec![],
    };
    let batch = NativeProofBatch {
        address,
        storage_proofs: vec![
            StorageSlotProof {
                key: first_slot,
                proof: InnerStorageProof::Existing(entry.clone()),
            },
            StorageSlotProof {
                key: second_slot,
                proof: InnerStorageProof::Existing(entry),
            },
        ],
    };
    assert_eq!(
        batch.verify(&address, &[first_slot, second_slot]),
        Err(ProofError::BatchRootMismatch { position: 1 })
    );
}
