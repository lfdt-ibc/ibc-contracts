// SPDX-License-Identifier: Apache-2.0

use prividium_zksync_native::{
    derive_native_tree_key, empty_subtree_hash, hash_branch, hash_leaf, reconstruct_root,
    state_commitment, verify_native_absence, Address, Hash, InnerStorageProof, NativeProofBatch,
    ProofEntry, ProofEntryWithKey, ProofError, StateCommitmentPreimage, StorageSlotProof,
    TREE_DEPTH,
};
use serde::Deserialize;

const EXISTING_NONZERO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/zksync-native/v0.20.8/local/existing-nonzero/raw-response.json"
));
const EXISTING_NONZERO_BATCH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/zksync-native/v0.20.8/local/existing-nonzero/raw-batch-response.json"
));
const NEVER_EXISTING: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/zksync-native/v0.20.8/local/never-existing/raw-response.json"
));
const EXISTING_ZERO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/zksync-native/v0.20.8/local/existing-zero/raw-response.json"
));
const EXISTING_ZERO_BATCH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-data/zksync-native/v0.20.8/local/existing-zero/raw-batch-response.json"
));

const ADDRESS: &str = "0xe441cf0795af14ddb9f7984da85cd36db1b8790d";
const SLOT_ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const SLOT_NEVER_WRITTEN: &str =
    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const ROOT_AT_BATCH_4: &str = "0x1efd73ca324557ff31d344658562e41262281781c16020ba90ed12b79c56950b";
const ROOT_AT_BATCH_5: &str = "0x931b17233867e41047e3f1fb4a3400647ad8eefcb2d495824918a2916c662932";

#[derive(Clone, Debug, Deserialize)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: u64,
    result: T,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireProofResult {
    address: String,
    state_commitment_preimage: WireStateCommitmentPreimage,
    storage_proofs: Vec<WireStorageSlotProof>,
    l1_verification_data: WireL1VerificationData,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireStateCommitmentPreimage {
    next_free_slot: String,
    block_number: String,
    last_256_block_hashes_blake: String,
    last_block_timestamp: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireL1VerificationData {
    batch_number: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct WireStorageSlotProof {
    key: String,
    proof: WireInnerStorageProof,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "type"
)]
enum WireInnerStorageProof {
    Existing {
        index: u64,
        value: String,
        next_index: u64,
        siblings: Vec<String>,
    },
    NonExisting {
        left_neighbor: WireProofEntryWithKey,
        right_neighbor: WireProofEntryWithKey,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireProofEntryWithKey {
    index: u64,
    value: String,
    next_index: u64,
    siblings: Vec<String>,
    leaf_key: String,
}

#[derive(Debug, Deserialize)]
struct WireBatchResult {
    batch_info: WireBatchInfo,
    block_range: WireBlockRange,
}

#[derive(Debug, Deserialize)]
struct WireBatchInfo {
    batch_number: u64,
    state_commitment: String,
}

#[derive(Debug, Deserialize)]
struct WireBlockRange {
    start: u64,
    end: u64,
}

fn hex_bytes<const N: usize>(encoded: &str) -> [u8; N] {
    let encoded = encoded
        .strip_prefix("0x")
        .expect("fixture hex must have a 0x prefix");
    assert_eq!(encoded.len(), N * 2, "fixture hex has the wrong width");
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .expect("fixture hex must be valid");
    }
    output
}

fn hex_u64(encoded: &str) -> u64 {
    u64::from_str_radix(
        encoded
            .strip_prefix("0x")
            .expect("fixture quantity must have a 0x prefix"),
        16,
    )
    .expect("fixture quantity must fit u64")
}

fn parse_proof_fixture(json: &str) -> (RpcEnvelope<WireProofResult>, NativeProofBatch) {
    let envelope: RpcEnvelope<WireProofResult> = serde_json::from_str(json).unwrap();
    let batch = NativeProofBatch {
        address: hex_bytes::<20>(&envelope.result.address),
        storage_proofs: envelope
            .result
            .storage_proofs
            .iter()
            .map(|proof| StorageSlotProof {
                key: hex_bytes::<32>(&proof.key),
                proof: proof.proof.to_native(),
            })
            .collect(),
    };
    (envelope, batch)
}

impl WireInnerStorageProof {
    fn to_native(&self) -> InnerStorageProof {
        match self {
            Self::Existing {
                index,
                value,
                next_index,
                siblings,
            } => InnerStorageProof::Existing(ProofEntry {
                index: *index,
                value: hex_bytes::<32>(value),
                next_index: *next_index,
                siblings: siblings.iter().map(|hash| hex_bytes::<32>(hash)).collect(),
            }),
            Self::NonExisting {
                left_neighbor,
                right_neighbor,
            } => InnerStorageProof::NonExisting {
                left_neighbor: left_neighbor.to_native(),
                right_neighbor: right_neighbor.to_native(),
            },
        }
    }
}

impl WireProofEntryWithKey {
    fn to_native(&self) -> ProofEntryWithKey {
        ProofEntryWithKey {
            entry: ProofEntry {
                index: self.index,
                value: hex_bytes::<32>(&self.value),
                next_index: self.next_index,
                siblings: self
                    .siblings
                    .iter()
                    .map(|hash| hex_bytes::<32>(hash))
                    .collect(),
            },
            leaf_key: hex_bytes::<32>(&self.leaf_key),
        }
    }
}

impl WireStateCommitmentPreimage {
    fn to_native(&self) -> StateCommitmentPreimage {
        StateCommitmentPreimage {
            next_free_slot: hex_u64(&self.next_free_slot),
            block_number: hex_u64(&self.block_number),
            last_256_block_hashes_blake: hex_bytes::<32>(&self.last_256_block_hashes_blake),
            last_block_timestamp: hex_u64(&self.last_block_timestamp),
        }
    }
}

fn root_with_fully_expanded_path(leaf_key: &Hash, entry: &ProofEntry) -> Hash {
    let mut root = hash_leaf(leaf_key, &entry.value, entry.next_index);
    let mut index = entry.index;
    for depth in 0..TREE_DEPTH {
        let sibling = entry
            .siblings
            .get(usize::from(depth))
            .copied()
            .unwrap_or_else(|| empty_subtree_hash(depth).unwrap());
        root = if index.is_multiple_of(2) {
            hash_branch(&root, &sibling)
        } else {
            hash_branch(&sibling, &root)
        };
        index /= 2;
    }
    root
}

#[test]
fn real_existing_nonzero_rpc_response_verifies_to_batch_and_settlement_state() {
    let (wire, proof) = parse_proof_fixture(EXISTING_NONZERO);
    let batch: RpcEnvelope<WireBatchResult> = serde_json::from_str(EXISTING_NONZERO_BATCH).unwrap();
    let address: Address = hex_bytes(ADDRESS);
    let slot: Hash = hex_bytes(SLOT_ZERO);
    let expected_root: Hash = hex_bytes(ROOT_AT_BATCH_4);

    assert_eq!(wire.jsonrpc, "2.0");
    assert_eq!(wire.id, 1001);
    assert_eq!(wire.result.l1_verification_data.batch_number, 4);
    assert_eq!(batch.result.batch_info.batch_number, 4);
    assert_eq!(batch.result.block_range.start, 4);
    assert_eq!(batch.result.block_range.end, 4);
    assert_eq!(
        derive_native_tree_key(&address, &slot),
        hex_bytes("0xa01e4211894e4d61851e1b9b9afa0e24375e6bed7c2e431ff9d05709d1519d32")
    );

    let verified = proof
        .verify_against_root(&address, &[slot], &expected_root)
        .unwrap();
    assert_eq!(verified.tree_root, expected_root);
    assert_eq!(
        verified.values,
        vec![Some(hex_bytes(
            "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff1234"
        ))]
    );

    let state_preimage = wire.result.state_commitment_preimage.to_native();
    let state_commitment = state_commitment(&verified.tree_root, &state_preimage);
    assert_eq!(
        state_commitment,
        hex_bytes("0xd3ec308c0eee7ab0154ef61aa094f8c3e4e3c3f1a3bbcabcd05ab351fe2c4122")
    );
    assert_eq!(
        state_commitment,
        hex_bytes(&batch.result.batch_info.state_commitment)
    );
}

#[test]
fn real_never_existing_rpc_response_is_a_linked_two_neighbor_proof() {
    let (wire, proof) = parse_proof_fixture(NEVER_EXISTING);
    let address: Address = hex_bytes(ADDRESS);
    let slot: Hash = hex_bytes(SLOT_NEVER_WRITTEN);
    let expected_root: Hash = hex_bytes(ROOT_AT_BATCH_4);
    let query_key = derive_native_tree_key(&address, &slot);

    assert_eq!(wire.id, 1002);
    assert_eq!(
        query_key,
        hex_bytes("0xc14de4ee585a6de92c6944aa4b68ddd60009226870b47ebef9ac79d3e7c65a26")
    );

    let InnerStorageProof::NonExisting {
        left_neighbor,
        right_neighbor,
    } = &proof.storage_proofs[0].proof
    else {
        panic!("real never-existing response changed proof variant")
    };
    assert!(left_neighbor.leaf_key < query_key);
    assert!(query_key < right_neighbor.leaf_key);
    assert_eq!(left_neighbor.entry.next_index, right_neighbor.entry.index);
    assert_eq!(left_neighbor.entry.next_index, 22);
    assert_eq!(left_neighbor.entry.siblings.len(), 7);
    assert_eq!(right_neighbor.entry.siblings.len(), 7);

    let left_root = reconstruct_root(
        &left_neighbor.leaf_key,
        &left_neighbor.entry.value,
        left_neighbor.entry.next_index,
        left_neighbor.entry.index,
        &left_neighbor.entry.siblings,
    )
    .unwrap();
    let right_root = reconstruct_root(
        &right_neighbor.leaf_key,
        &right_neighbor.entry.value,
        right_neighbor.entry.next_index,
        right_neighbor.entry.index,
        &right_neighbor.entry.siblings,
    )
    .unwrap();
    assert_eq!(left_root, expected_root);
    assert_eq!(right_root, expected_root);

    let verified = proof
        .verify_against_root(&address, &[slot], &expected_root)
        .unwrap();
    assert_eq!(verified.values, vec![None]);
    verify_native_absence(&proof, &address, &slot, &expected_root).unwrap();
    assert_eq!(
        state_commitment(
            &verified.tree_root,
            &wire.result.state_commitment_preimage.to_native()
        ),
        hex_bytes("0xd3ec308c0eee7ab0154ef61aa094f8c3e4e3c3f1a3bbcabcd05ab351fe2c4122")
    );
}

#[test]
fn real_existing_zero_rpc_response_remains_existing() {
    let (wire, proof) = parse_proof_fixture(EXISTING_ZERO);
    let batch: RpcEnvelope<WireBatchResult> = serde_json::from_str(EXISTING_ZERO_BATCH).unwrap();
    let address: Address = hex_bytes(ADDRESS);
    let slot: Hash = hex_bytes(SLOT_ZERO);
    let expected_root: Hash = hex_bytes(ROOT_AT_BATCH_5);

    let InnerStorageProof::Existing(entry) = &proof.storage_proofs[0].proof else {
        panic!("written-then-zero slot must remain existing")
    };
    assert_eq!(entry.index, 103);
    assert_eq!(entry.next_index, 92);
    assert_eq!(entry.value, [0_u8; 32]);

    let verified = proof
        .verify_against_root(&address, &[slot], &expected_root)
        .unwrap();
    assert_eq!(verified.values, vec![Some([0_u8; 32])]);
    assert_eq!(
        verify_native_absence(&proof, &address, &slot, &expected_root),
        Err(ProofError::ExpectedNativeAbsence)
    );
    let state_preimage = wire.result.state_commitment_preimage.to_native();
    let state_commitment = state_commitment(&verified.tree_root, &state_preimage);
    assert_eq!(batch.result.batch_info.batch_number, 5);
    assert_eq!(
        state_commitment,
        hex_bytes("0xb9af383b2a2a9ff142363956da8ed0349ab104dd10dfdc2ad6418c35fc438181")
    );
    assert_eq!(
        state_commitment,
        hex_bytes(&batch.result.batch_info.state_commitment)
    );
}

#[test]
fn real_compressed_paths_expand_to_the_exact_same_root() {
    let (_, proof) = parse_proof_fixture(NEVER_EXISTING);
    let expected_root: Hash = hex_bytes(ROOT_AT_BATCH_4);
    let InnerStorageProof::NonExisting {
        left_neighbor,
        right_neighbor,
    } = &proof.storage_proofs[0].proof
    else {
        unreachable!()
    };

    assert_eq!(left_neighbor.entry.siblings.len(), 7);
    assert_eq!(right_neighbor.entry.siblings.len(), 7);
    assert_eq!(usize::from(TREE_DEPTH) - 7, 57);
    assert_eq!(
        root_with_fully_expanded_path(&left_neighbor.leaf_key, &left_neighbor.entry),
        expected_root
    );
    assert_eq!(
        root_with_fully_expanded_path(&right_neighbor.leaf_key, &right_neighbor.entry),
        expected_root
    );
}

#[test]
fn real_vectors_fail_closed_under_binding_and_path_mutations() {
    let (_, proof) = parse_proof_fixture(EXISTING_NONZERO);
    let address: Address = hex_bytes(ADDRESS);
    let slot: Hash = hex_bytes(SLOT_ZERO);
    let expected_root: Hash = hex_bytes(ROOT_AT_BATCH_4);

    let mut wrong_address = address;
    wrong_address[0] ^= 1;
    assert!(matches!(
        proof.verify(&wrong_address, &[slot]),
        Err(ProofError::AddressMismatch { .. })
    ));

    let mut wrong_slot = slot;
    wrong_slot[31] ^= 1;
    assert!(matches!(
        proof.verify(&address, &[wrong_slot]),
        Err(ProofError::SlotMismatch { .. })
    ));

    let mut wrong_sibling = proof.clone();
    let InnerStorageProof::Existing(entry) = &mut wrong_sibling.storage_proofs[0].proof else {
        unreachable!()
    };
    entry.siblings[0][0] ^= 1;
    assert_eq!(
        wrong_sibling.verify_against_root(&address, &[slot], &expected_root),
        Err(ProofError::ExpectedRootMismatch)
    );

    let mut wrong_index = proof.clone();
    let InnerStorageProof::Existing(entry) = &mut wrong_index.storage_proofs[0].proof else {
        unreachable!()
    };
    entry.index ^= 1;
    assert_eq!(
        wrong_index.verify_against_root(&address, &[slot], &expected_root),
        Err(ProofError::ExpectedRootMismatch)
    );

    let mut wrong_root = expected_root;
    wrong_root[0] ^= 1;
    assert_eq!(
        proof.verify_against_root(&address, &[slot], &wrong_root),
        Err(ProofError::ExpectedRootMismatch)
    );
}

#[test]
fn real_nonmembership_vector_rejects_bad_link_and_bad_ordering() {
    let (_, proof) = parse_proof_fixture(NEVER_EXISTING);
    let address: Address = hex_bytes(ADDRESS);
    let slot: Hash = hex_bytes(SLOT_NEVER_WRITTEN);
    let query_key = derive_native_tree_key(&address, &slot);

    let mut bad_link = proof.clone();
    let InnerStorageProof::NonExisting { left_neighbor, .. } =
        &mut bad_link.storage_proofs[0].proof
    else {
        unreachable!()
    };
    left_neighbor.entry.next_index += 1;
    assert!(matches!(
        bad_link.verify(&address, &[slot]),
        Err(ProofError::NeighborsNotLinked { .. })
    ));

    let mut bad_left_order = proof.clone();
    let InnerStorageProof::NonExisting { left_neighbor, .. } =
        &mut bad_left_order.storage_proofs[0].proof
    else {
        unreachable!()
    };
    left_neighbor.leaf_key = query_key;
    assert_eq!(
        bad_left_order.verify(&address, &[slot]),
        Err(ProofError::LeftNeighborNotLess)
    );

    let mut bad_right_order = proof.clone();
    let InnerStorageProof::NonExisting { right_neighbor, .. } =
        &mut bad_right_order.storage_proofs[0].proof
    else {
        unreachable!()
    };
    right_neighbor.leaf_key = query_key;
    assert_eq!(
        bad_right_order.verify(&address, &[slot]),
        Err(ProofError::RightNeighborNotGreater)
    );
}
