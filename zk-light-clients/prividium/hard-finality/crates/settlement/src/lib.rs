// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use prividium_ethereum_mpt::{verify_account, verify_storage_value, MptError};
use prividium_ssz::{execution_payload_header_root, verify_branch, SszError};
use prividium_types::{
    Address, EvmStorageProofWitness, ForkExecutionPayloadHeader, Hash32, L1VerificationData,
    StateCommitmentPreimage,
};
use prividium_zksync_native::state_commitment;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementError {
    Ssz(SszError),
    Mpt(MptError),
    SettlementAccountAbsent,
    StoredBatchHashSlotMismatch,
    TotalBatchesExecutedSlotMismatch,
    StoredBatchHashAbsent,
    TotalBatchesExecutedAbsent,
    BatchNotCommitted,
    BatchNotExecuted,
    StoredBatchHashMismatch,
}

#[derive(Clone, Copy)]
pub struct StoredBatchAuthentication<'a> {
    pub authenticated_l1_state_root: Hash32,
    pub settlement_address: Address,
    pub account_proof_nodes: &'a [alloc::vec::Vec<u8>],
    pub stored_batch_hash_proof: &'a EvmStorageProofWitness,
    pub total_batches_executed_proof: &'a EvmStorageProofWitness,
    pub stored_batch_hash_mapping_base_slot: Hash32,
    pub total_batches_executed_slot: Hash32,
    pub native_root: Hash32,
    pub state_preimage: &'a StateCommitmentPreimage,
    pub verification: &'a L1VerificationData,
}

#[must_use]
pub fn stored_batch_hash_slot(batch: u64, mapping_base_slot: Hash32) -> Hash32 {
    let mut preimage = [0_u8; 64];
    preimage[24..32].copy_from_slice(&batch.to_be_bytes());
    preimage[32..].copy_from_slice(&mapping_base_slot);
    prividium_crypto::keccak256(&preimage)
}

/// Exact v0.20.8 `keccak256(abi.encode(StoredBatchInfo))` layout.
#[must_use]
pub fn stored_batch_info_hash(
    native_root: Hash32,
    state_preimage: &StateCommitmentPreimage,
    verification: &L1VerificationData,
) -> Hash32 {
    let mut encoded = [0_u8; 32 * 9];
    encoded[24..32].copy_from_slice(&verification.batch_number.to_be_bytes());
    encoded[32..64].copy_from_slice(&state_commitment(&native_root, state_preimage));
    // indexRepeatedStorageChanges word is zero.
    encoded[120..128].copy_from_slice(&verification.number_of_layer1_txs.to_be_bytes());
    encoded[128..160].copy_from_slice(&verification.priority_operations_hash);
    encoded[160..192].copy_from_slice(&verification.dependency_roots_rolling_hash);
    encoded[192..224].copy_from_slice(&verification.l2_to_l1_logs_root_hash);
    // timestamp word is zero.
    encoded[256..288].copy_from_slice(&verification.commitment);
    prividium_crypto::keccak256(&encoded)
}

fn require_executed_batch(
    batch_number: u64,
    total_batches_executed: Hash32,
) -> Result<(), SettlementError> {
    let mut batch_number_word = [0_u8; 32];
    batch_number_word[24..].copy_from_slice(&batch_number.to_be_bytes());
    if total_batches_executed < batch_number_word {
        return Err(SettlementError::BatchNotExecuted);
    }
    Ok(())
}

/// Authenticates that batch `K` has both the expected stored batch hash and has
/// reached the executed lifecycle stage in the same authenticated L1 state.
pub fn authenticate_stored_batch(
    input: StoredBatchAuthentication<'_>,
) -> Result<Hash32, SettlementError> {
    let expected_slot = stored_batch_hash_slot(
        input.verification.batch_number,
        input.stored_batch_hash_mapping_base_slot,
    );
    if input.stored_batch_hash_proof.slot != expected_slot {
        return Err(SettlementError::StoredBatchHashSlotMismatch);
    }
    if input.total_batches_executed_proof.slot != input.total_batches_executed_slot {
        return Err(SettlementError::TotalBatchesExecutedSlotMismatch);
    }
    let account = verify_account(
        input.authenticated_l1_state_root,
        &input.settlement_address,
        input.account_proof_nodes,
    )?
    .ok_or(SettlementError::SettlementAccountAbsent)?;
    let authenticated = verify_storage_value(
        account.storage_root,
        &input.stored_batch_hash_proof.slot,
        &input.stored_batch_hash_proof.proof_nodes,
    )?
    .ok_or(SettlementError::StoredBatchHashAbsent)?;
    if authenticated == [0; 32] {
        return Err(SettlementError::BatchNotCommitted);
    }
    let computed =
        stored_batch_info_hash(input.native_root, input.state_preimage, input.verification);
    if authenticated != computed {
        return Err(SettlementError::StoredBatchHashMismatch);
    }
    let total_batches_executed = verify_storage_value(
        account.storage_root,
        &input.total_batches_executed_proof.slot,
        &input.total_batches_executed_proof.proof_nodes,
    )?
    .ok_or(SettlementError::TotalBatchesExecutedAbsent)?;
    require_executed_batch(input.verification.batch_number, total_batches_executed)?;
    Ok(input.native_root)
}

impl From<SszError> for SettlementError {
    fn from(value: SszError) -> Self {
        Self::Ssz(value)
    }
}

impl From<MptError> for SettlementError {
    fn from(value: MptError) -> Self {
        Self::Mpt(value)
    }
}

pub fn authenticate_execution_payload_state_root(
    header: &ForkExecutionPayloadHeader,
    execution_branch: &[Hash32],
    profile_execution_gindex: u64,
    authenticated_beacon_body_root: Hash32,
) -> Result<Hash32, SettlementError> {
    let header_root = execution_payload_header_root(header)?;
    verify_branch(
        header_root,
        execution_branch,
        profile_execution_gindex,
        authenticated_beacon_body_root,
    )?;
    match header {
        ForkExecutionPayloadHeader::FuluCompatibilityV1(value) => Ok(value.state_root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_storage_slot_is_rejected_before_proof_work() {
        let proof = EvmStorageProofWitness {
            slot: [1; 32],
            proof_nodes: alloc::vec::Vec::new(),
        };
        let preimage = StateCommitmentPreimage {
            next_free_slot: 0,
            block_number: 0,
            last_256_block_hashes_blake: [0; 32],
            last_block_timestamp: 0,
        };
        let verification = L1VerificationData {
            batch_number: 7,
            number_of_layer1_txs: 0,
            priority_operations_hash: [0; 32],
            dependency_roots_rolling_hash: [0; 32],
            l2_to_l1_logs_root_hash: [0; 32],
            commitment: [0; 32],
        };
        assert_eq!(
            authenticate_stored_batch(StoredBatchAuthentication {
                authenticated_l1_state_root: [0; 32],
                settlement_address: [0; 20],
                account_proof_nodes: &[],
                stored_batch_hash_proof: &proof,
                total_batches_executed_proof: &EvmStorageProofWitness {
                    slot: [2; 32],
                    proof_nodes: alloc::vec::Vec::new()
                },
                stored_batch_hash_mapping_base_slot: [9; 32],
                total_batches_executed_slot: [2; 32],
                native_root: [0; 32],
                state_preimage: &preimage,
                verification: &verification,
            }),
            Err(SettlementError::StoredBatchHashSlotMismatch)
        );
    }

    #[test]
    fn absent_settlement_account_is_rejected() {
        let query = EvmStorageProofWitness {
            slot: stored_batch_hash_slot(7, [9; 32]),
            proof_nodes: alloc::vec::Vec::new(),
        };
        let preimage = StateCommitmentPreimage {
            next_free_slot: 0,
            block_number: 0,
            last_256_block_hashes_blake: [0; 32],
            last_block_timestamp: 0,
        };
        let verification = L1VerificationData {
            batch_number: 7,
            number_of_layer1_txs: 0,
            priority_operations_hash: [0; 32],
            dependency_roots_rolling_hash: [0; 32],
            l2_to_l1_logs_root_hash: [0; 32],
            commitment: [0; 32],
        };
        assert_eq!(
            authenticate_stored_batch(StoredBatchAuthentication {
                authenticated_l1_state_root: prividium_crypto::keccak256(&[0x80]),
                settlement_address: [0; 20],
                account_proof_nodes: &[],
                stored_batch_hash_proof: &query,
                total_batches_executed_proof: &EvmStorageProofWitness {
                    slot: [2; 32],
                    proof_nodes: alloc::vec::Vec::new()
                },
                stored_batch_hash_mapping_base_slot: [9; 32],
                total_batches_executed_slot: [2; 32],
                native_root: [0; 32],
                state_preimage: &preimage,
                verification: &verification,
            }),
            Err(SettlementError::SettlementAccountAbsent)
        );
    }

    #[test]
    fn wrong_execution_counter_slot_is_rejected_before_proof_work() {
        let stored = EvmStorageProofWitness {
            slot: stored_batch_hash_slot(7, [9; 32]),
            proof_nodes: alloc::vec::Vec::new(),
        };
        let executed = EvmStorageProofWitness {
            slot: [3; 32],
            proof_nodes: alloc::vec::Vec::new(),
        };
        let preimage = StateCommitmentPreimage {
            next_free_slot: 0,
            block_number: 0,
            last_256_block_hashes_blake: [0; 32],
            last_block_timestamp: 0,
        };
        let verification = L1VerificationData {
            batch_number: 7,
            number_of_layer1_txs: 0,
            priority_operations_hash: [0; 32],
            dependency_roots_rolling_hash: [0; 32],
            l2_to_l1_logs_root_hash: [0; 32],
            commitment: [0; 32],
        };
        assert_eq!(
            authenticate_stored_batch(StoredBatchAuthentication {
                authenticated_l1_state_root: [0; 32],
                settlement_address: [0; 20],
                account_proof_nodes: &[],
                stored_batch_hash_proof: &stored,
                total_batches_executed_proof: &executed,
                stored_batch_hash_mapping_base_slot: [9; 32],
                total_batches_executed_slot: [2; 32],
                native_root: [0; 32],
                state_preimage: &preimage,
                verification: &verification,
            }),
            Err(SettlementError::TotalBatchesExecutedSlotMismatch)
        );
    }

    #[test]
    fn v0208_stored_batch_hash_binds_every_field_and_batch_slot() {
        let preimage = StateCommitmentPreimage {
            next_free_slot: 4,
            block_number: 9,
            last_256_block_hashes_blake: [3; 32],
            last_block_timestamp: 11,
        };
        let data = L1VerificationData {
            batch_number: 7,
            number_of_layer1_txs: 2,
            priority_operations_hash: [4; 32],
            dependency_roots_rolling_hash: [5; 32],
            l2_to_l1_logs_root_hash: [6; 32],
            commitment: [7; 32],
        };
        let root = [8; 32];
        let hash = stored_batch_info_hash(root, &preimage, &data);
        let base = [9; 32];
        assert_ne!(hash, [0; 32]);
        let mut changed = data;
        changed.commitment[0] ^= 1;
        assert_ne!(stored_batch_info_hash(root, &preimage, &changed), hash);
        assert_ne!(
            stored_batch_hash_slot(7, base),
            stored_batch_hash_slot(8, base)
        );
    }

    #[test]
    fn execution_counter_must_cover_the_candidate_batch() {
        let mut executed = [0_u8; 32];
        executed[24..].copy_from_slice(&7_u64.to_be_bytes());
        assert_eq!(require_executed_batch(7, executed), Ok(()));
        assert_eq!(require_executed_batch(6, executed), Ok(()));
        assert_eq!(
            require_executed_batch(8, executed),
            Err(SettlementError::BatchNotExecuted)
        );
    }
}
