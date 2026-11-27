// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::vec::Vec;
use prividium_bls::{fast_aggregate_verify_indexed, BlsError};
#[cfg(test)]
use prividium_consensus::sync_committee_signing_root;
use prividium_consensus::{
    apply_trust_transition, authenticate_state_branches_from_finalized_root, participating_pubkeys,
    reachable_committee_from_validated_trust, require_sync_committee_supermajority,
    sync_committee_signing_root_from_validated_profile, validate_attested_header_against_trust,
    validate_participation_and_count, validate_update_slots, ConsensusConstants, ConsensusError,
    ForkVersionEntry, ReachableCommittee, StateBranchGindices,
};
use prividium_ibc_storage::{
    derive_poc_direct_word_location_from_path, verify_native_non_existing_application_absence,
    DirectWordStorageProfile, IbcStorageError,
};
use prividium_profile_constants as profile;
use prividium_public_values::{
    consensus_trust_digest, membership_leaf, membership_request_digest,
    membership_root_from_leaves, non_membership_request_digest,
};
use prividium_settlement::{
    authenticate_execution_payload_state_root, authenticate_stored_batch, StoredBatchAuthentication,
};
use prividium_ssz::sync_committee_root;
use prividium_types::{
    MembershipEntryPublicValues, MembershipPublicValues, MembershipWitness,
    NonMembershipPublicValues, NonMembershipWitness, SettlementPublicValues, SettlementWitness,
    SyncAggregate, SyncCommittee, TrustUpdatePublicValues, TrustUpdateWitness,
    MAX_MEMBERSHIP_BATCH_ENTRIES, PACKET_PROGRAM_VERSION_V2, PROGRAM_VERSION_V1, SCHEMA_VERSION_V1,
    SETTLEMENT_PROGRAM_VERSION_V3,
};
use prividium_zksync_native::NativeProofBatch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramError {
    UnsupportedSchema(u32),
    Consensus(ConsensusError),
    Bls(BlsError),
    SigningCommitteeRootMismatch,
    UnsupportedFork,
    Settlement(prividium_settlement::SettlementError),
    Ibc(IbcStorageError),
    ZeroProofHeight,
    EmptyMembershipBatch,
    TooManyMembershipEntries(usize),
    DuplicatePacketPath,
    NativeMembershipValueMismatch,
}

impl From<ConsensusError> for ProgramError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl From<BlsError> for ProgramError {
    fn from(value: BlsError) -> Self {
        Self::Bls(value)
    }
}
impl From<prividium_settlement::SettlementError> for ProgramError {
    fn from(value: prividium_settlement::SettlementError) -> Self {
        Self::Settlement(value)
    }
}
impl From<IbcStorageError> for ProgramError {
    fn from(value: IbcStorageError) -> Self {
        Self::Ibc(value)
    }
}

fn constants() -> ConsensusConstants {
    ConsensusConstants {
        slots_per_epoch: profile::SLOTS_PER_EPOCH,
        epochs_per_sync_committee_period: profile::EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
        sync_committee_size: profile::SYNC_COMMITTEE_SIZE,
        genesis_validators_root: profile::GENESIS_VALIDATORS_ROOT,
    }
}

fn fork_schedule() -> [ForkVersionEntry<'static>; profile::FORK_SCHEDULE.len()] {
    core::array::from_fn(|index| {
        let entry = profile::FORK_SCHEDULE[index];
        ForkVersionEntry {
            fork_id: entry.0,
            activation_epoch: entry.1,
            fork_version: entry.2,
        }
    })
}

fn gindex(table: &[(&str, u64)], fork_id: &str) -> Result<u64, ProgramError> {
    table
        .iter()
        .find(|entry| entry.0 == fork_id)
        .map(|entry| entry.1)
        .ok_or(ProgramError::UnsupportedFork)
}

fn fork_id_at_slot(slot: u64) -> Result<&'static str, ProgramError> {
    let constants = constants();
    let epoch = constants.epoch(slot)?;
    let mut selected = None;
    for entry in profile::FORK_SCHEDULE {
        if entry.1 > epoch {
            break;
        }
        selected = Some(entry.0);
    }
    selected.ok_or(ProgramError::UnsupportedFork)
}

fn authenticate_signature(
    previous: &prividium_types::ConsensusTrustState,
    committee: &SyncCommittee,
    aggregate: &SyncAggregate,
    signature_slot: u64,
    attested_header_root: [u8; 32],
) -> Result<(), ProgramError> {
    let constants = constants();
    constants.validate()?;
    let expected =
        match reachable_committee_from_validated_trust(&constants, previous, signature_slot)? {
            ReachableCommittee::Current(root) | ReachableCommittee::Next(root) => root,
        };
    let computed = sync_committee_root(committee, profile::SYNC_COMMITTEE_SIZE)
        .map_err(ConsensusError::Ssz)?;
    if computed != expected {
        return Err(ProgramError::SigningCommitteeRootMismatch);
    }
    let participant_count =
        validate_participation_and_count(aggregate, profile::SYNC_COMMITTEE_SIZE)?;
    require_sync_committee_supermajority(participant_count, profile::SYNC_COMMITTEE_SIZE)?;
    let root = sync_committee_signing_root_from_validated_profile(
        &constants,
        &fork_schedule(),
        signature_slot,
        attested_header_root,
    )?;
    let participants = participating_pubkeys(committee, aggregate);
    fast_aggregate_verify_indexed(participants, root, &aggregate.sync_committee_signature)?;
    Ok(())
}

pub fn verify_trust_update(
    witness: &TrustUpdateWitness,
) -> Result<TrustUpdatePublicValues, ProgramError> {
    if witness.schema_version != SCHEMA_VERSION_V1 {
        return Err(ProgramError::UnsupportedSchema(witness.schema_version));
    }
    witness
        .previous_trust
        .validate()
        .map_err(|_| ConsensusError::InvalidTrustState)?;
    let update = &witness.update;
    let finalized_root = prividium_ssz::beacon_block_header_root(&update.finalized_header.beacon)
        .map_err(ConsensusError::Ssz)?;
    validate_update_slots(
        &witness.previous_trust,
        update.signature_slot,
        update.attested_header.beacon.slot,
        update.finalized_header.beacon.slot,
        finalized_root,
    )?;
    authenticate_signature(
        &witness.previous_trust,
        &witness.full_signing_sync_committee,
        &update.sync_aggregate,
        update.signature_slot,
        prividium_ssz::beacon_block_header_root(&update.attested_header.beacon)
            .map_err(ConsensusError::Ssz)?,
    )?;
    let fork_id = fork_id_at_slot(update.attested_header.beacon.slot)?;
    let branches = authenticate_state_branches_from_finalized_root(
        update.attested_header.beacon.state_root,
        finalized_root,
        &update.finality_branch,
        &update.next_sync_committee,
        &update.next_sync_committee_branch,
        profile::SYNC_COMMITTEE_SIZE,
        StateBranchGindices {
            finalized_checkpoint_root: gindex(&profile::FORK_SPECIFIC_FINALITY_GINDICES, fork_id)?,
            next_sync_committee: gindex(&profile::FORK_SPECIFIC_NEXT_COMMITTEE_GINDICES, fork_id)?,
        },
    )?;
    let new_state = apply_trust_transition(
        &constants(),
        &witness.previous_trust,
        update.finalized_header.beacon.slot,
        branches.finalized_header_root,
        branches.next_sync_committee_root,
    )?;
    Ok(TrustUpdatePublicValues {
        schema_version: SCHEMA_VERSION_V1,
        program_version: PROGRAM_VERSION_V1,
        source_profile_id: profile::SOURCE_PROFILE_ID,
        previous_consensus_trust_digest: consensus_trust_digest(&witness.previous_trust),
        last_signature_slot: update.signature_slot,
        new_finalized_beacon_slot: new_state.finalized_beacon_slot,
        new_finalized_beacon_header_root: new_state.finalized_beacon_header_root,
        new_current_sync_committee_root: new_state.current_sync_committee_root,
        new_next_sync_committee_root: new_state.next_sync_committee_root,
        new_next_sync_committee_known: new_state.next_sync_committee_known,
    })
}

pub fn verify_settlement_update(
    witness: &SettlementWitness,
) -> Result<SettlementPublicValues, ProgramError> {
    if witness.schema_version != SCHEMA_VERSION_V1 {
        return Err(ProgramError::UnsupportedSchema(witness.schema_version));
    }
    witness
        .previous_trust
        .validate()
        .map_err(|_| ConsensusError::InvalidTrustState)?;
    let update = &witness.optimistic_update;
    let attested_header_root =
        prividium_ssz::beacon_block_header_root(&update.attested_header.beacon)
            .map_err(ConsensusError::Ssz)?;
    validate_attested_header_against_trust(
        &witness.previous_trust,
        update.attested_header.beacon.slot,
        attested_header_root,
    )?;
    let reuses_trusted_finalized_header = update.attested_header.beacon.slot
        == witness.previous_trust.finalized_beacon_slot
        && attested_header_root == witness.previous_trust.finalized_beacon_header_root;
    if !reuses_trusted_finalized_header {
        if update.signature_slot <= update.attested_header.beacon.slot {
            return Err(ConsensusError::SignatureNotAfterAttested.into());
        }
        authenticate_signature(
            &witness.previous_trust,
            &witness.full_signing_sync_committee,
            &update.sync_aggregate,
            update.signature_slot,
            attested_header_root,
        )?;
    }
    let fork_id = fork_id_at_slot(update.attested_header.beacon.slot)?;
    let state_root = authenticate_execution_payload_state_root(
        &update.attested_header.execution,
        &update.attested_header.execution_branch,
        gindex(&profile::FORK_SPECIFIC_EXECUTION_GINDICES, fork_id)?,
        update.attested_header.beacon.body_root,
    )?;
    let native_root = authenticate_stored_batch(StoredBatchAuthentication {
        authenticated_l1_state_root: state_root,
        settlement_address: profile::DIAMOND_PROXY_ADDRESS,
        account_proof_nodes: &witness.settlement_account_proof,
        stored_batch_hash_proof: &witness.stored_batch_hash_proof,
        total_batches_executed_proof: &witness.total_batches_executed_proof,
        stored_batch_hash_mapping_base_slot: profile::STORED_BATCH_HASH_MAPPING_BASE_SLOT,
        total_batches_executed_slot: profile::TOTAL_BATCHES_EXECUTED_SLOT,
        native_root: witness.prividium_native_root,
        state_preimage: &witness.state_commitment_preimage,
        verification: &witness.l1_verification_data,
    })?;
    Ok(SettlementPublicValues {
        schema_version: SCHEMA_VERSION_V1,
        program_version: SETTLEMENT_PROGRAM_VERSION_V3,
        source_profile_id: profile::SOURCE_PROFILE_ID,
        previous_consensus_trust_digest: consensus_trust_digest(&witness.previous_trust),
        l2_block_number: witness.state_commitment_preimage.block_number,
        l1_batch_number: witness.l1_verification_data.batch_number,
        prividium_native_root: native_root,
        l2_batch_timestamp: witness.state_commitment_preimage.last_block_timestamp,
    })
}

fn ibc_profile() -> DirectWordStorageProfile {
    DirectWordStorageProfile {
        store_address: profile::IBC_STORE_ADDRESS,
        mapping_base_slot: profile::IBC_MAPPING_BASE_SLOT,
        max_client_id_bytes: profile::MAX_CLIENT_ID_BYTES,
    }
}

pub fn verify_membership(
    witness: &MembershipWitness<NativeProofBatch>,
) -> Result<MembershipPublicValues, ProgramError> {
    if witness.schema_version != SCHEMA_VERSION_V1 {
        return Err(ProgramError::UnsupportedSchema(witness.schema_version));
    }
    if witness.proof_height == 0 {
        return Err(ProgramError::ZeroProofHeight);
    }
    if witness.entries.is_empty() {
        return Err(ProgramError::EmptyMembershipBatch);
    }
    if witness.entries.len() > MAX_MEMBERSHIP_BATCH_ENTRIES {
        return Err(ProgramError::TooManyMembershipEntries(
            witness.entries.len(),
        ));
    }
    let storage = ibc_profile();
    let mut locations = Vec::with_capacity(witness.entries.len());
    for entry in &witness.entries {
        let location = derive_poc_direct_word_location_from_path(&storage, &entry.logical_path)?;
        if locations
            .iter()
            .any(|prior: &prividium_ibc_storage::DerivedStorageLocation| {
                prior.path_digest == location.path_digest
            })
        {
            return Err(ProgramError::DuplicatePacketPath);
        }
        locations.push(location);
    }
    let slots = locations
        .iter()
        .map(|location| location.solidity_storage_slot)
        .collect::<Vec<_>>();
    let verified = witness
        .proof
        .verify_against_root(
            &storage.store_address,
            &slots,
            &witness.prividium_native_root,
        )
        .map_err(IbcStorageError::from)?;
    let mut leaves = Vec::with_capacity(witness.entries.len());
    for ((entry, location), actual) in witness.entries.iter().zip(&locations).zip(&verified.values)
    {
        let actual = actual.ok_or(ProgramError::NativeMembershipValueMismatch)?;
        if actual != entry.expected_application_value {
            return Err(ProgramError::NativeMembershipValueMismatch);
        }
        let index = u32::try_from(leaves.len())
            .map_err(|_| ProgramError::TooManyMembershipEntries(leaves.len()))?;
        leaves.push(membership_leaf(
            index,
            &MembershipEntryPublicValues {
                path_digest: location.path_digest,
                value_hash: prividium_crypto::keccak256(&actual),
            },
        ));
    }
    let entry_count = u32::try_from(leaves.len())
        .map_err(|_| ProgramError::TooManyMembershipEntries(leaves.len()))?;
    let batch_root = membership_root_from_leaves(leaves).ok_or(
        ProgramError::TooManyMembershipEntries(witness.entries.len()),
    )?;
    let mut public = MembershipPublicValues {
        schema_version: SCHEMA_VERSION_V1,
        program_version: PACKET_PROGRAM_VERSION_V2,
        source_profile_id: profile::SOURCE_PROFILE_ID,
        proof_height: witness.proof_height,
        l1_batch_number: witness.l1_batch_number,
        prividium_native_root: witness.prividium_native_root,
        ibc_store: profile::IBC_STORE_ADDRESS,
        entry_count,
        batch_root,
        request_digest: [0; 32],
    };
    public.request_digest = membership_request_digest(&public);
    Ok(public)
}

pub fn verify_non_membership(
    witness: &NonMembershipWitness<NativeProofBatch>,
) -> Result<NonMembershipPublicValues, ProgramError> {
    if witness.schema_version != SCHEMA_VERSION_V1 {
        return Err(ProgramError::UnsupportedSchema(witness.schema_version));
    }
    if witness.proof_height == 0 {
        return Err(ProgramError::ZeroProofHeight);
    }
    let location = verify_native_non_existing_application_absence(
        &ibc_profile(),
        witness.prividium_native_root,
        &witness.logical_path,
        &witness.proof,
    )?;
    let mut public = NonMembershipPublicValues {
        schema_version: SCHEMA_VERSION_V1,
        program_version: PACKET_PROGRAM_VERSION_V2,
        source_profile_id: profile::SOURCE_PROFILE_ID,
        proof_height: witness.proof_height,
        l1_batch_number: witness.l1_batch_number,
        prividium_native_root: witness.prividium_native_root,
        ibc_store: profile::IBC_STORE_ADDRESS,
        path_digest: location.path_digest,
        solidity_storage_slot: location.solidity_storage_slot,
        native_tree_key: location.native_tree_key,
        absence_profile_id: profile::ABSENCE_PROFILE_ID,
        request_digest: [0; 32],
    };
    public.request_digest = non_membership_request_digest(&public);
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use bls12_381::{
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
        G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
    };
    use prividium_ibc_storage::{canonicalize_poc_terminal_path, PocPathType};
    #[cfg(feature = "sp1-execute-tests")]
    use prividium_public_values::StrictAbiCodec;
    use prividium_types::MembershipEntryWitness;
    use prividium_zksync_native::{
        hash_leaf, reconstruct_root, InnerStorageProof, ProofEntry, ProofEntryWithKey,
        StorageSlotProof, MAX_GUARD_KEY, MIN_GUARD_KEY,
    };
    use sha2::Sha256;

    #[cfg(feature = "sp1-execute-tests")]
    fn execute_guest<T: serde::Serialize>(program: &str, witness: &T, expected: &[u8]) {
        use sp1_sdk::{
            blocking::{Prover, ProverClient},
            SP1Stdin,
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release")
            .join(program);
        let elf = std::fs::read(path).unwrap_or_default();
        assert!(!elf.is_empty(), "build guests with cargo prove build first");
        let mut stdin = SP1Stdin::new();
        stdin.write(witness);
        let result = ProverClient::from_env().execute(elf.into(), stdin).run();
        assert!(result.is_ok(), "SP1 execute failed");
        if let Ok((public, _)) = result {
            assert_eq!(public.as_slice(), expected);
        }
    }

    fn path() -> Vec<u8> {
        canonicalize_poc_terminal_path(b"client-0", PocPathType::PacketCommitment, 7, 128)
            .unwrap_or_default()
    }

    fn execution() -> prividium_types::ForkExecutionPayloadHeader {
        prividium_types::ForkExecutionPayloadHeader::FuluCompatibilityV1(
            prividium_types::ExecutionPayloadHeaderFuluCompatibility {
                parent_hash: [0; 32],
                fee_recipient: [0; 20],
                state_root: [0; 32],
                receipts_root: [0; 32],
                logs_bloom: [0; 256].into(),
                prev_randao: [0; 32],
                block_number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: vec![],
                base_fee_per_gas_le: [0; 32],
                block_hash: [0; 32],
                transactions_root: [0; 32],
                withdrawals_root: [0; 32],
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
        )
    }

    fn execution_with_state(state_root: [u8; 32]) -> prividium_types::ForkExecutionPayloadHeader {
        let prividium_types::ForkExecutionPayloadHeader::FuluCompatibilityV1(mut value) =
            execution();
        value.state_root = state_root;
        value.block_number = 77;
        value.block_hash = [0x77; 32];
        prividium_types::ForkExecutionPayloadHeader::FuluCompatibilityV1(value)
    }

    fn header(
        slot: u64,
        state_root: [u8; 32],
        body_root: [u8; 32],
    ) -> prividium_types::LightClientHeader {
        prividium_types::LightClientHeader {
            beacon: prividium_types::BeaconBlockHeader {
                slot,
                proposer_index: 1,
                parent_root: [2; 32],
                state_root,
                body_root,
            },
            execution: execution(),
            execution_branch: vec![],
        }
    }

    fn contains(node: u64, mut descendant: u64) -> bool {
        while descendant > node {
            descendant /= 2;
        }
        descendant == node
    }

    fn sparse_node(node: u64, leaves: &[(u64, [u8; 32])]) -> [u8; 32] {
        if let Some((_, value)) = leaves.iter().find(|leaf| leaf.0 == node) {
            return *value;
        }
        if !leaves.iter().any(|leaf| contains(node, leaf.0)) {
            return [0; 32];
        }
        prividium_crypto::sha256_pair(
            &sparse_node(node * 2, leaves),
            &sparse_node(node * 2 + 1, leaves),
        )
    }

    fn sparse_branch(gindex: u64, leaves: &[(u64, [u8; 32])]) -> Vec<[u8; 32]> {
        let mut branch = Vec::new();
        let mut node = gindex;
        while node > 1 {
            branch.push(sparse_node(node ^ 1, leaves));
            node /= 2;
        }
        branch
    }

    fn nibbles(bytes: &[u8; 32]) -> Vec<u8> {
        let mut result = Vec::with_capacity(64);
        for byte in bytes {
            result.push(byte >> 4);
            result.push(byte & 0x0f);
        }
        result
    }

    fn usize_be(value: usize) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        bytes[first..].to_vec()
    }

    fn rlp_data(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() == 1 && bytes[0] < 0x80 {
            return bytes.to_vec();
        }
        let mut output = Vec::new();
        if bytes.len() <= 55 {
            output.push(0x80 + u8::try_from(bytes.len()).unwrap_or_default());
        } else {
            let length = usize_be(bytes.len());
            output.push(0xb7 + u8::try_from(length.len()).unwrap_or_default());
            output.extend_from_slice(&length);
        }
        output.extend_from_slice(bytes);
        output
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload_len = items.iter().map(Vec::len).sum::<usize>();
        let mut output = Vec::new();
        if payload_len <= 55 {
            output.push(0xc0 + u8::try_from(payload_len).unwrap_or_default());
        } else {
            let length = usize_be(payload_len);
            output.push(0xf7 + u8::try_from(length.len()).unwrap_or_default());
            output.extend_from_slice(&length);
        }
        for item in items {
            output.extend_from_slice(item);
        }
        output
    }

    fn leaf_node(key: [u8; 32], value: &[u8]) -> Vec<u8> {
        let path = nibbles(&key);
        let mut compact = Vec::with_capacity(33);
        compact.push(0x20);
        for pair in path.chunks_exact(2) {
            compact.push((pair[0] << 4) | pair[1]);
        }
        rlp_list(&[rlp_data(&compact), rlp_data(value)])
    }

    fn compact_path(path: &[u8], leaf: bool) -> Vec<u8> {
        let odd = path.len() % 2 == 1;
        let flag = if leaf { 2_u8 } else { 0 } + u8::from(odd);
        let mut compact = Vec::with_capacity(path.len() / 2 + 1);
        let mut offset = 0;
        if odd {
            compact.push((flag << 4) | path[0]);
            offset = 1;
        } else {
            compact.push(flag << 4);
        }
        for pair in path[offset..].chunks_exact(2) {
            compact.push((pair[0] << 4) | pair[1]);
        }
        compact
    }

    fn trie_child(node: &[u8]) -> Vec<u8> {
        if node.len() < 32 {
            node.to_vec()
        } else {
            rlp_data(&prividium_crypto::keccak256(node))
        }
    }

    fn two_leaf_trie(
        first_key: [u8; 32],
        first_value: &[u8],
        second_key: [u8; 32],
        second_value: &[u8],
    ) -> ([u8; 32], Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let first_path = nibbles(&first_key);
        let second_path = nibbles(&second_key);
        let common = first_path
            .iter()
            .zip(&second_path)
            .take_while(|(left, right)| left == right)
            .count();
        assert!(common < 64);
        let first_leaf = rlp_list(&[
            rlp_data(&compact_path(&first_path[common + 1..], true)),
            rlp_data(first_value),
        ]);
        let second_leaf = rlp_list(&[
            rlp_data(&compact_path(&second_path[common + 1..], true)),
            rlp_data(second_value),
        ]);
        let mut branch = vec![rlp_data(&[]); 17];
        branch[usize::from(first_path[common])] = trie_child(&first_leaf);
        branch[usize::from(second_path[common])] = trie_child(&second_leaf);
        let branch = rlp_list(&branch);
        if common == 0 {
            let root = prividium_crypto::keccak256(&branch);
            return (
                root,
                vec![branch.clone(), first_leaf],
                vec![branch, second_leaf],
            );
        }
        let extension = rlp_list(&[
            rlp_data(&compact_path(&first_path[..common], false)),
            trie_child(&branch),
        ]);
        let root = prividium_crypto::keccak256(&extension);
        (
            root,
            vec![extension.clone(), branch.clone(), first_leaf],
            vec![extension, branch, second_leaf],
        )
    }

    fn signed_committee_and_aggregate(
        previous_header: &prividium_types::BeaconBlockHeader,
        signature_slot: u64,
    ) -> (SyncCommittee, SyncAggregate) {
        let secret = Scalar::from(42_u64);
        let participant_count = u64::try_from(profile::SYNC_COMMITTEE_SIZE).unwrap_or_default();
        let aggregate_secret = secret * Scalar::from(participant_count);
        let public_key = G1Affine::from(G1Projective::generator() * secret).to_compressed();
        let committee = SyncCommittee {
            pubkeys: vec![public_key.into(); profile::SYNC_COMMITTEE_SIZE],
            aggregate_pubkey: G1Affine::from(G1Projective::generator() * aggregate_secret)
                .to_compressed()
                .into(),
        };
        let signing_root = sync_committee_signing_root(
            &constants(),
            &fork_schedule(),
            signature_slot,
            previous_header,
        )
        .unwrap_or_default();
        let point = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
            [signing_root],
            prividium_bls::ETHEREUM_BLS_DST,
        );
        let signature = G2Affine::from(point * aggregate_secret).to_compressed();
        let mut bits = vec![0xff; profile::SYNC_COMMITTEE_BITS_BYTES];
        let used_bits = profile::SYNC_COMMITTEE_SIZE % 8;
        if used_bits != 0 {
            bits[profile::SYNC_COMMITTEE_BITS_BYTES - 1] = (1_u8 << used_bits) - 1;
        }
        (
            committee,
            SyncAggregate {
                sync_committee_bits: bits,
                sync_committee_signature: signature.into(),
            },
        )
    }

    fn existing(value: [u8; 32]) -> Result<(NativeProofBatch, [u8; 32]), IbcStorageError> {
        let location = prividium_ibc_storage::derive_poc_direct_word_location_from_path(
            &ibc_profile(),
            &path(),
        )?;
        let entry = ProofEntry {
            index: 0,
            value,
            next_index: 1,
            siblings: vec![],
        };
        let root =
            reconstruct_root(&location.native_tree_key, &value, 1, 0, &[]).unwrap_or_default();
        Ok((
            NativeProofBatch {
                address: profile::IBC_STORE_ADDRESS,
                storage_proofs: vec![StorageSlotProof {
                    key: location.solidity_storage_slot,
                    proof: InnerStorageProof::Existing(entry),
                }],
            },
            root,
        ))
    }

    fn absent() -> Result<(NativeProofBatch, [u8; 32]), IbcStorageError> {
        let location = prividium_ibc_storage::derive_poc_direct_word_location_from_path(
            &ibc_profile(),
            &path(),
        )?;
        assert!(
            MIN_GUARD_KEY < location.native_tree_key && location.native_tree_key < MAX_GUARD_KEY
        );
        let left_value = [0; 32];
        let right_value = [0; 32];
        let left_hash = hash_leaf(&MIN_GUARD_KEY, &left_value, 1);
        let right_hash = hash_leaf(&MAX_GUARD_KEY, &right_value, 1);
        let left = ProofEntry {
            index: 0,
            value: left_value,
            next_index: 1,
            siblings: vec![right_hash],
        };
        let right = ProofEntry {
            index: 1,
            value: right_value,
            next_index: 1,
            siblings: vec![left_hash],
        };
        let root =
            reconstruct_root(&MIN_GUARD_KEY, &left_value, 1, 0, &[right_hash]).unwrap_or_default();
        Ok((
            NativeProofBatch {
                address: profile::IBC_STORE_ADDRESS,
                storage_proofs: vec![StorageSlotProof {
                    key: location.solidity_storage_slot,
                    proof: InnerStorageProof::NonExisting {
                        left_neighbor: ProofEntryWithKey {
                            entry: left,
                            leaf_key: MIN_GUARD_KEY,
                        },
                        right_neighbor: ProofEntryWithKey {
                            entry: right,
                            leaf_key: MAX_GUARD_KEY,
                        },
                    },
                }],
            },
            root,
        ))
    }

    #[test]
    fn membership_binds_path_value_root_and_profile() -> Result<(), ProgramError> {
        let value = [0x42; 32];
        let (proof, root) = existing(value)?;
        let witness = MembershipWitness {
            schema_version: 1,
            proof_height: 8,
            l1_batch_number: 9,
            prividium_native_root: root,
            entries: vec![MembershipEntryWitness {
                logical_path: path(),
                expected_application_value: value,
            }],
            proof,
        };
        let public = verify_membership(&witness)?;
        assert_eq!(public.source_profile_id, profile::SOURCE_PROFILE_ID);
        assert_eq!(public.request_digest, membership_request_digest(&public));
        #[cfg(feature = "sp1-execute-tests")]
        execute_guest(
            "prividium-membership-program",
            &witness,
            &public.abi_encode(),
        );
        let mut wrong = witness;
        wrong.entries[0].logical_path[0] ^= 1;
        assert!(verify_membership(&wrong).is_err());
        Ok(())
    }

    #[test]
    fn membership_rejects_empty_oversized_and_duplicate_batches() -> Result<(), ProgramError> {
        let value = [0x42; 32];
        let (proof, root) = existing(value)?;
        let base = MembershipWitness {
            schema_version: 1,
            proof_height: 8,
            l1_batch_number: 9,
            prividium_native_root: root,
            entries: vec![MembershipEntryWitness {
                logical_path: path(),
                expected_application_value: value,
            }],
            proof,
        };

        let mut empty = base.clone();
        empty.entries.clear();
        assert_eq!(
            verify_membership(&empty),
            Err(ProgramError::EmptyMembershipBatch)
        );

        let mut oversized = base.clone();
        oversized.entries = vec![base.entries[0].clone(); MAX_MEMBERSHIP_BATCH_ENTRIES + 1];
        assert_eq!(
            verify_membership(&oversized),
            Err(ProgramError::TooManyMembershipEntries(
                MAX_MEMBERSHIP_BATCH_ENTRIES + 1
            ))
        );

        let mut duplicate = base;
        duplicate.entries.push(duplicate.entries[0].clone());
        assert_eq!(
            verify_membership(&duplicate),
            Err(ProgramError::DuplicatePacketPath)
        );
        Ok(())
    }

    #[test]
    fn non_membership_requires_native_nonexisting_and_rejects_existing_zero(
    ) -> Result<(), ProgramError> {
        let (proof, root) = absent()?;
        let witness = NonMembershipWitness {
            schema_version: 1,
            proof_height: 8,
            l1_batch_number: 9,
            prividium_native_root: root,
            logical_path: path(),
            proof,
        };
        let public = verify_non_membership(&witness)?;
        assert_eq!(public.absence_profile_id, profile::ABSENCE_PROFILE_ID);
        #[cfg(feature = "sp1-execute-tests")]
        execute_guest(
            "prividium-non-membership-program",
            &witness,
            &public.abi_encode(),
        );
        let (zero_proof, zero_root) = existing([0; 32])?;
        let zero = NonMembershipWitness {
            prividium_native_root: zero_root,
            proof: zero_proof,
            ..witness
        };
        assert!(matches!(
            verify_non_membership(&zero),
            Err(ProgramError::Ibc(IbcStorageError::NativeProof(
                prividium_zksync_native::ProofError::ExpectedNativeAbsence
            )))
        ));
        Ok(())
    }

    #[test]
    fn full_trust_update_authenticates_bls_both_branches_and_transition() -> Result<(), ProgramError>
    {
        let next_committee = {
            let secret = Scalar::from(7_u64);
            let key = G1Affine::from(G1Projective::generator() * secret).to_compressed();
            SyncCommittee {
                pubkeys: vec![key.into(); profile::SYNC_COMMITTEE_SIZE],
                aggregate_pubkey: key.into(),
            }
        };
        let finalized = header(2, [8; 32], [9; 32]);
        let finalized_root = prividium_ssz::beacon_block_header_root(&finalized.beacon)
            .map_err(ConsensusError::Ssz)?;
        let next_root =
            prividium_ssz::sync_committee_root(&next_committee, profile::SYNC_COMMITTEE_SIZE)
                .map_err(ConsensusError::Ssz)?;
        let leaves = [(105, finalized_root), (55, next_root)];
        let state_root = sparse_node(1, &leaves);
        let attested = header(3, state_root, [10; 32]);
        let (signing_committee, aggregate) = signed_committee_and_aggregate(&attested.beacon, 4);
        let signing_root =
            prividium_ssz::sync_committee_root(&signing_committee, profile::SYNC_COMMITTEE_SIZE)
                .map_err(ConsensusError::Ssz)?;
        let previous = prividium_types::ConsensusTrustState {
            finalized_beacon_slot: 1,
            finalized_beacon_header_root: [11; 32],
            current_sync_committee_root: signing_root,
            next_sync_committee_root: next_root,
            next_sync_committee_known: true,
        };
        let witness = TrustUpdateWitness {
            schema_version: 1,
            previous_trust: previous,
            full_signing_sync_committee: signing_committee,
            update: prividium_types::LightClientUpdateWitness {
                attested_header: attested,
                finalized_header: finalized,
                finality_branch: sparse_branch(105, &leaves),
                next_sync_committee: next_committee,
                next_sync_committee_branch: sparse_branch(55, &leaves),
                sync_aggregate: aggregate,
                signature_slot: 4,
            },
        };
        let public = verify_trust_update(&witness)?;
        assert_eq!(public.new_finalized_beacon_slot, 2);
        #[cfg(feature = "sp1-execute-tests")]
        execute_guest(
            "prividium-trust-update-program",
            &witness,
            &public.abi_encode(),
        );
        let mut wrong_signature = witness;
        wrong_signature
            .update
            .sync_aggregate
            .sync_committee_signature
            .0[0] ^= 1;
        assert!(verify_trust_update(&wrong_signature).is_err());
        Ok(())
    }

    #[test]
    fn full_settlement_authenticates_beacon_execution_mpt_stored_hash_and_execution_counter(
    ) -> Result<(), ProgramError> {
        let native_root = [0x44; 32];
        let state_preimage = prividium_types::StateCommitmentPreimage {
            next_free_slot: 12,
            block_number: 99,
            last_256_block_hashes_blake: [0x55; 32],
            last_block_timestamp: 1_700_000_123,
        };
        let l1_data = prividium_types::L1VerificationData {
            batch_number: 4,
            number_of_layer1_txs: 2,
            priority_operations_hash: [0x61; 32],
            dependency_roots_rolling_hash: [0x62; 32],
            l2_to_l1_logs_root_hash: [0x63; 32],
            commitment: [0x64; 32],
        };
        let stored_hash =
            prividium_settlement::stored_batch_info_hash(native_root, &state_preimage, &l1_data);
        let storage_slot = prividium_settlement::stored_batch_hash_slot(
            4,
            profile::STORED_BATCH_HASH_MAPPING_BASE_SLOT,
        );
        let storage_key = prividium_ethereum_mpt::storage_trie_key(&storage_slot);
        let executed_key =
            prividium_ethereum_mpt::storage_trie_key(&profile::TOTAL_BATCHES_EXECUTED_SLOT);
        let (storage_root, stored_hash_proof, executed_proof) = two_leaf_trie(
            storage_key,
            &rlp_data(&stored_hash),
            executed_key,
            &rlp_data(&[4]),
        );
        let account = rlp_list(&[
            rlp_data(&[]),
            rlp_data(&[]),
            rlp_data(&storage_root),
            rlp_data(&[0x77; 32]),
        ]);
        let account_key = prividium_ethereum_mpt::account_trie_key(&profile::DIAMOND_PROXY_ADDRESS);
        let account_leaf = leaf_node(account_key, &account);
        let l1_state_root = prividium_crypto::keccak256(&account_leaf);
        let execution = execution_with_state(l1_state_root);
        let execution_root = prividium_ssz::execution_payload_header_root(&execution)
            .map_err(ConsensusError::Ssz)?;
        let execution_leaves = [(25, execution_root)];
        let body_root = sparse_node(1, &execution_leaves);
        let mut attested = header(2, [0x22; 32], body_root);
        attested.execution = execution;
        attested.execution_branch = sparse_branch(25, &execution_leaves);
        let (committee, aggregate) = signed_committee_and_aggregate(&attested.beacon, 3);
        let committee_root =
            prividium_ssz::sync_committee_root(&committee, profile::SYNC_COMMITTEE_SIZE)
                .map_err(ConsensusError::Ssz)?;
        let previous = prividium_types::ConsensusTrustState {
            finalized_beacon_slot: 1,
            finalized_beacon_header_root: [1; 32],
            current_sync_committee_root: committee_root,
            next_sync_committee_root: [0; 32],
            next_sync_committee_known: false,
        };
        let witness = SettlementWitness {
            schema_version: 1,
            previous_trust: previous,
            full_signing_sync_committee: committee,
            optimistic_update: prividium_types::OptimisticUpdateWitness {
                attested_header: attested,
                sync_aggregate: aggregate,
                signature_slot: 3,
            },
            prividium_native_root: native_root,
            settlement_account_proof: vec![account_leaf],
            stored_batch_hash_proof: prividium_types::EvmStorageProofWitness {
                slot: storage_slot,
                proof_nodes: stored_hash_proof,
            },
            total_batches_executed_proof: prividium_types::EvmStorageProofWitness {
                slot: profile::TOTAL_BATCHES_EXECUTED_SLOT,
                proof_nodes: executed_proof,
            },
            state_commitment_preimage: state_preimage,
            l1_verification_data: l1_data,
        };
        let public = verify_settlement_update(&witness)?;
        assert_eq!(
            (public.l1_batch_number, public.prividium_native_root),
            (4, native_root)
        );
        assert_eq!(public.program_version, SETTLEMENT_PROGRAM_VERSION_V3);
        assert_eq!(public.l2_block_number, state_preimage.block_number);
        assert_eq!(
            public.l2_batch_timestamp,
            state_preimage.last_block_timestamp
        );

        let mut older_than_finalized = witness.clone();
        older_than_finalized.previous_trust.finalized_beacon_slot = older_than_finalized
            .optimistic_update
            .attested_header
            .beacon
            .slot
            + 1;
        assert_eq!(
            verify_settlement_update(&older_than_finalized),
            Err(ProgramError::Consensus(
                ConsensusError::AttestedBeforeFinalized
            ))
        );

        let mut conflicts_with_finalized = witness.clone();
        conflicts_with_finalized
            .previous_trust
            .finalized_beacon_slot = conflicts_with_finalized
            .optimistic_update
            .attested_header
            .beacon
            .slot;
        conflicts_with_finalized
            .previous_trust
            .finalized_beacon_header_root = [0x99; 32];
        assert_eq!(
            verify_settlement_update(&conflicts_with_finalized),
            Err(ProgramError::Consensus(
                ConsensusError::SameSlotDifferentRoot
            ))
        );

        let mut wrong_timestamp = witness.clone();
        wrong_timestamp
            .state_commitment_preimage
            .last_block_timestamp += 1;
        assert!(verify_settlement_update(&wrong_timestamp).is_err());

        let mut finalized = witness.clone();
        finalized.previous_trust.finalized_beacon_slot =
            finalized.optimistic_update.attested_header.beacon.slot;
        finalized.previous_trust.finalized_beacon_header_root =
            prividium_ssz::beacon_block_header_root(
                &finalized.optimistic_update.attested_header.beacon,
            )
            .map_err(ConsensusError::Ssz)?;
        finalized.full_signing_sync_committee.pubkeys.clear();
        finalized
            .optimistic_update
            .sync_aggregate
            .sync_committee_signature = [0_u8; 96].into();

        let finalized_public = verify_settlement_update(&finalized)?;
        assert_eq!(
            finalized_public.program_version,
            SETTLEMENT_PROGRAM_VERSION_V3
        );

        let mut wrong_finalized_root = finalized.clone();
        wrong_finalized_root
            .previous_trust
            .finalized_beacon_header_root[0] ^= 1;
        assert!(verify_settlement_update(&wrong_finalized_root).is_err());

        let mut wrong_finalized_slot = finalized.clone();
        wrong_finalized_slot.previous_trust.finalized_beacon_slot = wrong_finalized_slot
            .previous_trust
            .finalized_beacon_slot
            .saturating_sub(1);
        assert!(verify_settlement_update(&wrong_finalized_slot).is_err());

        #[cfg(feature = "sp1-execute-tests")]
        execute_guest(
            "prividium-settlement-update-program",
            &witness,
            &public.abi_encode(),
        );
        let mut wrong = witness;
        wrong.l1_verification_data.commitment[0] ^= 1;
        assert!(verify_settlement_update(&wrong).is_err());
        Ok(())
    }
}
