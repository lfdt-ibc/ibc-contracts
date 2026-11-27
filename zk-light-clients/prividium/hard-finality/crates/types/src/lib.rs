// SPDX-License-Identifier: Apache-2.0

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Hash32 = [u8; 32];
pub type Address = [u8; 20];
pub type BlsPublicKey = FixedBytes<48>;
pub type BlsSignature = FixedBytes<96>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(N)?;
        for byte in self.0 {
            tuple.serialize_element(&byte)?;
        }
        tuple.end()
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedBytesVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for FixedBytesVisitor<N> {
            type Value = FixedBytes<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "exactly {N} bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = [0_u8; N];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if sequence.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(N + 1, &self));
                }
                Ok(FixedBytes(bytes))
            }
        }

        deserializer.deserialize_tuple(N, FixedBytesVisitor::<N>)
    }
}

pub const SCHEMA_VERSION_V1: u32 = 1;
pub const PROGRAM_VERSION_V1: u32 = 1;
pub const PACKET_PROGRAM_VERSION_V2: u32 = 2;
pub const SETTLEMENT_PROGRAM_VERSION_V3: u32 = 3;
pub const MAX_MEMBERSHIP_BATCH_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusTrustState {
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_header_root: Hash32,
    pub current_sync_committee_root: Hash32,
    pub next_sync_committee_root: Hash32,
    pub next_sync_committee_known: bool,
}

impl ConsensusTrustState {
    /// Enforces the canonical v1 representation for an unknown next committee.
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.finalized_beacon_slot == 0 {
            return Err(TypeError::ZeroFinalizedBeaconSlot);
        }
        if self.finalized_beacon_header_root == [0_u8; 32] {
            return Err(TypeError::ZeroFinalizedBeaconHeaderRoot);
        }
        if self.current_sync_committee_root == [0_u8; 32] {
            return Err(TypeError::ZeroCurrentSyncCommitteeRoot);
        }
        if !self.next_sync_committee_known && self.next_sync_committee_root != [0_u8; 32] {
            return Err(TypeError::UnknownNextCommitteeHasRoot);
        }
        if self.next_sync_committee_known && self.next_sync_committee_root == [0_u8; 32] {
            return Err(TypeError::KnownNextCommitteeHasZeroRoot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Hash32,
    pub state_root: Hash32,
    pub body_root: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommittee {
    pub pubkeys: Vec<BlsPublicKey>,
    pub aggregate_pubkey: BlsPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAggregate {
    pub sync_committee_bits: Vec<u8>,
    pub sync_committee_signature: BlsSignature,
}

/// The 17-field execution payload header shape recorded by the SPEC's captured
/// Fulu compatibility fixture. Profile fork dispatch remains external and must
/// select this variant explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPayloadHeaderFuluCompatibility {
    pub parent_hash: Hash32,
    pub fee_recipient: Address,
    pub state_root: Hash32,
    pub receipts_root: Hash32,
    pub logs_bloom: FixedBytes<256>,
    pub prev_randao: Hash32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    /// Canonical SSZ uint256 byte order (little endian).
    pub base_fee_per_gas_le: Hash32,
    pub block_hash: Hash32,
    pub transactions_root: Hash32,
    pub withdrawals_root: Hash32,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkExecutionPayloadHeader {
    FuluCompatibilityV1(ExecutionPayloadHeaderFuluCompatibility),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ForkExecutionPayloadHeader,
    pub execution_branch: Vec<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientUpdateWitness {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vec<Hash32>,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<Hash32>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustUpdateWitness {
    pub schema_version: u32,
    pub previous_trust: ConsensusTrustState,
    pub full_signing_sync_committee: SyncCommittee,
    pub update: LightClientUpdateWitness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmStorageProofWitness {
    pub slot: Hash32,
    pub proof_nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCommitmentPreimage {
    pub next_free_slot: u64,
    pub block_number: u64,
    pub last_256_block_hashes_blake: Hash32,
    pub last_block_timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1VerificationData {
    pub batch_number: u64,
    pub number_of_layer1_txs: u64,
    pub priority_operations_hash: Hash32,
    pub dependency_roots_rolling_hash: Hash32,
    pub l2_to_l1_logs_root_hash: Hash32,
    pub commitment: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimisticUpdateWitness {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementWitness {
    pub schema_version: u32,
    pub previous_trust: ConsensusTrustState,
    pub full_signing_sync_committee: SyncCommittee,
    pub optimistic_update: OptimisticUpdateWitness,
    /// Private candidate authenticated through StoredBatchInfo.batchHash.
    pub prividium_native_root: Hash32,
    pub settlement_account_proof: Vec<Vec<u8>>,
    pub stored_batch_hash_proof: EvmStorageProofWitness,
    pub total_batches_executed_proof: EvmStorageProofWitness,
    pub state_commitment_preimage: StateCommitmentPreimage,
    pub l1_verification_data: L1VerificationData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipWitness<P> {
    pub schema_version: u32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: Hash32,
    pub entries: Vec<MembershipEntryWitness>,
    pub proof: P,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEntryWitness {
    pub logical_path: Vec<u8>,
    pub expected_application_value: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipWitness<P> {
    pub schema_version: u32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: Hash32,
    pub logical_path: Vec<u8>,
    pub proof: P,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustUpdatePublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: Hash32,
    pub previous_consensus_trust_digest: Hash32,
    pub last_signature_slot: u64,
    pub new_finalized_beacon_slot: u64,
    pub new_finalized_beacon_header_root: Hash32,
    pub new_current_sync_committee_root: Hash32,
    pub new_next_sync_committee_root: Hash32,
    pub new_next_sync_committee_known: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: Hash32,
    pub previous_consensus_trust_digest: Hash32,
    pub l2_block_number: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: Hash32,
    pub l2_batch_timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: Hash32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: Hash32,
    pub ibc_store: Address,
    pub entry_count: u32,
    pub batch_root: Hash32,
    pub request_digest: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipEntryPublicValues {
    pub path_digest: Hash32,
    pub value_hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: Hash32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: Hash32,
    pub ibc_store: Address,
    pub path_digest: Hash32,
    pub solidity_storage_slot: Hash32,
    pub native_tree_key: Hash32,
    pub absence_profile_id: u32,
    pub request_digest: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeError {
    ZeroFinalizedBeaconSlot,
    ZeroFinalizedBeaconHeaderRoot,
    ZeroCurrentSyncCommitteeRoot,
    UnknownNextCommitteeHasRoot,
    KnownNextCommitteeHasZeroRoot,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn unknown_next_committee_requires_zero_root() {
        let valid = ConsensusTrustState {
            finalized_beacon_slot: 1,
            finalized_beacon_header_root: [1; 32],
            current_sync_committee_root: [2; 32],
            next_sync_committee_root: [0; 32],
            next_sync_committee_known: false,
        };
        assert_eq!(valid.validate(), Ok(()));
        assert_eq!(
            ConsensusTrustState {
                next_sync_committee_root: [3; 32],
                ..valid
            }
            .validate(),
            Err(TypeError::UnknownNextCommitteeHasRoot)
        );
        assert_eq!(
            ConsensusTrustState {
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: true,
                ..valid
            }
            .validate(),
            Err(TypeError::KnownNextCommitteeHasZeroRoot)
        );
        assert_eq!(
            ConsensusTrustState {
                finalized_beacon_slot: 0,
                ..valid
            }
            .validate(),
            Err(TypeError::ZeroFinalizedBeaconSlot)
        );
    }

    #[test]
    fn fixed_protocol_bytes_serde_rejects_short_and_long_sequences() {
        let value = FixedBytes::<48>([7; 48]);
        let encoded = serde_json::to_vec(&value).unwrap_or_default();
        assert_eq!(
            serde_json::from_slice::<FixedBytes<48>>(&encoded).ok(),
            Some(value)
        );
        let short = format!("[{}]", ["7"; 47].join(","));
        let long = format!("[{}]", ["7"; 49].join(","));
        assert!(serde_json::from_str::<FixedBytes<48>>(&short).is_err());
        assert!(serde_json::from_str::<FixedBytes<48>>(&long).is_err());
    }
}
