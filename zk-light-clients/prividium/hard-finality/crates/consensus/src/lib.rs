// SPDX-License-Identifier: Apache-2.0

#![no_std]

#[cfg(test)]
extern crate alloc;
use prividium_ssz::{
    beacon_block_header_root, compute_domain, signing_root, sync_committee_root, verify_branch,
    SszError,
};
use prividium_types::{
    BeaconBlockHeader, BlsPublicKey, ConsensusTrustState, Hash32, SyncAggregate, SyncCommittee,
};

pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusConstants {
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub sync_committee_size: usize,
    pub genesis_validators_root: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkVersionEntry<'a> {
    pub fork_id: &'a str,
    pub activation_epoch: u64,
    pub fork_version: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateBranchGindices {
    pub finalized_checkpoint_root: u64,
    pub next_sync_committee: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedStateBranches {
    pub finalized_header_root: Hash32,
    pub next_sync_committee_root: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachableCommittee {
    Current(Hash32),
    Next(Hash32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    ZeroSlotsPerEpoch,
    ZeroEpochsPerPeriod,
    ZeroCommitteeSize,
    ArithmeticOverflow,
    EmptyForkSchedule,
    ForkScheduleNotStrictlyIncreasing,
    NoForkAtEpoch(u64),
    UnreachableSignaturePeriod {
        trusted: u64,
        signature: u64,
    },
    NextCommitteeUnknown,
    InvalidTrustState,
    WrongCommitteeSize {
        expected: usize,
        actual: usize,
    },
    WrongBitvectorLength {
        expected: usize,
        actual: usize,
    },
    NonZeroUnusedBits,
    ZeroParticipants,
    InsufficientSyncCommitteeParticipation {
        participants: usize,
        required: usize,
        committee_size: usize,
    },
    SignatureNotAfterAttested,
    AttestedBeforeFinalized,
    FinalizedSlotRegression,
    SameSlotDifferentRoot,
    InvalidPeriodTransition {
        previous: u64,
        new: u64,
    },
    NextCommitteeMismatchInSamePeriod,
    Ssz(SszError),
}

impl From<SszError> for ConsensusError {
    fn from(value: SszError) -> Self {
        Self::Ssz(value)
    }
}

impl ConsensusConstants {
    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.slots_per_epoch == 0 {
            return Err(ConsensusError::ZeroSlotsPerEpoch);
        }
        if self.epochs_per_sync_committee_period == 0 {
            return Err(ConsensusError::ZeroEpochsPerPeriod);
        }
        if self.sync_committee_size == 0 {
            return Err(ConsensusError::ZeroCommitteeSize);
        }
        Ok(())
    }

    pub fn epoch(&self, slot: u64) -> Result<u64, ConsensusError> {
        self.validate()?;
        Ok(slot / self.slots_per_epoch)
    }

    pub fn sync_committee_period(&self, slot: u64) -> Result<u64, ConsensusError> {
        Ok(self.epoch(slot)? / self.epochs_per_sync_committee_period)
    }
}

pub fn validate_fork_schedule(schedule: &[ForkVersionEntry<'_>]) -> Result<(), ConsensusError> {
    if schedule.is_empty() {
        return Err(ConsensusError::EmptyForkSchedule);
    }
    for pair in schedule.windows(2) {
        if pair[0].activation_epoch >= pair[1].activation_epoch {
            return Err(ConsensusError::ForkScheduleNotStrictlyIncreasing);
        }
    }
    Ok(())
}

pub fn fork_at_epoch<'a>(
    schedule: &'a [ForkVersionEntry<'a>],
    epoch: u64,
) -> Result<ForkVersionEntry<'a>, ConsensusError> {
    validate_fork_schedule(schedule)?;
    schedule
        .iter()
        .rev()
        .find(|entry| entry.activation_epoch <= epoch)
        .copied()
        .ok_or(ConsensusError::NoForkAtEpoch(epoch))
}

pub fn signature_fork<'a>(
    constants: &ConsensusConstants,
    schedule: &'a [ForkVersionEntry<'a>],
    signature_slot: u64,
) -> Result<ForkVersionEntry<'a>, ConsensusError> {
    let fork_version_slot = signature_slot.max(1) - 1;
    fork_at_epoch(schedule, constants.epoch(fork_version_slot)?)
}

pub fn sync_committee_signing_root(
    constants: &ConsensusConstants,
    schedule: &[ForkVersionEntry<'_>],
    signature_slot: u64,
    attested_header: &BeaconBlockHeader,
) -> Result<Hash32, ConsensusError> {
    sync_committee_signing_root_from_object_root(
        constants,
        schedule,
        signature_slot,
        beacon_block_header_root(attested_header)?,
    )
}

pub fn sync_committee_signing_root_from_object_root(
    constants: &ConsensusConstants,
    schedule: &[ForkVersionEntry<'_>],
    signature_slot: u64,
    attested_header_root: Hash32,
) -> Result<Hash32, ConsensusError> {
    let fork = signature_fork(constants, schedule, signature_slot)?;
    signing_root_for_fork(constants, fork, attested_header_root)
}

/// Signing-root variant for a compile-time-validated profile schedule.
///
/// Source profiles reject empty or non-increasing schedules before generating
/// guest constants, so circuit callers can avoid repeating that validation.
pub fn sync_committee_signing_root_from_validated_profile(
    constants: &ConsensusConstants,
    schedule: &[ForkVersionEntry<'_>],
    signature_slot: u64,
    attested_header_root: Hash32,
) -> Result<Hash32, ConsensusError> {
    let fork_version_slot = signature_slot.max(1) - 1;
    let epoch = fork_version_slot / constants.slots_per_epoch;
    let fork = schedule
        .iter()
        .rev()
        .find(|entry| entry.activation_epoch <= epoch)
        .copied()
        .ok_or(ConsensusError::NoForkAtEpoch(epoch))?;
    signing_root_for_fork(constants, fork, attested_header_root)
}

fn signing_root_for_fork(
    constants: &ConsensusConstants,
    fork: ForkVersionEntry<'_>,
    attested_header_root: Hash32,
) -> Result<Hash32, ConsensusError> {
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork.fork_version,
        constants.genesis_validators_root,
    )?;
    Ok(signing_root(attested_header_root, domain)?)
}

pub fn reachable_committee(
    constants: &ConsensusConstants,
    trust: &ConsensusTrustState,
    signature_slot: u64,
) -> Result<ReachableCommittee, ConsensusError> {
    constants.validate()?;
    trust
        .validate()
        .map_err(|_| ConsensusError::InvalidTrustState)?;
    reachable_committee_from_validated_trust(constants, trust, signature_slot)
}

/// Committee lookup after the caller has validated both the trust-state
/// representation and its compile-time profile constants.
pub fn reachable_committee_from_validated_trust(
    constants: &ConsensusConstants,
    trust: &ConsensusTrustState,
    signature_slot: u64,
) -> Result<ReachableCommittee, ConsensusError> {
    let slots_per_period = constants
        .slots_per_epoch
        .checked_mul(constants.epochs_per_sync_committee_period)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    let trusted_period = trust.finalized_beacon_slot / slots_per_period;
    let signature_period = signature_slot / slots_per_period;
    if signature_period == trusted_period {
        return Ok(ReachableCommittee::Current(
            trust.current_sync_committee_root,
        ));
    }
    let next_period = trusted_period
        .checked_add(1)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if signature_period == next_period {
        if !trust.next_sync_committee_known {
            return Err(ConsensusError::NextCommitteeUnknown);
        }
        return Ok(ReachableCommittee::Next(trust.next_sync_committee_root));
    }
    Err(ConsensusError::UnreachableSignaturePeriod {
        trusted: trusted_period,
        signature: signature_period,
    })
}

/// Iterates over participating committee keys after the caller has validated
/// the committee size and aggregate bitvector.
pub fn participating_pubkeys<'a>(
    committee: &'a SyncCommittee,
    aggregate: &'a SyncAggregate,
) -> impl Iterator<Item = (usize, &'a BlsPublicKey)> + 'a {
    committee
        .pubkeys
        .iter()
        .enumerate()
        .filter(move |(index, _)| {
            aggregate.sync_committee_bits[index / 8] & (1_u8 << (index % 8)) != 0
        })
}

/// Validates a sync-committee bitvector and returns its participant count
/// without allocating a vector of public-key references.
pub fn validate_participation_and_count(
    aggregate: &SyncAggregate,
    expected_size: usize,
) -> Result<usize, ConsensusError> {
    if expected_size == 0 {
        return Err(ConsensusError::ZeroCommitteeSize);
    }
    let expected_bytes = expected_size
        .checked_add(7)
        .ok_or(ConsensusError::ArithmeticOverflow)?
        / 8;
    if aggregate.sync_committee_bits.len() != expected_bytes {
        return Err(ConsensusError::WrongBitvectorLength {
            expected: expected_bytes,
            actual: aggregate.sync_committee_bits.len(),
        });
    }
    let used_bits = expected_size % 8;
    if used_bits != 0 {
        let forbidden_mask = !((1_u8 << used_bits) - 1);
        if aggregate.sync_committee_bits[expected_bytes - 1] & forbidden_mask != 0 {
            return Err(ConsensusError::NonZeroUnusedBits);
        }
    }

    let participant_count = aggregate
        .sync_committee_bits
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    if participant_count == 0 {
        return Err(ConsensusError::ZeroParticipants);
    }
    Ok(participant_count)
}

/// Requires the sync-committee participation needed to authenticate an update.
/// The Ethereum light-client supermajority rule is `participants * 3 >= size * 2`.
pub fn require_sync_committee_supermajority(
    participant_count: usize,
    committee_size: usize,
) -> Result<(), ConsensusError> {
    if committee_size == 0 {
        return Err(ConsensusError::ZeroCommitteeSize);
    }
    if participant_count > committee_size {
        return Err(ConsensusError::WrongCommitteeSize {
            expected: committee_size,
            actual: participant_count,
        });
    }
    let required = committee_size
        .checked_mul(2)
        .and_then(|value| value.checked_add(2))
        .ok_or(ConsensusError::ArithmeticOverflow)?
        / 3;
    if participant_count < required {
        return Err(ConsensusError::InsufficientSyncCommitteeParticipation {
            participants: participant_count,
            required,
            committee_size,
        });
    }
    Ok(())
}

pub fn validate_update_slots(
    previous: &ConsensusTrustState,
    signature_slot: u64,
    attested_slot: u64,
    finalized_slot: u64,
    finalized_root: Hash32,
) -> Result<(), ConsensusError> {
    if signature_slot <= attested_slot {
        return Err(ConsensusError::SignatureNotAfterAttested);
    }
    if attested_slot < finalized_slot {
        return Err(ConsensusError::AttestedBeforeFinalized);
    }
    if finalized_slot < previous.finalized_beacon_slot {
        return Err(ConsensusError::FinalizedSlotRegression);
    }
    if finalized_slot == previous.finalized_beacon_slot
        && finalized_root != previous.finalized_beacon_header_root
    {
        return Err(ConsensusError::SameSlotDifferentRoot);
    }
    Ok(())
}

/// Rejects an attested header that predates or conflicts with the finalized
/// checkpoint already stored by the light client.
pub fn validate_attested_header_against_trust(
    previous: &ConsensusTrustState,
    attested_slot: u64,
    attested_root: Hash32,
) -> Result<(), ConsensusError> {
    if attested_slot < previous.finalized_beacon_slot {
        return Err(ConsensusError::AttestedBeforeFinalized);
    }
    if attested_slot == previous.finalized_beacon_slot
        && attested_root != previous.finalized_beacon_header_root
    {
        return Err(ConsensusError::SameSlotDifferentRoot);
    }
    Ok(())
}

pub fn authenticate_state_branches(
    authenticated_attested_state_root: Hash32,
    finalized_header: &BeaconBlockHeader,
    finality_branch: &[Hash32],
    next_sync_committee: &SyncCommittee,
    next_sync_committee_branch: &[Hash32],
    committee_size: usize,
    gindices: StateBranchGindices,
) -> Result<AuthenticatedStateBranches, ConsensusError> {
    let finalized_header_root = beacon_block_header_root(finalized_header)?;
    authenticate_state_branches_from_finalized_root(
        authenticated_attested_state_root,
        finalized_header_root,
        finality_branch,
        next_sync_committee,
        next_sync_committee_branch,
        committee_size,
        gindices,
    )
}

pub fn authenticate_state_branches_from_finalized_root(
    authenticated_attested_state_root: Hash32,
    finalized_header_root: Hash32,
    finality_branch: &[Hash32],
    next_sync_committee: &SyncCommittee,
    next_sync_committee_branch: &[Hash32],
    committee_size: usize,
    gindices: StateBranchGindices,
) -> Result<AuthenticatedStateBranches, ConsensusError> {
    verify_branch(
        finalized_header_root,
        finality_branch,
        gindices.finalized_checkpoint_root,
        authenticated_attested_state_root,
    )?;
    let next_sync_committee_root = sync_committee_root(next_sync_committee, committee_size)?;
    verify_branch(
        next_sync_committee_root,
        next_sync_committee_branch,
        gindices.next_sync_committee,
        authenticated_attested_state_root,
    )?;
    Ok(AuthenticatedStateBranches {
        finalized_header_root,
        next_sync_committee_root,
    })
}

/// Applies the compact committee rotation implied by an authenticated update.
pub fn apply_trust_transition(
    constants: &ConsensusConstants,
    previous: &ConsensusTrustState,
    new_finalized_slot: u64,
    new_finalized_root: Hash32,
    authenticated_next_committee_root: Hash32,
) -> Result<ConsensusTrustState, ConsensusError> {
    if new_finalized_slot < previous.finalized_beacon_slot {
        return Err(ConsensusError::FinalizedSlotRegression);
    }
    if new_finalized_slot == previous.finalized_beacon_slot
        && new_finalized_root != previous.finalized_beacon_header_root
    {
        return Err(ConsensusError::SameSlotDifferentRoot);
    }
    let previous_period = constants.sync_committee_period(previous.finalized_beacon_slot)?;
    let new_period = constants.sync_committee_period(new_finalized_slot)?;
    let (current, next) = if !previous.next_sync_committee_known {
        if new_period != previous_period {
            return Err(ConsensusError::InvalidPeriodTransition {
                previous: previous_period,
                new: new_period,
            });
        }
        (
            previous.current_sync_committee_root,
            authenticated_next_committee_root,
        )
    } else if new_period == previous_period {
        if authenticated_next_committee_root != previous.next_sync_committee_root {
            return Err(ConsensusError::NextCommitteeMismatchInSamePeriod);
        }
        (
            previous.current_sync_committee_root,
            previous.next_sync_committee_root,
        )
    } else if new_period
        == previous_period
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?
    {
        (
            previous.next_sync_committee_root,
            authenticated_next_committee_root,
        )
    } else {
        return Err(ConsensusError::InvalidPeriodTransition {
            previous: previous_period,
            new: new_period,
        });
    };
    Ok(ConsensusTrustState {
        finalized_beacon_slot: new_finalized_slot,
        finalized_beacon_header_root: new_finalized_root,
        current_sync_committee_root: current,
        next_sync_committee_root: next,
        next_sync_committee_known: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn constants() -> ConsensusConstants {
        ConsensusConstants {
            slots_per_epoch: 4,
            epochs_per_sync_committee_period: 2,
            sync_committee_size: 10,
            genesis_validators_root: [9; 32],
        }
    }

    fn trust() -> ConsensusTrustState {
        ConsensusTrustState {
            finalized_beacon_slot: 7,
            finalized_beacon_header_root: [1; 32],
            current_sync_committee_root: [2; 32],
            next_sync_committee_root: [3; 32],
            next_sync_committee_known: true,
        }
    }

    #[test]
    fn epoch_period_and_reachability_boundaries() {
        let config = constants();
        assert_eq!(config.epoch(7), Ok(1));
        assert_eq!(config.sync_committee_period(7), Ok(0));
        assert_eq!(config.sync_committee_period(8), Ok(1));
        assert_eq!(
            reachable_committee(&config, &trust(), 7),
            Ok(ReachableCommittee::Current([2; 32]))
        );
        assert_eq!(
            reachable_committee(&config, &trust(), 8),
            Ok(ReachableCommittee::Next([3; 32]))
        );
        assert_eq!(
            reachable_committee(&config, &trust(), 16),
            Err(ConsensusError::UnreachableSignaturePeriod {
                trusted: 0,
                signature: 2
            })
        );
    }

    #[test]
    fn signature_fork_uses_one_slot_lookback() {
        let schedule = [
            ForkVersionEntry {
                fork_id: "old",
                activation_epoch: 0,
                fork_version: [1, 0, 0, 0],
            },
            ForkVersionEntry {
                fork_id: "new",
                activation_epoch: 2,
                fork_version: [2, 0, 0, 0],
            },
        ];
        assert_eq!(signature_fork(&constants(), &schedule, 8), Ok(schedule[0]));
        assert_eq!(signature_fork(&constants(), &schedule, 9), Ok(schedule[1]));
        assert_eq!(signature_fork(&constants(), &schedule, 0), Ok(schedule[0]));
    }

    #[test]
    fn participant_bits_are_little_endian_within_each_byte() {
        let committee = SyncCommittee {
            pubkeys: (0_u8..10).map(|value| [value; 48].into()).collect(),
            aggregate_pubkey: [0; 48].into(),
        };
        let aggregate = SyncAggregate {
            sync_committee_bits: vec![0b1000_0001, 0b0000_0010],
            sync_committee_signature: [0; 96].into(),
        };
        let selected = participating_pubkeys(&committee, &aggregate);
        assert_eq!(
            selected
                .map(|(_, key)| key.0[0])
                .collect::<alloc::vec::Vec<_>>(),
            vec![0, 7, 9]
        );
    }

    #[test]
    fn participant_selection_rejects_dirty_unused_bits_and_empty_set() {
        let dirty = SyncAggregate {
            sync_committee_bits: vec![0, 0x80],
            sync_committee_signature: [0; 96].into(),
        };
        assert_eq!(
            validate_participation_and_count(&dirty, 10),
            Err(ConsensusError::NonZeroUnusedBits)
        );
        let empty = SyncAggregate {
            sync_committee_bits: vec![0, 0],
            sync_committee_signature: [0; 96].into(),
        };
        assert_eq!(
            validate_participation_and_count(&empty, 10),
            Err(ConsensusError::ZeroParticipants)
        );
    }

    #[test]
    fn sync_committee_supermajority_is_derived_from_committee_size() {
        assert_eq!(require_sync_committee_supermajority(1, 1), Ok(()));
        assert_eq!(
            require_sync_committee_supermajority(0, 1),
            Err(ConsensusError::InsufficientSyncCommitteeParticipation {
                participants: 0,
                required: 1,
                committee_size: 1,
            })
        );
        assert_eq!(
            require_sync_committee_supermajority(21, 32),
            Err(ConsensusError::InsufficientSyncCommitteeParticipation {
                participants: 21,
                required: 22,
                committee_size: 32,
            })
        );
        assert_eq!(require_sync_committee_supermajority(22, 32), Ok(()));
        assert_eq!(
            require_sync_committee_supermajority(341, 512),
            Err(ConsensusError::InsufficientSyncCommitteeParticipation {
                participants: 341,
                required: 342,
                committee_size: 512,
            })
        );
        assert_eq!(require_sync_committee_supermajority(342, 512), Ok(()));
        assert_eq!(
            require_sync_committee_supermajority(2, 1),
            Err(ConsensusError::WrongCommitteeSize {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(
            require_sync_committee_supermajority(usize::MAX, usize::MAX),
            Err(ConsensusError::ArithmeticOverflow)
        );
    }

    #[test]
    fn committee_bits_enforce_the_18_14_split_threshold() {
        for (participant_count, accepted) in [(14, false), (18, false), (21, false), (22, true)] {
            let mut bits = vec![0_u8; 4];
            for index in 0..participant_count {
                bits[index / 8] |= 1_u8 << (index % 8);
            }
            let aggregate = SyncAggregate {
                sync_committee_bits: bits,
                sync_committee_signature: [0; 96].into(),
            };
            let counted = validate_participation_and_count(&aggregate, 32).unwrap_or_default();
            let result = require_sync_committee_supermajority(counted, 32);
            assert_eq!(
                result.is_ok(),
                accepted,
                "unexpected result for {participant_count}/32 participation"
            );
        }
    }

    #[test]
    fn slot_order_and_same_slot_root_are_strict() {
        assert_eq!(validate_update_slots(&trust(), 10, 9, 8, [4; 32]), Ok(()));
        assert_eq!(
            validate_update_slots(&trust(), 9, 9, 8, [4; 32]),
            Err(ConsensusError::SignatureNotAfterAttested)
        );
        assert_eq!(
            validate_update_slots(&trust(), 8, 7, 7, [4; 32]),
            Err(ConsensusError::SameSlotDifferentRoot)
        );
    }

    #[test]
    fn attested_header_cannot_conflict_with_finalized_trust() {
        let previous = trust();
        assert_eq!(
            validate_attested_header_against_trust(
                &previous,
                previous.finalized_beacon_slot - 1,
                previous.finalized_beacon_header_root,
            ),
            Err(ConsensusError::AttestedBeforeFinalized)
        );
        assert_eq!(
            validate_attested_header_against_trust(
                &previous,
                previous.finalized_beacon_slot,
                [0x99; 32],
            ),
            Err(ConsensusError::SameSlotDifferentRoot)
        );
        assert_eq!(
            validate_attested_header_against_trust(
                &previous,
                previous.finalized_beacon_slot,
                previous.finalized_beacon_header_root,
            ),
            Ok(())
        );
        assert_eq!(
            validate_attested_header_against_trust(
                &previous,
                previous.finalized_beacon_slot + 1,
                [0x99; 32],
            ),
            Ok(())
        );
    }

    #[test]
    fn finality_and_next_committee_share_one_authenticated_state_root() {
        let finalized_header = BeaconBlockHeader {
            slot: 2,
            proposer_index: 3,
            parent_root: [4; 32],
            state_root: [5; 32],
            body_root: [6; 32],
        };
        let next_committee = SyncCommittee {
            pubkeys: vec![[7; 48].into(), [8; 48].into()],
            aggregate_pubkey: [9; 48].into(),
        };
        let finalized_root = beacon_block_header_root(&finalized_header).unwrap_or_default();
        let next_root = sync_committee_root(&next_committee, 2).unwrap_or_default();
        let state_root = prividium_crypto::sha256_pair(&finalized_root, &next_root);
        assert_eq!(
            authenticate_state_branches(
                state_root,
                &finalized_header,
                &[next_root],
                &next_committee,
                &[finalized_root],
                2,
                StateBranchGindices {
                    finalized_checkpoint_root: 2,
                    next_sync_committee: 3,
                },
            ),
            Ok(AuthenticatedStateBranches {
                finalized_header_root: finalized_root,
                next_sync_committee_root: next_root,
            })
        );
        assert!(authenticate_state_branches(
            state_root,
            &finalized_header,
            &[[0; 32]],
            &next_committee,
            &[finalized_root],
            2,
            StateBranchGindices {
                finalized_checkpoint_root: 2,
                next_sync_committee: 3,
            },
        )
        .is_err());
    }

    #[test]
    fn trust_transition_rotates_only_at_one_period_boundary() {
        let before = trust();
        let same = apply_trust_transition(&constants(), &before, 7, [1; 32], [3; 32]);
        assert_eq!(same, Ok(before));
        let rotated = apply_trust_transition(&constants(), &before, 8, [4; 32], [5; 32]);
        assert_eq!(
            rotated.map(|state| (
                state.current_sync_committee_root,
                state.next_sync_committee_root
            )),
            Ok(([3; 32], [5; 32]))
        );
        assert!(apply_trust_transition(&constants(), &before, 16, [4; 32], [5; 32]).is_err());
    }
}
