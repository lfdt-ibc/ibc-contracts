// SPDX-License-Identifier: Apache-2.0

//! This module provides [`verify_misbehaviour`] function to check for misbehaviour

use alloy_primitives::B256;
use ethereum_types::consensus::light_client_header::LightClientUpdate;
use tree_hash::TreeHash;

use crate::{
    client_state::ClientState,
    consensus_state::{ConsensusState, TrustedConsensusState},
    error::EthereumIBCError,
    header::ActiveSyncCommittee,
    sync_protocol_helpers::{finalized_root_gindex_at_slot, normalize_merkle_branch},
    verify::{validate_light_client_update, BlsVerify},
};

/// Verifies if a consensus misbehaviour is valid by checking if the two light client updates are
/// valid and finalize conflicting headers.
///
/// The finalized headers conflict if their roots differ and they are either for the same slot or
/// for the same finalized checkpoint epoch. The attested headers are not compared, since the
/// client only trusts finalized headers.
///
/// * `client_state`: The current client state.
/// * `consensus_state`: The current consensus state (previously verified and stored)
/// * `full_sync_committee`: The full sync committee data. (untrusted)
/// * `update_1`: The first light client update.
/// * `update_2`: The second light client update.
/// * `current_timestamp`: The current timestamp, used to compute the current slot.
/// * `bls_verifier`: BLS verification implementation.
///
/// # Errors
/// Returns an error if the misbehaviour cannot be verified.
#[allow(clippy::module_name_repetitions, clippy::needless_pass_by_value)]
pub fn verify_misbehaviour<V: BlsVerify>(
    client_state: &ClientState,
    consensus_state: &ConsensusState,
    full_sync_committee: &ActiveSyncCommittee,
    update_1: &LightClientUpdate,
    update_2: &LightClientUpdate,
    current_timestamp: u64,
    bls_verifier: V,
) -> Result<(), EthereumIBCError> {
    let trusted_consensus_state = TrustedConsensusState::new(
        client_state,
        consensus_state.clone(),
        full_sync_committee.clone(),
        &bls_verifier,
    )?;

    // Both updates must meet the same participation threshold as a client update
    ensure!(
        update_1.sync_aggregate.validate_signature_supermajority()
            && update_2.sync_aggregate.validate_signature_supermajority(),
        EthereumIBCError::NotEnoughSignatures
    );

    let (finalized_1, finalized_2) = (
        update_1.finalized_header.beacon(),
        update_2.finalized_header.beacon(),
    );
    let finalized_root = finalized_1.tree_hash_root();
    ensure!(
        finalized_root != finalized_2.tree_hash_root(),
        EthereumIBCError::MisbehaviourFinalizedRootsMatch(finalized_root)
    );

    // Two different finalized headers are only known to conflict if they are for the same slot or
    // the same finalized checkpoint. Otherwise, they may be on the same chain.
    ensure!(
        finalized_1.slot == finalized_2.slot
            || finalized_checkpoint_epoch(client_state, update_1)?
                == finalized_checkpoint_epoch(client_state, update_2)?,
        EthereumIBCError::MisbehaviourFinalizedHeadersNotConflicting {
            slot_1: finalized_1.slot,
            slot_2: finalized_2.slot,
        }
    );

    let current_slot = client_state
        .compute_slot_at_timestamp(current_timestamp)
        .ok_or(EthereumIBCError::FailedToComputeSlotAtTimestamp {
            timestamp: current_timestamp,
            genesis: client_state.genesis_time,
            seconds_per_slot: client_state.seconds_per_slot,
            genesis_slot: client_state.genesis_slot,
        })?;

    // This also proves the finalized headers and their checkpoint epochs, which were compared above
    validate_light_client_update::<V>(
        client_state,
        &trusted_consensus_state,
        update_1,
        current_slot,
        &bls_verifier,
    )?;

    validate_light_client_update::<V>(
        client_state,
        &trusted_consensus_state,
        update_2,
        current_slot,
        &bls_verifier,
    )?;

    Ok(())
}

/// Returns the tree hash root of the epoch of the finalized checkpoint that the update proves.
///
/// The finality branch proves the root of the finalized checkpoint, whose only sibling in the
/// checkpoint is the epoch. This makes the epoch the first node of the branch.
fn finalized_checkpoint_epoch(
    client_state: &ClientState,
    update: &LightClientUpdate,
) -> Result<B256, EthereumIBCError> {
    let gindex = finalized_root_gindex_at_slot(client_state, update.attested_header.beacon().slot)?;
    Ok(normalize_merkle_branch(&update.finality_branch, gindex)?[0])
}

#[cfg(test)]
mod test {
    use ethereum_types::consensus::{
        bls::{BlsPublicKey, BlsSignature},
        light_client_header::{BeaconBlockHeader, LightClientHeader},
        merkle::floorlog2,
    };
    use ibc_proto_eureka::ibc::lightclients::wasm::v1::ClientMessage;
    use prost::Message;
    use sha2::{Digest, Sha256};

    use crate::{
        header::Header,
        sync_protocol_helpers::get_subtree_index,
        test_utils::{
            bls_verifier::{aggreagate, BlsError},
            fixtures::{self, InitialState, RelayerMessages, StepsFixture},
        },
    };

    use super::*;

    /// Accepts any signature, since the tests cannot sign the conflicting updates they build.
    struct AcceptAllBlsVerifier;

    impl BlsVerify for AcceptAllBlsVerifier {
        type Error = BlsError;

        fn fast_aggregate_verify(
            &self,
            _: &[BlsPublicKey],
            _: B256,
            _: BlsSignature,
        ) -> Result<(), BlsError> {
            Ok(())
        }

        fn aggregate(&self, public_keys: &[BlsPublicKey]) -> Result<BlsPublicKey, BlsError> {
            aggreagate(public_keys)
        }
    }

    fn setup() -> (InitialState, Header) {
        let fixture: StepsFixture =
            fixtures::load("Test_ICS20TransferERC20TokenfromEthereumToCosmosAndBack");
        let relayer_messages: RelayerMessages = fixture.get_data_at_step(1);
        let (update_client_msgs, _, _, _) = relayer_messages.get_sdk_msgs();
        let client_msg = ClientMessage::decode(
            update_client_msgs[0]
                .client_message
                .as_ref()
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();

        (
            fixture.get_data_at_step(0),
            serde_json::from_slice(&client_msg.data).unwrap(),
        )
    }

    fn beacon_mut(header: &mut LightClientHeader) -> &mut BeaconBlockHeader {
        match header {
            LightClientHeader::Gloas(header) => &mut header.beacon,
            LightClientHeader::Fulu(header) => &mut header.beacon,
        }
    }

    /// Sets the attested state root to the one that the finality branch gives for the finalized
    /// header, so that a modified update is valid again.
    fn reseal(client_state: &ClientState, update: &mut LightClientUpdate) {
        let gindex =
            finalized_root_gindex_at_slot(client_state, update.attested_header.beacon().slot)
                .unwrap();
        let index = get_subtree_index(gindex);
        assert_eq!(update.finality_branch.len(), floorlog2(gindex));

        let mut root = update.finalized_header.beacon().tree_hash_root();
        for (i, node) in update.finality_branch.iter().enumerate() {
            let mut hasher = Sha256::new();
            if (index >> i) & 1 == 1 {
                hasher.update(node);
                hasher.update(root);
            } else {
                hasher.update(root);
                hasher.update(node);
            }
            root = B256::from_slice(&hasher.finalize());
        }
        beacon_mut(&mut update.attested_header).state_root = root;
    }

    fn verify(
        state: &InitialState,
        header: &Header,
        update_2: &LightClientUpdate,
    ) -> Result<(), EthereumIBCError> {
        verify_misbehaviour(
            &state.client_state,
            &state.consensus_state,
            &header.active_sync_committee,
            &header.consensus_update,
            update_2,
            state
                .client_state
                .compute_timestamp_at_slot(update_2.signature_slot)
                + 1000,
            AcceptAllBlsVerifier,
        )
    }

    /// Returns the fixture state and header, with a valid update that finalizes a different
    /// header at the same slot.
    fn setup_conflict() -> (InitialState, Header, LightClientUpdate) {
        let (state, header) = setup();
        let mut update_2 = header.consensus_update.clone();
        beacon_mut(&mut update_2.finalized_header).proposer_index += 1;
        // Its branch is for the attested state root that is replaced below
        update_2.next_sync_committee = None;
        update_2.next_sync_committee_branch = None;
        reseal(&state.client_state, &mut update_2);

        (state, header, update_2)
    }

    #[test]
    fn test_conflicting_finalized_headers() {
        let (state, header, update_2) = setup_conflict();

        // The attested headers are for the same slot and execution block
        assert_eq!(
            header.consensus_update.attested_header.block_hash(),
            update_2.attested_header.block_hash()
        );
        verify(&state, &header, &update_2).unwrap();
    }

    #[test]
    fn test_conflicting_finalized_headers_with_different_attested_slots() {
        let (state, header, mut update_2) = setup_conflict();
        beacon_mut(&mut update_2.attested_header).slot += 1;
        update_2.signature_slot += 1;

        verify(&state, &header, &update_2).unwrap();
    }

    #[test]
    fn test_conflicting_finalized_headers_with_different_slots_in_same_epoch() {
        let (state, header, mut update_2) = setup_conflict();
        beacon_mut(&mut update_2.finalized_header).slot -= 1;
        reseal(&state.client_state, &mut update_2);

        verify(&state, &header, &update_2).unwrap();
    }

    #[test]
    fn test_fork_below_finality() {
        let (state, header) = setup();
        let mut update_2 = header.consensus_update.clone();
        beacon_mut(&mut update_2.attested_header).proposer_index += 1;

        let err = verify(&state, &header, &update_2).unwrap_err();
        assert!(matches!(
            err,
            EthereumIBCError::MisbehaviourFinalizedRootsMatch(_)
        ));
    }

    #[test]
    fn test_finalized_headers_for_different_slots_and_epochs() {
        let (state, header, mut update_2) = setup_conflict();
        beacon_mut(&mut update_2.finalized_header).slot -= 1;
        update_2.finality_branch[0].0[0] ^= 1;
        reseal(&state.client_state, &mut update_2);

        let err = verify(&state, &header, &update_2).unwrap_err();
        assert!(matches!(
            err,
            EthereumIBCError::MisbehaviourFinalizedHeadersNotConflicting { .. }
        ));
    }

    #[test]
    fn test_conflicting_finalized_headers_without_supermajority() {
        let (state, header, mut update_2) = setup_conflict();
        // Half of the sync committee, which is above `min_sync_committee_participants`
        let mut bits = update_2.sync_aggregate.sync_committee_bits.to_vec();
        let half = bits.len() / 2;
        bits[..half].fill(0);
        update_2.sync_aggregate.sync_committee_bits = bits.into();
        assert!(update_2
            .sync_aggregate
            .has_sufficient_participants(state.client_state.min_sync_committee_participants));

        let err = verify(&state, &header, &update_2).unwrap_err();
        assert!(matches!(err, EthereumIBCError::NotEnoughSignatures));
    }

    #[test]
    fn test_conflicting_finalized_headers_with_invalid_finality_branch() {
        let (state, header, mut update_2) = setup_conflict();
        beacon_mut(&mut update_2.finalized_header).proposer_index += 1;

        let err = verify(&state, &header, &update_2).unwrap_err();
        assert!(matches!(
            err,
            EthereumIBCError::ValidateFinalizedHeaderFailed(_)
        ));
    }
}
