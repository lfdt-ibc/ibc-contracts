// SPDX-License-Identifier: Apache-2.0

//! This module provides [`update_consensus_state`] function to update the consensus state

use crate::{
    client_state::ClientState, consensus_state::ConsensusState, error::EthereumIBCError,
    header::Header,
};

/// Updates the consensus state, and the client state if the header is newer than the latest slot.
///
/// The trusted consensus state must be the one that the header was verified against, see
/// [`verify_header`](crate::verify::verify_header).
///
/// # Returns
/// Returns the updated slot, the updated consensus state and optionally the updated client state.
///
/// # Errors
/// Returns an error if the store period is not equal to the finalized period
#[allow(clippy::module_name_repetitions, clippy::needless_pass_by_value)]
pub fn update_consensus_state(
    trusted_consensus_state: ConsensusState,
    current_client_state: ClientState,
    header: Header,
) -> Result<(u64, ConsensusState, Option<ClientState>), EthereumIBCError> {
    let store_slot = trusted_consensus_state.slot;
    let store_period = current_client_state.compute_sync_committee_period_at_slot(store_slot);

    let update_finalized_slot = header.consensus_update.finalized_header.beacon().slot;
    let update_finalized_period =
        current_client_state.compute_sync_committee_period_at_slot(update_finalized_slot);

    let finalized_execution = header.finalized_execution()?;

    let mut new_consensus_state = trusted_consensus_state.clone();

    if let Some(next_sync_committee) = trusted_consensus_state.next_sync_committee {
        // sync committee only changes when the period change
        if update_finalized_period == store_period + 1 {
            new_consensus_state.current_sync_committee = next_sync_committee;
            new_consensus_state.next_sync_committee = header
                .consensus_update
                .next_sync_committee
                .map(|c| c.to_summarized_sync_committee());
        }
    } else {
        // if the finalized period is greater, we have to have a next sync committee
        ensure!(
            update_finalized_period == store_period,
            EthereumIBCError::StorePeriodMustBeEqualToFinalizedPeriod
        );
        new_consensus_state.next_sync_committee = header
            .consensus_update
            .next_sync_committee
            .map(|c| c.to_summarized_sync_committee());
    }

    new_consensus_state.slot = update_finalized_slot;
    new_consensus_state.state_root = finalized_execution.state_root;
    new_consensus_state.timestamp = finalized_execution.timestamp;

    let new_client_state =
        (update_finalized_slot > current_client_state.latest_slot).then_some(ClientState {
            latest_slot: update_finalized_slot,
            latest_execution_block_number: finalized_execution.block_number,
            ..current_client_state
        });
    Ok((update_finalized_slot, new_consensus_state, new_client_state))
}

#[cfg(test)]
mod test {
    use ibc_proto_eureka::ibc::lightclients::wasm::v1::ClientMessage;
    use prost::Message;

    use crate::test_utils::fixtures::{self, InitialState, RelayerMessages};

    use super::*;

    #[test]
    fn test_update_consensus_state_from_trusted_consensus_state() {
        let fixture: fixtures::StepsFixture =
            fixtures::load("Test_MultiPeriodClientUpdateToCosmos");

        let initial_state: InitialState = fixture.get_data_at_step(0);

        let client_state = initial_state.client_state;
        let trusted_consensus_state = initial_state.consensus_state;

        let relayer_messages: RelayerMessages = fixture.get_data_at_step(1);
        let (update_client_msgs, _, _, _) = relayer_messages.get_sdk_msgs();
        let client_msg = ClientMessage::decode(
            update_client_msgs[0]
                .client_message
                .clone()
                .unwrap()
                .value
                .as_slice(),
        )
        .unwrap();
        let header: Header = serde_json::from_slice(client_msg.data.as_slice()).unwrap();

        // The header is newer than the latest slot, so the client state is updated too.
        let (updated_slot, updated_consensus_state, updated_client_state) = update_consensus_state(
            trusted_consensus_state.clone(),
            client_state.clone(),
            header.clone(),
        )
        .unwrap();
        assert_eq!(updated_client_state.unwrap().latest_slot, updated_slot);
        assert_eq!(
            Some(updated_consensus_state.current_sync_committee.clone()),
            trusted_consensus_state.next_sync_committee
        );

        // The header is older than the latest slot. The consensus state is the same, because it
        // only depends on the trusted consensus state, and the client state is left as it is.
        let client_state = ClientState {
            latest_slot: updated_slot + 1,
            ..client_state
        };
        let (historical_slot, historical_consensus_state, historical_client_state) =
            update_consensus_state(trusted_consensus_state, client_state, header).unwrap();
        assert_eq!(historical_slot, updated_slot);
        assert_eq!(historical_consensus_state, updated_consensus_state);
        assert!(historical_client_state.is_none());
    }
}
