// SPDX-License-Identifier: Apache-2.0

//! This module defines the chain listener for the Canton IBC contracts.

use anyhow::Result;
use futures::future;
use serde::Deserialize;

use crate::{
    events::{EurekaEvent, EurekaEventWithHeight},
    utils::canton::{DamlPacket, LedgerClient, PACKET_ACK_TEMPLATE, PACKET_COMMITMENT_TEMPLATE},
};

#[derive(Deserialize)]
struct PacketCommitment {
    packet: DamlPacket,
}

#[derive(Deserialize)]
struct PacketAck {
    packet: DamlPacket,
    acknowledgements: Vec<String>,
}

/// The `ChainListener` reads IBC events from a Canton participant.
///
/// Canton has no event log: a packet commitment or acknowledgement contract being created is the
/// event. Event heights are record times in unix microseconds.
pub struct ChainListener {
    client: LedgerClient,
    /// The party whose view of the ledger is read. It must be a stakeholder of the router's
    /// contracts, as a relayer is.
    party: String,
}

impl ChainListener {
    /// Create a new `ChainListener` instance.
    #[must_use]
    pub const fn new(client: LedgerClient, party: String) -> Self {
        Self { client, party }
    }

    /// Fetch the IBC events of the transactions with the given update ids.
    ///
    /// # Errors
    /// Returns an error if a transaction cannot be fetched or holds a malformed IBC contract.
    pub async fn fetch_tx_events(
        &self,
        update_ids: Vec<String>,
    ) -> Result<Vec<EurekaEventWithHeight>> {
        let transactions = future::try_join_all(
            update_ids
                .iter()
                .map(|update_id| self.client.transaction(update_id, &self.party)),
        )
        .await?;

        let mut events = Vec::new();
        for transaction in transactions {
            for created in transaction.created {
                let event = if created.is_template(PACKET_COMMITMENT_TEMPLATE) {
                    let commitment: PacketCommitment = created.argument()?;
                    EurekaEvent::SendPacket(commitment.packet.try_into()?)
                } else if created.is_template(PACKET_ACK_TEMPLATE) {
                    let ack: PacketAck = created.argument()?;
                    EurekaEvent::WriteAcknowledgement(
                        ack.packet.try_into()?,
                        ack.acknowledgements
                            .iter()
                            .map(|ack| Ok(alloy::primitives::hex::decode(ack)?.into()))
                            .collect::<Result<_>>()?,
                    )
                } else {
                    continue;
                };
                events.push(EurekaEventWithHeight {
                    event,
                    height: transaction.record_time,
                });
            }
        }
        Ok(events)
    }
}
