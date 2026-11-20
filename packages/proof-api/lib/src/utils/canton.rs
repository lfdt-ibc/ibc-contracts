// SPDX-License-Identifier: Apache-2.0

//! JSON Ledger API client and Daml value conversions for the Canton IBC contracts.

use alloy::primitives::hex;
use anyhow::{anyhow, Context, Result};
use ibc_eureka_solidity_types::ics26::IICS26RouterMsgs::{Packet, Payload};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

/// Template id of the router.
pub const ROUTER_TEMPLATE: &str = "#ibc:IBC.Router:Router";
/// Template id of the per-client router state.
pub const CLIENT_TEMPLATE: &str = "#ibc:IBC.Router:Client";
/// Template id of a packet commitment. Its creation is the send packet event.
pub const PACKET_COMMITMENT_TEMPLATE: &str = "#ibc:IBC.Router:PacketCommitment";
/// Template id of a packet acknowledgement. Its creation is the write acknowledgement event.
pub const PACKET_ACK_TEMPLATE: &str = "#ibc:IBC.Router:PacketAck";
/// Interface id of contracts callable through ICS27 GMP.
pub const GMP_RECEIVER_INTERFACE: &str = "#ibc-api:IBC.GMPReceiver:GMPReceiver";

/// `IBC.Types.Payload` in the JSON Ledger API encoding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DamlPayload {
    /// The source port.
    pub source_port: String,
    /// The destination port.
    pub dest_port: String,
    /// The application version.
    pub version: String,
    /// The payload encoding.
    pub encoding: String,
    /// The hex-encoded payload value.
    pub value: String,
}

/// `IBC.Types.Packet` in the JSON Ledger API encoding, where `Int` is a decimal string.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DamlPacket {
    /// The packet sequence.
    pub sequence: String,
    /// The source client id.
    pub source_client: String,
    /// The destination client id.
    pub dest_client: String,
    /// The timeout timestamp in unix seconds.
    pub timeout_timestamp: String,
    /// The packet payloads.
    pub payloads: Vec<DamlPayload>,
}

impl TryFrom<DamlPacket> for Packet {
    type Error = anyhow::Error;

    fn try_from(packet: DamlPacket) -> Result<Self> {
        Ok(Self {
            sequence: packet.sequence.parse()?,
            sourceClient: packet.source_client,
            destClient: packet.dest_client,
            timeoutTimestamp: packet.timeout_timestamp.parse()?,
            payloads: packet
                .payloads
                .into_iter()
                .map(|payload| {
                    Ok(Payload {
                        sourcePort: payload.source_port,
                        destPort: payload.dest_port,
                        version: payload.version,
                        encoding: payload.encoding,
                        value: hex::decode(payload.value)?.into(),
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}

impl From<&Packet> for DamlPacket {
    fn from(packet: &Packet) -> Self {
        Self {
            sequence: packet.sequence.to_string(),
            source_client: packet.sourceClient.clone(),
            dest_client: packet.destClient.clone(),
            timeout_timestamp: packet.timeoutTimestamp.to_string(),
            payloads: packet
                .payloads
                .iter()
                .map(|payload| DamlPayload {
                    source_port: payload.sourcePort.clone(),
                    dest_port: payload.destPort.clone(),
                    version: payload.version.clone(),
                    encoding: payload.encoding.clone(),
                    value: hex::encode(&payload.value),
                })
                .collect(),
        }
    }
}

/// A contract creation, as returned by the JSON Ledger API.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedEvent {
    /// The contract id.
    pub contract_id: String,
    /// The template id, qualified by package id.
    pub template_id: String,
    /// The contract payload.
    pub create_argument: Value,
    /// The opaque blob needed to disclose the contract to a non-stakeholder.
    pub created_event_blob: String,
    /// The signatories of the contract.
    pub signatories: Vec<String>,
}

impl CreatedEvent {
    /// Whether the contract is an instance of `template`, given as `#package:Module:Entity`.
    #[must_use]
    pub fn is_template(&self, template: &str) -> bool {
        template.split_once(':').is_some_and(|(_, name)| {
            self.template_id
                .split_once(':')
                .is_some_and(|(_, n)| n == name)
        })
    }

    /// Decode the contract payload.
    ///
    /// # Errors
    /// Returns an error if the payload does not have the expected shape.
    pub fn argument<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.create_argument.clone())
            .with_context(|| format!("unexpected payload for {}", self.template_id))
    }
}

/// An active contract together with the synchronizer it is assigned to.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveContract {
    /// The creation of the contract.
    pub created_event: CreatedEvent,
    /// The synchronizer the contract is assigned to.
    pub synchronizer_id: String,
}

impl ActiveContract {
    /// The entry that discloses this contract in a command submission.
    #[must_use]
    pub fn disclosure(&self) -> Value {
        json!({
            "templateId": self.created_event.template_id,
            "contractId": self.created_event.contract_id,
            "createdEventBlob": self.created_event.created_event_blob,
            "synchronizerId": self.synchronizer_id,
        })
    }
}

/// A committed transaction, filtered to what one party can see.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// The contracts created by the transaction.
    pub created: Vec<CreatedEvent>,
    /// The time the synchronizer sequenced the transaction, in unix microseconds. Unlike ledger
    /// offsets, this is the same on every participant.
    pub record_time: u64,
}

/// A client for the JSON Ledger API of a Canton participant.
#[derive(Clone, Debug)]
pub struct LedgerClient {
    http: reqwest::Client,
    url: String,
}

impl LedgerClient {
    /// Create a client for the JSON Ledger API at `url`.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
        }
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let response = self
            .http
            .post(format!("{}{path}", self.url))
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await?;
        anyhow::ensure!(status.is_success(), "{path} failed with {status}: {text}");
        Ok(serde_json::from_str(&text)?)
    }

    /// Fetch the transaction with the given update id, as seen by `party`.
    ///
    /// # Errors
    /// Returns an error if the update does not exist, is not a transaction, or is not visible.
    pub async fn transaction(&self, update_id: &str, party: &str) -> Result<Transaction> {
        let wildcard =
            json!({ "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } });
        let response = self
            .post(
                "/v2/updates/update-by-id",
                &json!({
                    "updateId": update_id,
                    "updateFormat": { "includeTransactions": {
                        "eventFormat": event_format(party, &wildcard),
                        "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA",
                    }},
                }),
            )
            .await?;
        let transaction = response
            .pointer("/update/Transaction/value")
            .ok_or_else(|| anyhow!("update {update_id} is not a transaction"))?;

        let created = transaction["events"]
            .as_array()
            .ok_or_else(|| anyhow!("update {update_id} has no events"))?
            .iter()
            .filter_map(|event| event.get("CreatedEvent"))
            .map(|event| Ok(serde_json::from_value(event.clone())?))
            .collect::<Result<_>>()?;
        let record_time = transaction["recordTime"]
            .as_str()
            .ok_or_else(|| anyhow!("update {update_id} has no record time"))?;
        let record_time = time::OffsetDateTime::parse(
            record_time,
            &time::format_description::well_known::Rfc3339,
        )?
        .unix_timestamp_nanos()
            / 1000;

        Ok(Transaction {
            created,
            record_time: record_time.try_into()?,
        })
    }

    /// Fetch the active contracts of `template` visible to `party`.
    ///
    /// # Errors
    /// Returns an error if the ledger cannot be queried.
    pub async fn active_contracts(
        &self,
        party: &str,
        template: &str,
    ) -> Result<Vec<ActiveContract>> {
        let filter = json!({ "TemplateFilter": { "value": {
            "templateId": template,
            "includeCreatedEventBlob": false,
        }}});
        self.query_active_contracts(party, &filter).await
    }

    /// Fetch the active contracts implementing `interface` visible to `party`, with the blobs
    /// needed to disclose them.
    ///
    /// # Errors
    /// Returns an error if the ledger cannot be queried.
    pub async fn active_interface_contracts(
        &self,
        party: &str,
        interface: &str,
    ) -> Result<Vec<ActiveContract>> {
        let filter = json!({ "InterfaceFilter": { "value": {
            "interfaceId": interface,
            "includeInterfaceView": false,
            "includeCreatedEventBlob": true,
        }}});
        self.query_active_contracts(party, &filter).await
    }

    async fn query_active_contracts(
        &self,
        party: &str,
        filter: &Value,
    ) -> Result<Vec<ActiveContract>> {
        let ledger_end = self
            .http
            .get(format!("{}/v2/state/ledger-end", self.url))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        let response = self
            .post(
                "/v2/state/active-contracts",
                &json!({
                    "activeAtOffset": ledger_end["offset"],
                    "eventFormat": event_format(party, filter),
                }),
            )
            .await?;
        response
            .as_array()
            .ok_or_else(|| anyhow!("unexpected active contracts response"))?
            .iter()
            .filter_map(|entry| entry.pointer("/contractEntry/JsActiveContract"))
            .map(|contract| Ok(serde_json::from_value(contract.clone())?))
            .collect()
    }
}

fn event_format(party: &str, identifier_filter: &Value) -> Value {
    json!({
        "filtersByParty": { party: { "cumulative": [{ "identifierFilter": identifier_filter }] } },
        "verbose": false,
    })
}
