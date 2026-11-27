// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::ResolvedIbcStorage,
    proto::{PacketProofsRequest, ProofKind},
    rpc::JsonRpcClient,
    EngineError,
};
use blake2::Blake2s256;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

const PATH_PACKET_COMMITMENT: u8 = 1;
const PATH_RECEIPT: u8 = 2;
const PATH_ACKNOWLEDGEMENT: u8 = 3;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketProofEvidence {
    pub l2_block_number: u64,
    pub l1_batch_number: u64,
    pub logical_path: String,
    pub storage_slot: String,
    pub expected_application_value: Option<String>,
    pub zks_get_proof: Value,
}

pub trait PacketEvidenceSource: Send + Sync + 'static {
    fn collect(
        &self,
        request: &PacketProofsRequest,
        counterparty_client_id: &str,
    ) -> Result<Vec<PacketProofEvidence>, EngineError>;
}

#[derive(Clone)]
pub struct PacketEvidenceCollector {
    rpc: JsonRpcClient,
    profile: ResolvedIbcStorage,
}

impl PacketEvidenceCollector {
    #[must_use]
    pub fn new(rpc: JsonRpcClient, profile: ResolvedIbcStorage) -> Self {
        Self { rpc, profile }
    }
}

impl PacketEvidenceSource for PacketEvidenceCollector {
    fn collect(
        &self,
        request: &PacketProofsRequest,
        counterparty_client_id: &str,
    ) -> Result<Vec<PacketProofEvidence>, EngineError> {
        let kind = ProofKind::try_from(request.kind)
            .map_err(|_| EngineError::InvalidRequest("unsupported proof kind".into()))?;
        let executed = self.rpc.executed_batch_at(request.height)?;
        let mut paths = Vec::with_capacity(request.packets.len());
        let mut slots = Vec::with_capacity(request.packets.len());
        for packet in &request.packets {
            let path = canonical_path(
                counterparty_client_id.as_bytes(),
                kind,
                packet.sequence,
                self.profile.max_client_id_bytes,
            )?;
            let slot = direct_mapping_slot(&path, self.profile.mapping_base_slot);
            if slots.contains(&slot) {
                return Err(EngineError::InvalidRequest(format!(
                    "packet {} duplicates another claim path",
                    packet.sequence
                )));
            }
            paths.push(path);
            slots.push(slot);
        }
        let wire_slots = slots
            .iter()
            .map(|slot| format!("0x{}", hex::encode(slot)))
            .collect::<Vec<_>>();
        let raw = self.rpc.call_raw_non_null(
            "zks_getProof",
            &json!([
                format!("0x{}", hex::encode(self.profile.store_address)),
                wire_slots,
                executed.l1_batch_number
            ]),
        )?;
        let response = validate_zks_get_proof_batch(
            &raw,
            self.profile.store_address,
            &slots,
            executed.l1_batch_number,
        )?;
        if response.block_number != executed.l2_block_number
            || response.last_block_timestamp != executed.last_block_timestamp
        {
            return Err(EngineError::Unavailable(
                "zks_getProof state commitment does not match the executed batch-end block".into(),
            ));
        }
        let zks_get_proof = strict_json_value(&raw)?;
        request
            .packets
            .iter()
            .zip(paths)
            .zip(slots)
            .zip(response.storage_values)
            .map(|(((packet, logical_path), storage_slot), storage_value)| {
                Ok(PacketProofEvidence {
                    l2_block_number: executed.l2_block_number,
                    l1_batch_number: executed.l1_batch_number,
                    logical_path: format!("0x{}", hex::encode(logical_path)),
                    storage_slot: format!("0x{}", hex::encode(storage_slot)),
                    expected_application_value: expected_application_value(
                        kind,
                        packet.sequence,
                        packet.timeout_timestamp,
                        storage_value,
                        response.last_block_timestamp,
                    )?,
                    zks_get_proof: zks_get_proof.clone(),
                })
            })
            .collect()
    }
}

fn expected_application_value(
    kind: ProofKind,
    sequence: u64,
    timeout_timestamp: u64,
    storage_value: ProvenStorageValue,
    last_block_timestamp: u64,
) -> Result<Option<String>, EngineError> {
    match (kind, storage_value) {
        (ProofKind::ReceiptAbsence, ProvenStorageValue::NonExisting) => {
            if timeout_timestamp == 0 || last_block_timestamp < timeout_timestamp {
                return Err(EngineError::InvalidRequest(format!(
                    "packet {sequence} timeout has not been reached by authenticated batch timestamp {last_block_timestamp}"
                )));
            }
            Ok(None)
        }
        (ProofKind::ReceiptAbsence, ProvenStorageValue::Existing(_)) => {
            Err(EngineError::InvalidRequest(format!(
                "packet {sequence} receipt exists at the requested batch"
            )))
        }
        (_, ProvenStorageValue::Existing(value)) => Ok(Some(format!("0x{}", hex::encode(value)))),
        (_, ProvenStorageValue::NonExisting) => Err(EngineError::InvalidRequest(format!(
            "packet {sequence} membership value is absent at the requested batch"
        ))),
    }
}

fn canonical_path(
    client_id: &[u8],
    kind: ProofKind,
    sequence: u64,
    maximum_client_id_bytes: usize,
) -> Result<Vec<u8>, EngineError> {
    if client_id.is_empty() || client_id.len() > maximum_client_id_bytes {
        return Err(EngineError::InvalidRequest(format!(
            "counterparty client ID must contain 1..={maximum_client_id_bytes} bytes"
        )));
    }
    let path_type = match kind {
        ProofKind::PacketCommitment => PATH_PACKET_COMMITMENT,
        ProofKind::Acknowledgement => PATH_ACKNOWLEDGEMENT,
        ProofKind::ReceiptAbsence => PATH_RECEIPT,
        ProofKind::Unspecified => {
            return Err(EngineError::InvalidRequest("proof kind is required".into()));
        }
    };
    let mut path = Vec::with_capacity(client_id.len() + 9);
    path.extend_from_slice(client_id);
    path.push(path_type);
    path.extend_from_slice(&sequence.to_be_bytes());
    Ok(path)
}

fn direct_mapping_slot(path: &[u8], mapping_base_slot: [u8; 32]) -> [u8; 32] {
    let application_key: [u8; 32] = Keccak256::digest(path).into();
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&application_key);
    preimage[32..].copy_from_slice(&mapping_base_slot);
    Keccak256::digest(preimage).into()
}

pub(crate) fn derive_native_tree_key(address: [u8; 20], storage_slot: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0_u8; 64];
    preimage[12..32].copy_from_slice(&address);
    preimage[32..].copy_from_slice(&storage_slot);
    Blake2s256::digest(preimage).into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope {
    jsonrpc: String,
    id: u64,
    result: ZksProofResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZksProofResult {
    address: String,
    state_commitment_preimage: StateCommitmentPreimage,
    storage_proofs: Vec<StorageProof>,
    l1_verification_data: L1VerificationData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateCommitmentPreimage {
    next_free_slot: String,
    block_number: String,
    last_256_block_hashes_blake: String,
    last_block_timestamp: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageProof {
    key: String,
    proof: WireStorageProof,
}

#[derive(Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields,
    tag = "type"
)]
enum WireStorageProof {
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireProofEntryWithKey {
    index: u64,
    value: String,
    next_index: u64,
    siblings: Vec<String>,
    leaf_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct L1VerificationData {
    batch_number: u64,
    number_of_layer1_txs: u64,
    priority_operations_hash: String,
    dependency_roots_rolling_hash: String,
    l2_to_l1_logs_root_hash: String,
    commitment: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvenStorageValue {
    Existing([u8; 32]),
    NonExisting,
}

pub(crate) struct ValidatedZksProof {
    pub(crate) block_number: u64,
    pub(crate) last_block_timestamp: u64,
    #[allow(dead_code)] // Read by focused proof-validation tests, not StateProof's metadata probe.
    pub(crate) storage_value: ProvenStorageValue,
}

pub(crate) struct ValidatedZksProofBatch {
    pub(crate) block_number: u64,
    pub(crate) last_block_timestamp: u64,
    pub(crate) storage_values: Vec<ProvenStorageValue>,
}

pub(crate) fn validate_zks_get_proof(
    raw: &[u8],
    expected_address: [u8; 20],
    expected_slot: [u8; 32],
    expected_batch: u64,
) -> Result<ValidatedZksProof, EngineError> {
    let batch =
        validate_zks_get_proof_batch(raw, expected_address, &[expected_slot], expected_batch)?;
    let storage_value =
        batch.storage_values.first().copied().ok_or_else(|| {
            EngineError::Unavailable("zks_getProof returned no storage proof".into())
        })?;
    Ok(ValidatedZksProof {
        block_number: batch.block_number,
        last_block_timestamp: batch.last_block_timestamp,
        storage_value,
    })
}

pub(crate) fn validate_zks_get_proof_batch(
    raw: &[u8],
    expected_address: [u8; 20],
    expected_slots: &[[u8; 32]],
    expected_batch: u64,
) -> Result<ValidatedZksProofBatch, EngineError> {
    let envelope: RpcEnvelope = strict_json(raw, "zks_getProof response")?;
    if envelope.jsonrpc != "2.0" || envelope.id != 1 {
        return Err(EngineError::Unavailable(
            "zks_getProof returned unexpected JSON-RPC version or id".into(),
        ));
    }
    let result = envelope.result;
    if decode_fixed::<20>("zks_getProof address", &result.address)? != expected_address
        || expected_slots.is_empty()
        || result.storage_proofs.len() != expected_slots.len()
        || result.l1_verification_data.batch_number != expected_batch
    {
        return Err(EngineError::Unavailable(
            "zks_getProof response is not bound to the requested address, slot and batch".into(),
        ));
    }
    validate_quantity(
        "stateCommitmentPreimage.nextFreeSlot",
        &result.state_commitment_preimage.next_free_slot,
    )?;
    let block_number = validate_quantity(
        "stateCommitmentPreimage.blockNumber",
        &result.state_commitment_preimage.block_number,
    )?;
    decode_fixed::<32>(
        "stateCommitmentPreimage.last256BlockHashesBlake",
        &result.state_commitment_preimage.last_256_block_hashes_blake,
    )?;
    let last_block_timestamp = validate_quantity(
        "stateCommitmentPreimage.lastBlockTimestamp",
        &result.state_commitment_preimage.last_block_timestamp,
    )?;
    validate_l1_data(&result.l1_verification_data)?;
    let storage_values = result
        .storage_proofs
        .iter()
        .zip(expected_slots)
        .map(|(proof, expected_slot)| {
            if decode_fixed::<32>("zks_getProof storage key", &proof.key)? != *expected_slot {
                return Err(EngineError::Unavailable(
                    "zks_getProof response contains an unexpected storage slot".into(),
                ));
            }
            validate_storage_proof(
                &proof.proof,
                derive_native_tree_key(expected_address, *expected_slot),
            )
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    Ok(ValidatedZksProofBatch {
        block_number,
        last_block_timestamp,
        storage_values,
    })
}

fn validate_storage_proof(
    proof: &WireStorageProof,
    queried_key: [u8; 32],
) -> Result<ProvenStorageValue, EngineError> {
    match proof {
        WireStorageProof::Existing {
            index,
            value,
            next_index,
            siblings,
        } => {
            validate_proof_entry(*index, *next_index, value, siblings, "existing proof")?;
            Ok(ProvenStorageValue::Existing(decode_fixed::<32>(
                "existing proof value",
                value,
            )?))
        }
        WireStorageProof::NonExisting {
            left_neighbor,
            right_neighbor,
        } => {
            let left_key = validate_neighbor(left_neighbor, "left neighbor")?;
            let right_key = validate_neighbor(right_neighbor, "right neighbor")?;
            if left_neighbor.next_index != right_neighbor.index {
                return Err(EngineError::Unavailable(
                    "non-membership neighbor indices are not linked".into(),
                ));
            }
            if left_key >= queried_key || queried_key >= right_key {
                return Err(EngineError::Unavailable(
                    "non-membership neighbors do not strictly bracket the queried native key"
                        .into(),
                ));
            }
            Ok(ProvenStorageValue::NonExisting)
        }
    }
}

fn validate_neighbor(value: &WireProofEntryWithKey, field: &str) -> Result<[u8; 32], EngineError> {
    validate_proof_entry(
        value.index,
        value.next_index,
        &value.value,
        &value.siblings,
        field,
    )?;
    decode_fixed::<32>(&format!("{field} leaf key"), &value.leaf_key)
}

fn validate_proof_entry(
    _index: u64,
    _next_index: u64,
    value: &str,
    siblings: &[String],
    field: &str,
) -> Result<(), EngineError> {
    decode_fixed::<32>(&format!("{field} value"), value)?;
    if siblings.len() > 64 {
        return Err(EngineError::Unavailable(format!(
            "{field} contains more than 64 siblings"
        )));
    }
    for sibling in siblings {
        decode_fixed::<32>(&format!("{field} sibling"), sibling)?;
    }
    Ok(())
}

fn validate_l1_data(value: &L1VerificationData) -> Result<(), EngineError> {
    let _ = value.number_of_layer1_txs;
    decode_fixed::<32>("priorityOperationsHash", &value.priority_operations_hash)?;
    decode_fixed::<32>(
        "dependencyRootsRollingHash",
        &value.dependency_roots_rolling_hash,
    )?;
    decode_fixed::<32>("l2ToL1LogsRootHash", &value.l2_to_l1_logs_root_hash)?;
    decode_fixed::<32>("commitment", &value.commitment)?;
    Ok(())
}

pub(crate) fn validate_quantity(field: &str, value: &str) -> Result<u64, EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    if body.is_empty()
        || (body.len() > 1 && body.starts_with('0'))
        || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EngineError::Unavailable(format!(
            "{field} is not a canonical hexadecimal quantity"
        )));
    }
    u64::from_str_radix(body, 16)
        .map_err(|_| EngineError::Unavailable(format!("{field} exceeds u64")))
}

pub(crate) fn decode_fixed<const N: usize>(
    field: &str,
    value: &str,
) -> Result<[u8; N], EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    let bytes = hex::decode(body)
        .map_err(|_| EngineError::Unavailable(format!("{field} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| EngineError::Unavailable(format!("{field} must be {N} bytes")))
}

pub(crate) fn strict_json<T: for<'de> Deserialize<'de>>(
    raw: &[u8],
    label: &str,
) -> Result<T, EngineError> {
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut decoder)
        .map_err(|error| EngineError::Unavailable(format!("invalid {label}: {error}")))?;
    decoder
        .end()
        .map_err(|error| EngineError::Unavailable(format!("trailing data in {label}: {error}")))?;
    Ok(value)
}

pub(crate) fn strict_json_value(raw: &[u8]) -> Result<Value, EngineError> {
    strict_json(raw, "zks_getProof response")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::ResolvedRpc;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    fn rpc(responses: Vec<Vec<u8>>) -> JsonRpcClient {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        JsonRpcClient::new(
            &ResolvedRpc {
                url: url::Url::parse(&format!("http://{address}/")).unwrap(),
                chain_id: 6565,
                authorization: None,
                max_response_bytes: 64 * 1024,
                max_batch_lookback: 4,
            },
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn batch_response() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":1, "result": {
                "batch_info": {
                    "batch_number": 7,
                    "state_commitment": format!("0x{}", "11".repeat(32)),
                    "number_of_layer1_txs": 0,
                    "priority_operations_hash": format!("0x{}", "22".repeat(32)),
                    "dependency_roots_rolling_hash": format!("0x{}", "33".repeat(32)),
                    "l2_to_l1_logs_root_hash": format!("0x{}", "44".repeat(32)),
                    "commitment": format!("0x{}", "55".repeat(32)),
                    "last_block_timestamp": 100
                },
                "block_range": {"start":2,"end":2},
                "execute_sl_block_number": 10
            }
        }))
        .unwrap()
    }

    #[test]
    fn canonical_paths_match_reviewed_poc_shape() {
        assert_eq!(
            canonical_path(b"client-0", ProofKind::PacketCommitment, 1, 128),
            Ok(hex::decode("636c69656e742d30010000000000000001").unwrap_or_default())
        );
        assert_eq!(
            canonical_path(b"client-0", ProofKind::ReceiptAbsence, 2, 128),
            Ok(hex::decode("636c69656e742d30020000000000000002").unwrap_or_default())
        );
        assert_eq!(
            canonical_path(b"client-0", ProofKind::Acknowledgement, 3, 128),
            Ok(hex::decode("636c69656e742d30030000000000000003").unwrap_or_default())
        );
    }

    #[test]
    fn slot_binds_path_and_mapping_base_slot() {
        let path =
            canonical_path(b"client-0", ProofKind::PacketCommitment, 1, 128).unwrap_or_default();
        let first = direct_mapping_slot(&path, [0_u8; 32]);
        let second = direct_mapping_slot(&path, [1_u8; 32]);
        assert_ne!(first, second);
    }
    fn zks_response(address: [u8; 20], slot: [u8; 32], batch: u64, proof: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "address": format!("0x{}", hex::encode(address)),
                "stateCommitmentPreimage": {
                    "nextFreeSlot": "0x1",
                    "blockNumber": "0x2",
                    "last256BlockHashesBlake": format!("0x{}", "33".repeat(32)),
                    "lastBlockTimestamp": "0x64"
                },
                "storageProofs": [{
                    "key": format!("0x{}", hex::encode(slot)),
                    "proof": proof
                }],
                "l1VerificationData": {
                    "batchNumber": batch,
                    "numberOfLayer1Txs": 0,
                    "priorityOperationsHash": format!("0x{}", "44".repeat(32)),
                    "dependencyRootsRollingHash": format!("0x{}", "55".repeat(32)),
                    "l2ToL1LogsRootHash": format!("0x{}", "66".repeat(32)),
                    "commitment": format!("0x{}", "77".repeat(32))
                }
            }
        }))
        .unwrap_or_default()
    }

    #[test]
    fn zks_proof_response_is_bound_to_address_slot_and_batch() {
        let address = [0x11; 20];
        let slot = [0x22; 32];
        let response = zks_response(
            address,
            slot,
            7,
            &json!({
                "type": "existing",
                "index": 1,
                "value": format!("0x{}", "aa".repeat(32)),
                "nextIndex": 2,
                "siblings": []
            }),
        );
        let validated = validate_zks_get_proof(&response, address, slot, 7);
        assert!(matches!(
            validated,
            Ok(ValidatedZksProof {
                block_number: 2,
                last_block_timestamp: 100,
                storage_value: ProvenStorageValue::Existing(_)
            })
        ));
        assert!(validate_zks_get_proof(&response, [0x12; 20], slot, 7).is_err());
        assert!(validate_zks_get_proof(&response, address, [0x23; 32], 7).is_err());
        assert!(validate_zks_get_proof(&response, address, slot, 8).is_err());
    }

    #[test]
    fn native_proof_variant_and_neighbor_linkage_are_enforced() {
        let address = [0x31; 20];
        let slot = [0x42; 32];
        let non_existing = |right_index| {
            zks_response(
                address,
                slot,
                9,
                &json!({
                    "type": "nonExisting",
                    "leftNeighbor": {
                        "index": 1,
                        "value": format!("0x{}", "11".repeat(32)),
                        "nextIndex": 2,
                        "siblings": [],
                        "leafKey": format!("0x{}", "00".repeat(32))
                    },
                    "rightNeighbor": {
                        "index": right_index,
                        "value": format!("0x{}", "33".repeat(32)),
                        "nextIndex": 3,
                        "siblings": [],
                        "leafKey": format!("0x{}", "ff".repeat(32))
                    }
                }),
            )
        };
        let valid = validate_zks_get_proof(&non_existing(2), address, slot, 9);
        assert!(matches!(
            valid,
            Ok(ValidatedZksProof {
                storage_value: ProvenStorageValue::NonExisting,
                ..
            })
        ));
        assert!(validate_zks_get_proof(&non_existing(4), address, slot, 9).is_err());
    }

    #[test]
    fn packet_kind_requires_matching_native_proof_variant() {
        let existing = ValidatedZksProof {
            block_number: 1,
            last_block_timestamp: 100,
            storage_value: ProvenStorageValue::Existing([0x55; 32]),
        };
        let absent = ValidatedZksProof {
            block_number: 1,
            last_block_timestamp: 100,
            storage_value: ProvenStorageValue::NonExisting,
        };
        assert_eq!(
            expected_application_value(
                ProofKind::PacketCommitment,
                7,
                0,
                existing.storage_value,
                existing.last_block_timestamp,
            ),
            Ok(Some(format!("0x{}", "55".repeat(32))))
        );
        assert!(expected_application_value(
            ProofKind::PacketCommitment,
            7,
            0,
            absent.storage_value,
            absent.last_block_timestamp
        )
        .is_err());
        assert!(expected_application_value(
            ProofKind::ReceiptAbsence,
            7,
            90,
            existing.storage_value,
            existing.last_block_timestamp
        )
        .is_err());
        assert_eq!(
            expected_application_value(
                ProofKind::ReceiptAbsence,
                7,
                90,
                absent.storage_value,
                absent.last_block_timestamp,
            ),
            Ok(None)
        );
        assert!(expected_application_value(
            ProofKind::ReceiptAbsence,
            7,
            101,
            absent.storage_value,
            absent.last_block_timestamp,
        )
        .is_err());
    }

    #[test]
    fn collector_builds_packet_evidence_from_executed_native_state() {
        let address = [0x11; 20];
        let mapping = [0x22; 32];
        let logical = canonical_path(b"counterparty", ProofKind::PacketCommitment, 1, 128).unwrap();
        let slot = direct_mapping_slot(&logical, mapping);
        let proof = zks_response(
            address,
            slot,
            7,
            &json!({
                "type": "existing", "index": 1,
                "value": format!("0x{}", "aa".repeat(32)),
                "nextIndex": 2, "siblings": []
            }),
        );
        let collector = PacketEvidenceCollector::new(
            rpc(vec![batch_response(), proof]),
            ResolvedIbcStorage {
                store_address: address,
                mapping_base_slot: mapping,
                native_root_probe_slot: [0x33; 32],
                absence_profile_id: 1,
                max_client_id_bytes: 128,
            },
        );
        let request = PacketProofsRequest {
            client: None,
            height: 2,
            kind: ProofKind::PacketCommitment as i32,
            packets: vec![crate::proto::Packet {
                sequence: 1,
                source_client: "source".into(),
                destination_client: "destination".into(),
                timeout_timestamp: 200,
                payloads: vec![],
            }],
        };
        let evidence = collector.collect(&request, "counterparty").unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].l2_block_number, 2);
        assert_eq!(evidence[0].l1_batch_number, 7);
        let expected = format!("0x{}", "aa".repeat(32));
        assert_eq!(
            evidence[0].expected_application_value.as_deref(),
            Some(expected.as_str())
        );
    }
}
