// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::{ResolvedBootstrap, ResolvedIbcStorage, ResolvedSettlement},
    http::read_response_bounded,
    rpc::JsonRpcClient,
    storage::{decode_fixed, strict_json, validate_quantity, validate_zks_get_proof},
    EngineError,
};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::time::Duration;

const OPTIMISTIC_UPDATE_PATH: &str = "/eth/v1/beacon/light_client/optimistic_update";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateProofEvidence {
    pub candidate_batch: u64,
    pub target_l2_block: u64,
    pub l2_batch_timestamp: u64,
    pub settlement_storage_slot: String,
    pub total_batches_executed_slot: String,
    pub native_root_proof: Value,
    pub optimistic_update: Value,
    pub settlement_account_proof: Value,
}

pub trait StateEvidenceSource: Send + Sync + 'static {
    fn collect(&self, candidate_batch: u64) -> Result<StateProofEvidence, EngineError>;
}

#[derive(Clone)]
pub struct SettlementEvidenceCollector {
    l2_rpc: JsonRpcClient,
    l1_rpc: JsonRpcClient,
    ibc: ResolvedIbcStorage,
    settlement: ResolvedSettlement,
    beacon_url: url::Url,
    beacon_authorization: Option<String>,
    beacon_max_response_bytes: usize,
    beacon_client: HttpClient,
}

impl SettlementEvidenceCollector {
    pub fn new(
        l2_rpc: JsonRpcClient,
        l1_rpc: JsonRpcClient,
        ibc: ResolvedIbcStorage,
        settlement: ResolvedSettlement,
        beacon: &ResolvedBootstrap,
        timeout: Duration,
    ) -> Result<Self, EngineError> {
        let beacon_client = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| EngineError::Internal(format!("build Beacon HTTP client: {error}")))?;
        Ok(Self {
            l2_rpc,
            l1_rpc,
            ibc,
            settlement,
            beacon_url: beacon.url.clone(),
            beacon_authorization: beacon.authorization.clone(),
            beacon_max_response_bytes: beacon.max_response_bytes,
            beacon_client,
        })
    }

    fn optimistic_update(&self) -> Result<Vec<u8>, EngineError> {
        let url = self
            .beacon_url
            .join(OPTIMISTIC_UPDATE_PATH)
            .map_err(|error| EngineError::Internal(format!("Beacon URL: {error}")))?;
        let mut request = self
            .beacon_client
            .get(url)
            .header("Accept", "application/json");
        if let Some(authorization) = &self.beacon_authorization {
            request = request.header("Authorization", authorization);
        }
        let response = request.send().map_err(|error| {
            EngineError::Unavailable(format!("Beacon optimistic update: {error}"))
        })?;
        let status = response.status();
        let body = read_response_bounded(response, self.beacon_max_response_bytes)
            .map_err(|error| EngineError::Unavailable(error.to_string()))?;
        if !status.is_success() {
            return Err(EngineError::Unavailable(format!(
                "Beacon optimistic update returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(body)
    }
}

impl StateEvidenceSource for SettlementEvidenceCollector {
    fn collect(&self, source_height: u64) -> Result<StateProofEvidence, EngineError> {
        if source_height == 0 {
            return Err(EngineError::InvalidRequest(
                "source height must be nonzero".into(),
            ));
        }
        let executed = self.l2_rpc.executed_batch_at(source_height)?;
        let candidate_batch = executed.l1_batch_number;

        let native_raw = self.l2_rpc.call_raw_non_null(
            "zks_getProof",
            &json!([
                format!("0x{}", hex::encode(self.ibc.store_address)),
                [format!(
                    "0x{}",
                    hex::encode(self.ibc.native_root_probe_slot)
                )],
                candidate_batch
            ]),
        )?;
        let native = validate_zks_get_proof(
            &native_raw,
            self.ibc.store_address,
            self.ibc.native_root_probe_slot,
            candidate_batch,
        )?;
        if native.block_number != executed.l2_block_number
            || native.last_block_timestamp != executed.last_block_timestamp
        {
            return Err(EngineError::Unavailable(
                "zks_getProof state commitment does not match the executed batch-end block".into(),
            ));
        }
        let optimistic_raw = self.optimistic_update()?;
        let execution_block = validate_optimistic_update(&optimistic_raw)?;
        let settlement_slot = stored_batch_hash_slot(
            candidate_batch,
            self.settlement.stored_batch_hash_mapping_base_slot,
        );
        let l1_raw = self.l1_rpc.call_raw_non_null(
            "eth_getProof",
            &json!([
                format!("0x{}", hex::encode(self.settlement.diamond_proxy_address)),
                [
                    format!("0x{}", hex::encode(settlement_slot)),
                    format!(
                        "0x{}",
                        hex::encode(self.settlement.total_batches_executed_slot)
                    )
                ],
                format!("0x{execution_block:x}")
            ]),
        )?;
        validate_eth_get_proof(
            &l1_raw,
            self.settlement.diamond_proxy_address,
            [settlement_slot, self.settlement.total_batches_executed_slot],
            candidate_batch,
        )?;

        Ok(StateProofEvidence {
            candidate_batch,
            target_l2_block: native.block_number,
            l2_batch_timestamp: native.last_block_timestamp,
            settlement_storage_slot: format!("0x{}", hex::encode(settlement_slot)),
            total_batches_executed_slot: format!(
                "0x{}",
                hex::encode(self.settlement.total_batches_executed_slot)
            ),
            native_root_proof: strict_json(&native_raw, "zks_getProof response")?,
            optimistic_update: strict_json(&optimistic_raw, "Beacon optimistic update")?,
            settlement_account_proof: strict_json(&l1_raw, "eth_getProof response")?,
        })
    }
}

fn stored_batch_hash_slot(batch: u64, mapping_base_slot: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0_u8; 64];
    preimage[24..32].copy_from_slice(&batch.to_be_bytes());
    preimage[32..].copy_from_slice(&mapping_base_slot);
    Keccak256::digest(preimage).into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptimisticEnvelope {
    version: String,
    data: Value,
}

fn validate_optimistic_update(raw: &[u8]) -> Result<u64, EngineError> {
    let envelope: OptimisticEnvelope = strict_json(raw, "Beacon optimistic update")?;
    if envelope.version != "fulu" {
        return Err(EngineError::Unavailable(format!(
            "unsupported optimistic-update fork {}",
            envelope.version
        )));
    }
    let execution_block = envelope
        .data
        .pointer("/attested_header/execution/block_number")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            EngineError::Unavailable(
                "optimistic update lacks attested execution block number".into(),
            )
        })?;
    let signature_slot = envelope
        .data
        .get("signature_slot")
        .and_then(Value::as_str)
        .ok_or_else(|| EngineError::Unavailable("optimistic update lacks signature slot".into()))?;
    let execution_block = parse_decimal_u64("execution block number", execution_block)?;
    let signature_slot = parse_decimal_u64("signature slot", signature_slot)?;
    if execution_block == 0 || signature_slot == 0 {
        return Err(EngineError::Unavailable(
            "optimistic update contains a zero execution block or signature slot".into(),
        ));
    }
    Ok(execution_block)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope<T> {
    jsonrpc: String,
    id: u64,
    result: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EthProof {
    address: String,
    account_proof: Vec<String>,
    balance: String,
    code_hash: String,
    nonce: String,
    storage_hash: String,
    storage_proof: Vec<EthStorageProof>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EthStorageProof {
    key: String,
    proof: Vec<String>,
    value: String,
}

fn validate_eth_get_proof(
    raw: &[u8],
    expected_address: [u8; 20],
    expected_slots: [[u8; 32]; 2],
    candidate_batch: u64,
) -> Result<(), EngineError> {
    let envelope: RpcEnvelope<EthProof> = strict_json(raw, "eth_getProof response")?;
    if envelope.jsonrpc != "2.0" || envelope.id != 1 {
        return Err(EngineError::Unavailable(
            "eth_getProof returned unexpected JSON-RPC version or id".into(),
        ));
    }
    let proof = envelope.result;
    if decode_fixed::<20>("eth_getProof address", &proof.address)? != expected_address
        || proof.storage_proof.len() != 2
        || decode_fixed::<32>("eth_getProof storage key", &proof.storage_proof[0].key)?
            != expected_slots[0]
        || decode_fixed::<32>(
            "eth_getProof execution-counter key",
            &proof.storage_proof[1].key,
        )? != expected_slots[1]
    {
        return Err(EngineError::Unavailable(
            "eth_getProof response is not bound to the requested address and slot".into(),
        ));
    }
    validate_u256_quantity("eth_getProof balance", &proof.balance)?;
    validate_quantity("eth_getProof nonce", &proof.nonce)?;
    decode_fixed::<32>("eth_getProof code hash", &proof.code_hash)?;
    decode_fixed::<32>("eth_getProof storage hash", &proof.storage_hash)?;
    let storage_value =
        validate_u256_quantity("eth_getProof storage value", &proof.storage_proof[0].value)?;
    if storage_value.iter().all(|byte| *byte == 0) {
        return Err(EngineError::Unavailable(
            "settlement stored-batch hash is zero at the authenticated L1 block".into(),
        ));
    }
    let total_batches_executed = validate_u256_quantity(
        "eth_getProof totalBatchesExecuted",
        &proof.storage_proof[1].value,
    )?;
    let mut candidate_batch_word = [0_u8; 32];
    candidate_batch_word[24..].copy_from_slice(&candidate_batch.to_be_bytes());
    if total_batches_executed < candidate_batch_word {
        return Err(EngineError::Unavailable(format!(
            "candidate batch {candidate_batch} has not reached the executed lifecycle stage"
        )));
    }
    validate_proof_nodes("eth_getProof account proof", &proof.account_proof)?;
    validate_proof_nodes(
        "eth_getProof stored-batch proof",
        &proof.storage_proof[0].proof,
    )?;
    validate_proof_nodes(
        "eth_getProof totalBatchesExecuted proof",
        &proof.storage_proof[1].proof,
    )
}

fn validate_proof_nodes(field: &str, nodes: &[String]) -> Result<(), EngineError> {
    if nodes.is_empty() {
        return Err(EngineError::Unavailable(format!("{field} is empty")));
    }
    for node in nodes {
        let body = node
            .strip_prefix("0x")
            .ok_or_else(|| EngineError::Unavailable(format!("{field} node lacks 0x prefix")))?;
        if body.is_empty()
            || body.len() % 2 != 0
            || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EngineError::Unavailable(format!(
                "{field} contains invalid hex"
            )));
        }
    }
    Ok(())
}

fn validate_u256_quantity(field: &str, value: &str) -> Result<[u8; 32], EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    if body.is_empty()
        || body.len() > 64
        || (body.len() > 1 && body.starts_with('0'))
        || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EngineError::Unavailable(format!(
            "{field} is not a canonical 256-bit hexadecimal quantity"
        )));
    }
    let mut padded = String::with_capacity(64);
    padded.extend(std::iter::repeat_n('0', 64 - body.len()));
    padded.push_str(body);
    let decoded = hex::decode(padded)
        .map_err(|_| EngineError::Unavailable(format!("{field} is invalid hex")))?;
    decoded
        .try_into()
        .map_err(|_| EngineError::Internal(format!("{field} padding produced the wrong length")))
}

fn parse_decimal_u64(field: &str, value: &str) -> Result<u64, EngineError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(EngineError::Unavailable(format!(
            "{field} is not a canonical decimal u64"
        )));
    }
    value
        .parse()
        .map_err(|_| EngineError::Unavailable(format!("{field} exceeds u64")))
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
    };

    fn serve(responses: Vec<Vec<u8>>) -> url::Url {
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
        url::Url::parse(&format!("http://{address}/")).unwrap()
    }

    fn rpc(responses: Vec<Vec<u8>>) -> JsonRpcClient {
        JsonRpcClient::new(
            &ResolvedRpc {
                url: serve(responses),
                chain_id: 1,
                authorization: None,
                max_response_bytes: 128 * 1024,
                max_batch_lookback: 4,
            },
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn batch_response() -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{
            "batch_info":{"batch_number":7,"state_commitment":format!("0x{}","11".repeat(32)),"number_of_layer1_txs":0,"priority_operations_hash":format!("0x{}","22".repeat(32)),"dependency_roots_rolling_hash":format!("0x{}","33".repeat(32)),"l2_to_l1_logs_root_hash":format!("0x{}","44".repeat(32)),"commitment":format!("0x{}","55".repeat(32)),"last_block_timestamp":100},
            "block_range":{"start":2,"end":2},"execute_sl_block_number":10
        }})).unwrap()
    }

    fn native_proof(address: [u8; 20], slot: [u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{
            "address":format!("0x{}",hex::encode(address)),
            "stateCommitmentPreimage":{"nextFreeSlot":"0x1","blockNumber":"0x2","last256BlockHashesBlake":format!("0x{}","33".repeat(32)),"lastBlockTimestamp":"0x64"},
            "storageProofs":[{"key":format!("0x{}",hex::encode(slot)),"proof":{"type":"existing","index":1,"value":format!("0x{}","aa".repeat(32)),"nextIndex":2,"siblings":[]}}],
            "l1VerificationData":{"batchNumber":7,"numberOfLayer1Txs":0,"priorityOperationsHash":format!("0x{}","44".repeat(32)),"dependencyRootsRollingHash":format!("0x{}","55".repeat(32)),"l2ToL1LogsRootHash":format!("0x{}","66".repeat(32)),"commitment":format!("0x{}","77".repeat(32))}
        }})).unwrap()
    }

    #[test]
    fn stored_batch_slot_binds_batch_and_mapping_slot() {
        let first = stored_batch_hash_slot(7, [0x11; 32]);
        assert_ne!(first, stored_batch_hash_slot(8, [0x11; 32]));
        assert_ne!(first, stored_batch_hash_slot(7, [0x12; 32]));
    }

    #[test]
    fn optimistic_update_requires_fulu_and_canonical_numbers() {
        let valid = br#"{"version":"fulu","data":{"attested_header":{"execution":{"block_number":"42"}},"signature_slot":"99"}}"#;
        assert_eq!(validate_optimistic_update(valid), Ok(42));
        let wrong_fork = br#"{"version":"electra","data":{"attested_header":{"execution":{"block_number":"42"}},"signature_slot":"99"}}"#;
        assert!(validate_optimistic_update(wrong_fork).is_err());
        let noncanonical = br#"{"version":"fulu","data":{"attested_header":{"execution":{"block_number":"042"}},"signature_slot":"99"}}"#;
        assert!(validate_optimistic_update(noncanonical).is_err());
    }

    fn eth_proof(
        address: [u8; 20],
        stored_slot: [u8; 32],
        executed_slot: [u8; 32],
        executed: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "address": format!("0x{}", hex::encode(address)),
                "accountProof": ["0x01"],
                "balance": "0x0",
                "codeHash": format!("0x{}", "11".repeat(32)),
                "nonce": "0x0",
                "storageHash": format!("0x{}", "22".repeat(32)),
                "storageProof": [{
                    "key": format!("0x{}", hex::encode(stored_slot)),
                    "proof": ["0x02"],
                    "value": format!("0x{}", "ab".repeat(32))
                }, {
                    "key": format!("0x{}", hex::encode(executed_slot)),
                    "proof": ["0x03"],
                    "value": format!("0x{executed:x}")
                }]
            }
        }))
        .unwrap_or_default()
    }

    #[test]
    fn eth_proof_is_bound_to_address_slot_and_well_formed_nodes() {
        let address = [0x33; 20];
        let slot = [0x44; 32];
        let executed_slot = [0x46; 32];
        let valid = eth_proof(address, slot, executed_slot, 7);
        assert_eq!(
            validate_eth_get_proof(&valid, address, [slot, executed_slot], 7),
            Ok(())
        );
        assert!(validate_eth_get_proof(&valid, [0x34; 20], [slot, executed_slot], 7).is_err());
        assert!(validate_eth_get_proof(&valid, address, [[0x45; 32], executed_slot], 7).is_err());
        let committed_only = eth_proof(address, slot, executed_slot, 6);
        assert!(
            validate_eth_get_proof(&committed_only, address, [slot, executed_slot], 7).is_err()
        );

        let empty_account_proof = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "address": format!("0x{}", hex::encode(address)),
                "accountProof": [],
                "balance": "0x0",
                "codeHash": format!("0x{}", "11".repeat(32)),
                "nonce": "0x0",
                "storageHash": format!("0x{}", "22".repeat(32)),
                "storageProof": [{
                    "key": format!("0x{}", hex::encode(slot)),
                    "proof": ["0x02"],
                    "value": format!("0x{}", "ab".repeat(32))
                }, {
                    "key": format!("0x{}", hex::encode(executed_slot)),
                    "proof": ["0x03"],
                    "value": "0x7"
                }]
            }
        }))
        .unwrap_or_default();
        assert!(
            validate_eth_get_proof(&empty_account_proof, address, [slot, executed_slot], 7)
                .is_err()
        );
    }

    #[test]
    fn quantities_nodes_and_optimistic_fields_are_strict() {
        assert_eq!(validate_u256_quantity("value", "0x0").unwrap(), [0; 32]);
        assert_eq!(validate_u256_quantity("value", "0xff").unwrap()[31], 0xff);
        for invalid in ["1", "0x", "0x00", "0xzz"] {
            assert!(validate_u256_quantity("value", invalid).is_err());
        }
        assert!(validate_u256_quantity("value", &format!("0x{}", "1".repeat(65))).is_err());
        assert!(validate_proof_nodes("proof", &[]).is_err());
        assert!(validate_proof_nodes("proof", &["01".into()]).is_err());
        assert!(validate_proof_nodes("proof", &["0x0".into()]).is_err());
        assert!(validate_proof_nodes("proof", &["0xzz".into()]).is_err());
        assert!(validate_proof_nodes("proof", &["0x01".into()]).is_ok());
        for invalid in ["", "01", "a", "18446744073709551616"] {
            assert!(parse_decimal_u64("decimal", invalid).is_err());
        }
        assert_eq!(parse_decimal_u64("decimal", "42"), Ok(42));

        let missing_execution = br#"{"version":"fulu","data":{"attested_header":{"execution":{}},"signature_slot":"1"}}"#;
        assert!(validate_optimistic_update(missing_execution).is_err());
        let missing_signature =
            br#"{"version":"fulu","data":{"attested_header":{"execution":{"block_number":"1"}}}}"#;
        assert!(validate_optimistic_update(missing_signature).is_err());
        let zero = br#"{"version":"fulu","data":{"attested_header":{"execution":{"block_number":"0"}},"signature_slot":"1"}}"#;
        assert!(validate_optimistic_update(zero).is_err());
    }

    #[test]
    fn collector_combines_executed_native_beacon_and_l1_evidence() {
        let store = [0x11; 20];
        let probe_slot = [0x22; 32];
        let diamond = [0x33; 20];
        let mapping = [0x44; 32];
        let executed_slot = [0x45; 32];
        let settlement_slot = stored_batch_hash_slot(7, mapping);
        let optimistic = br#"{"version":"fulu","data":{"attested_header":{"execution":{"block_number":"42"}},"signature_slot":"99"}}"#.to_vec();
        let beacon_url = serve(vec![optimistic]);
        let collector = SettlementEvidenceCollector::new(
            rpc(vec![batch_response(), native_proof(store, probe_slot)]),
            rpc(vec![eth_proof(diamond, settlement_slot, executed_slot, 7)]),
            ResolvedIbcStorage {
                store_address: store,
                mapping_base_slot: [0; 32],
                native_root_probe_slot: probe_slot,
                absence_profile_id: 1,
                max_client_id_bytes: 128,
            },
            ResolvedSettlement {
                diamond_proxy_address: diamond,
                stored_batch_hash_mapping_base_slot: mapping,
                total_batches_executed_slot: executed_slot,
            },
            &ResolvedBootstrap {
                source_profile_id_bytes: [1; 32],
                url: beacon_url,
                authorization: None,
                finalized_checkpoint_root: format!("0x{}", "11".repeat(32)),
                source_profile_id: format!("0x{}", "12".repeat(32)),
                initial_trust_path: "/tmp/trust.json".into(),
                initial_trust_sha256: "13".repeat(32),
                sync_committee_size: 8,
                slots_per_epoch: 8,
                epochs_per_sync_committee_period: 8,
                max_response_bytes: 128 * 1024,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        let evidence = collector.collect(2).unwrap();
        assert_eq!(evidence.candidate_batch, 7);
        assert_eq!(evidence.target_l2_block, 2);
        assert_eq!(evidence.l2_batch_timestamp, 100);
        assert!(collector.collect(0).is_err());
    }
}
