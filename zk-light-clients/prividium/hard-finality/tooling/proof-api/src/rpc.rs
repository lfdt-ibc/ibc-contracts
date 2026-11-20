// SPDX-License-Identifier: Apache-2.0

use crate::{config::ResolvedRpc, http::read_response_bounded, EngineError};
use reqwest::blocking::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};

pub trait ProvableHeightSource: Send + Sync + 'static {
    fn latest_provable_height(&self) -> Result<(u64, u64), EngineError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutedBatch {
    pub l2_block_number: u64,
    pub l1_batch_number: u64,
    pub last_block_timestamp: u64,
}

#[derive(Clone)]
pub struct JsonRpcClient {
    url: url::Url,
    authorization: Option<String>,
    max_response_bytes: usize,
    client: HttpClient,
}

impl JsonRpcClient {
    pub fn new(config: &ResolvedRpc, timeout: std::time::Duration) -> Result<Self, EngineError> {
        let client = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| EngineError::Internal(format!("build JSON-RPC client: {error}")))?;
        Ok(Self {
            url: config.url.clone(),
            authorization: config.authorization.clone(),
            max_response_bytes: config.max_response_bytes,
            client,
        })
    }

    pub(crate) fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: &Value,
    ) -> Result<Option<T>, EngineError> {
        let body = self.send(method, params)?;
        decode_rpc_response(method, &body)
    }

    pub(crate) fn call_raw_non_null(
        &self,
        method: &'static str,
        params: &Value,
    ) -> Result<Vec<u8>, EngineError> {
        let body = self.send(method, params)?;
        if decode_rpc_response::<Value>(method, &body)?.is_none() {
            return Err(EngineError::Unavailable(format!("{method} returned null")));
        }
        Ok(body)
    }

    pub fn verify_chain_id(&self, expected: u64) -> Result<(), EngineError> {
        let value: String = self
            .call("eth_chainId", &json!([]))?
            .ok_or_else(|| EngineError::Unavailable("eth_chainId returned null".into()))?;
        let actual = parse_quantity("eth_chainId", &value)?;
        if actual != expected {
            return Err(EngineError::Unavailable(format!(
                "RPC chain ID {actual} does not match configured chain ID {expected}"
            )));
        }
        Ok(())
    }

    fn send(&self, method: &'static str, params: &Value) -> Result<Vec<u8>, EngineError> {
        let mut request = self
            .client
            .post(self.url.clone())
            .header("Accept", "application/json")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1_u64,
                "method": method,
                "params": params,
            }));
        if let Some(authorization) = &self.authorization {
            request = request.header("Authorization", authorization);
        }
        let response = request
            .send()
            .map_err(|error| EngineError::Unavailable(format!("{method}: {error}")))?;
        let status = response.status();
        let body = read_response_bounded(response, self.max_response_bytes)
            .map_err(|error| EngineError::Unavailable(format!("{method}: {error}")))?;
        if !status.is_success() {
            return Err(EngineError::Unavailable(format!(
                "{method} returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(body)
    }

    pub(crate) fn executed_batch_at(
        &self,
        l2_block_number: u64,
    ) -> Result<ExecutedBatch, EngineError> {
        let batch = self
            .call::<BatchByBlock>("unstable_getBatchByBlockNumber", &json!([l2_block_number]))?
            .ok_or_else(|| {
                EngineError::Unavailable(format!(
                    "L2 block {l2_block_number} is not assigned to a batch"
                ))
            })?;
        batch.validate(l2_block_number)?;
        if batch.execute_sl_block_number.is_none() {
            return Err(EngineError::Unavailable(format!(
                "batch {} containing L2 block {l2_block_number} is not executed",
                batch.batch_info.batch_number
            )));
        }
        if batch.batch_info.last_block_timestamp == 0 {
            return Err(EngineError::Unavailable(
                "executed batch returned zero lastBlockTimestamp".into(),
            ));
        }
        Ok(ExecutedBatch {
            l2_block_number: batch.block_range.end,
            l1_batch_number: batch.batch_info.batch_number,
            last_block_timestamp: batch.batch_info.last_block_timestamp,
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RpcEnvelope {
    Success {
        jsonrpc: String,
        id: u64,
        result: Value,
    },
    Failure {
        jsonrpc: String,
        id: u64,
        error: RpcError,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn decode_rpc_response<T: DeserializeOwned>(
    method: &'static str,
    body: &[u8],
) -> Result<Option<T>, EngineError> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let envelope = RpcEnvelope::deserialize(&mut decoder).map_err(|error| {
        EngineError::Unavailable(format!("{method}: invalid JSON-RPC: {error}"))
    })?;
    decoder.end().map_err(|error| {
        EngineError::Unavailable(format!("{method}: trailing JSON-RPC data: {error}"))
    })?;
    match envelope {
        RpcEnvelope::Success {
            jsonrpc,
            id,
            result,
        } => {
            validate_envelope(method, &jsonrpc, id)?;
            if result.is_null() {
                return Ok(None);
            }
            serde_json::from_value(result).map(Some).map_err(|error| {
                EngineError::Unavailable(format!("{method}: invalid result: {error}"))
            })
        }
        RpcEnvelope::Failure { jsonrpc, id, error } => {
            validate_envelope(method, &jsonrpc, id)?;
            let suffix = error
                .data
                .map(|data| format!("; data={data}"))
                .unwrap_or_default();
            Err(EngineError::Unavailable(format!(
                "{method} RPC error {}: {}{suffix}",
                error.code, error.message
            )))
        }
    }
}

fn validate_envelope(method: &str, version: &str, id: u64) -> Result<(), EngineError> {
    if version != "2.0" || id != 1 {
        return Err(EngineError::Unavailable(format!(
            "{method}: unexpected JSON-RPC version or id"
        )));
    }
    Ok(())
}

#[derive(Clone)]
pub struct ZksyncHeightProvider {
    rpc: JsonRpcClient,
    max_batch_lookback: u64,
}

impl ZksyncHeightProvider {
    #[must_use]
    pub fn new(rpc: JsonRpcClient, max_batch_lookback: u64) -> Self {
        Self {
            rpc,
            max_batch_lookback,
        }
    }
}

impl ProvableHeightSource for ZksyncHeightProvider {
    fn latest_provable_height(&self) -> Result<(u64, u64), EngineError> {
        let head: String = self
            .rpc
            .call("eth_blockNumber", &json!([]))?
            .ok_or_else(|| EngineError::Unavailable("eth_blockNumber returned null".into()))?;
        let head = parse_quantity("eth_blockNumber", &head)?;
        for offset in 0..=self.max_batch_lookback.min(head) {
            let block = head - offset;
            let Some(batch) = self
                .rpc
                .call::<BatchByBlock>("unstable_getBatchByBlockNumber", &json!([block]))?
            else {
                continue;
            };
            if batch.execute_sl_block_number.is_none() {
                continue;
            }
            batch.validate(block)?;
            if batch.batch_info.last_block_timestamp == 0 {
                return Err(EngineError::Unavailable(
                    "executed batch returned zero lastBlockTimestamp".into(),
                ));
            }
            return Ok((batch.block_range.end, batch.batch_info.last_block_timestamp));
        }
        Err(EngineError::Unavailable(format!(
            "no executed L1 batch found within {} L2 blocks of head {head}",
            self.max_batch_lookback
        )))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchByBlock {
    batch_info: BatchInfo,
    block_range: BlockRange,
    execute_sl_block_number: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchInfo {
    batch_number: u64,
    state_commitment: String,
    number_of_layer1_txs: u64,
    priority_operations_hash: String,
    dependency_roots_rolling_hash: String,
    l2_to_l1_logs_root_hash: String,
    commitment: String,
    last_block_timestamp: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockRange {
    start: u64,
    end: u64,
}

impl BatchByBlock {
    fn validate(&self, requested_block: u64) -> Result<(), EngineError> {
        if self.batch_info.batch_number == 0
            || self.block_range.start > self.block_range.end
            || requested_block < self.block_range.start
            || requested_block > self.block_range.end
            || self.execute_sl_block_number == Some(0)
        {
            return Err(EngineError::Unavailable(
                "unstable_getBatchByBlockNumber returned inconsistent batch metadata".into(),
            ));
        }
        validate_fixed_hex("stateCommitment", &self.batch_info.state_commitment, 32)?;
        validate_fixed_hex(
            "priorityOperationsHash",
            &self.batch_info.priority_operations_hash,
            32,
        )?;
        validate_fixed_hex(
            "dependencyRootsRollingHash",
            &self.batch_info.dependency_roots_rolling_hash,
            32,
        )?;
        validate_fixed_hex(
            "l2ToL1LogsRootHash",
            &self.batch_info.l2_to_l1_logs_root_hash,
            32,
        )?;
        validate_fixed_hex("commitment", &self.batch_info.commitment, 32)?;
        let _ = self.batch_info.number_of_layer1_txs;
        Ok(())
    }
}

pub(crate) fn parse_quantity(field: &str, value: &str) -> Result<u64, EngineError> {
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

fn validate_fixed_hex(field: &str, value: &str, bytes: usize) -> Result<(), EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    if body.len() != bytes * 2 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError::Unavailable(format!(
            "{field} must be exactly {bytes} bytes of hex"
        )));
    }
    Ok(())
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

    const BATCH: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"batch_info":{"batch_number":4,"state_commitment":"0xd3ec308c0eee7ab0154ef61aa094f8c3e4e3c3f1a3bbcabcd05ab351fe2c4122","number_of_layer1_txs":0,"priority_operations_hash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","dependency_roots_rolling_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","l2_to_l1_logs_root_hash":"0x692f35c99f9c698852289ffecf07f6dd45770904521149d79aa85aae598fa375","commitment":"0xa1dd31c9de2345dc1133f9946daf9908dfb9580c4d32c82b62d3e5cf6294a569","last_block_timestamp":1789453484},"block_range":{"start":4,"end":4},"execute_sl_block_number":1966}}"#;

    fn client(responses: Vec<(u16, String)>) -> JsonRpcClient {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let read = stream.read(&mut request).unwrap();
                assert!(String::from_utf8_lossy(&request[..read]).contains("\"jsonrpc\":\"2.0\""));
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        JsonRpcClient::new(
            &ResolvedRpc {
                url: url::Url::parse(&format!("http://{address}/")).unwrap(),
                chain_id: 6565,
                authorization: Some("Bearer rpc-token".into()),
                max_response_bytes: 64 * 1024,
                max_batch_lookback: 4,
            },
            Duration::from_secs(2),
        )
        .unwrap()
    }

    #[test]
    fn parses_pinned_v0208_batch_shape() {
        let batch = decode_rpc_response::<BatchByBlock>("unstable_getBatchByBlockNumber", BATCH);
        assert!(matches!(
            batch,
            Ok(Some(BatchByBlock {
                batch_info: BatchInfo {
                    batch_number: 4,
                    last_block_timestamp: 1_789_453_484,
                    ..
                },
                ..
            }))
        ));
    }

    #[test]
    fn accepts_null_batch_but_rejects_rpc_error_and_trailing_data() {
        let null = br#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        assert!(matches!(
            decode_rpc_response::<BatchByBlock>("batch", null),
            Ok(None)
        ));
        let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"failed"}}"#;
        assert!(decode_rpc_response::<BatchByBlock>("batch", error).is_err());
        let trailing = br#"{"jsonrpc":"2.0","id":1,"result":null} {}"#;
        assert!(decode_rpc_response::<BatchByBlock>("batch", trailing).is_err());
    }

    #[test]
    fn json_rpc_transport_verifies_chain_and_executed_batch() {
        let rpc = client(vec![(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x19a5"}"#.into(),
        )]);
        assert!(rpc.verify_chain_id(6565).is_ok());

        let rpc = client(vec![(200, String::from_utf8(BATCH.to_vec()).unwrap())]);
        let batch = rpc.executed_batch_at(4).unwrap();
        assert_eq!(batch.l2_block_number, 4);
        assert_eq!(batch.l1_batch_number, 4);

        let rpc = client(vec![(500, "{}".into())]);
        assert!(rpc.call::<Value>("eth_chainId", &json!([])).is_err());
    }

    #[test]
    fn height_provider_walks_back_to_latest_executed_batch() {
        let head = r#"{"jsonrpc":"2.0","id":1,"result":"0x5"}"#.to_owned();
        let null = r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_owned();
        let batch = String::from_utf8(BATCH.to_vec()).unwrap();
        let provider =
            ZksyncHeightProvider::new(client(vec![(200, head), (200, null), (200, batch)]), 4);
        assert_eq!(
            provider.latest_provable_height().unwrap(),
            (4, 1_789_453_484)
        );
    }

    #[test]
    fn malformed_envelopes_and_batch_metadata_are_rejected() {
        assert!(
            decode_rpc_response::<Value>("method", br#"{"jsonrpc":"1.0","id":1,"result":{}}"#)
                .is_err()
        );
        assert!(
            decode_rpc_response::<Value>("method", br#"{"jsonrpc":"2.0","id":2,"result":{}}"#)
                .is_err()
        );
        assert!(validate_fixed_hex("hash", "11", 1).is_err());
        assert!(validate_fixed_hex("hash", "0xzz", 1).is_err());

        let mut batch: BatchByBlock = serde_json::from_value(
            serde_json::from_slice::<Value>(BATCH).unwrap()["result"].clone(),
        )
        .unwrap();
        batch.batch_info.batch_number = 0;
        assert!(batch.validate(4).is_err());
    }

    #[test]
    fn quantities_are_canonical() {
        assert_eq!(parse_quantity("height", "0x0"), Ok(0));
        assert_eq!(parse_quantity("height", "0x10"), Ok(16));
        assert!(parse_quantity("height", "0x00").is_err());
        assert!(parse_quantity("height", "10").is_err());
    }
}
