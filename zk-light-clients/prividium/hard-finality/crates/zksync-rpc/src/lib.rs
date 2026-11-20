// SPDX-License-Identifier: Apache-2.0

use prividium_types::{L1VerificationData, StateCommitmentPreimage};
use prividium_zksync_native::{
    InnerStorageProof, NativeProofBatch, ProofEntry, ProofEntryWithKey, StorageSlotProof,
};
use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedZksGetProof {
    pub request_id: u64,
    pub proof: NativeProofBatch,
    pub state_commitment_preimage: StateCommitmentPreimage,
    pub l1_verification_data: L1VerificationData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcParseError {
    Json(String),
    WrongJsonRpcVersion(String),
    MissingHexPrefix(&'static str),
    EmptyQuantity(&'static str),
    NonCanonicalQuantity(&'static str),
    InvalidHex(&'static str),
    WrongHexLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    QuantityOverflow(&'static str),
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
struct WireProofResult {
    address: String,
    state_commitment_preimage: WireStateCommitmentPreimage,
    storage_proofs: Vec<WireStorageSlotProof>,
    l1_verification_data: WireL1VerificationData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireStateCommitmentPreimage {
    next_free_slot: String,
    block_number: String,
    last_256_block_hashes_blake: String,
    last_block_timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireL1VerificationData {
    batch_number: u64,
    number_of_layer1_txs: u64,
    priority_operations_hash: String,
    dependency_roots_rolling_hash: String,
    l2_to_l1_logs_root_hash: String,
    commitment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStorageSlotProof {
    key: String,
    proof: WireInnerStorageProof,
}

#[derive(Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields,
    tag = "type"
)]
enum WireInnerStorageProof {
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

pub fn parse_zks_get_proof_response(json: &[u8]) -> Result<ParsedZksGetProof, RpcParseError> {
    let envelope: RpcEnvelope<WireProofResult> =
        serde_json::from_slice(json).map_err(|error| RpcParseError::Json(error.to_string()))?;
    if envelope.jsonrpc != "2.0" {
        return Err(RpcParseError::WrongJsonRpcVersion(envelope.jsonrpc));
    }
    let result = envelope.result;
    let mut storage_proofs = Vec::with_capacity(result.storage_proofs.len());
    for storage in result.storage_proofs {
        storage_proofs.push(StorageSlotProof {
            key: parse_fixed_hex("storageProof.key", &storage.key)?,
            proof: storage.proof.parse()?,
        });
    }
    Ok(ParsedZksGetProof {
        request_id: envelope.id,
        proof: NativeProofBatch {
            address: parse_fixed_hex("address", &result.address)?,
            storage_proofs,
        },
        state_commitment_preimage: StateCommitmentPreimage {
            next_free_slot: parse_quantity(
                "stateCommitmentPreimage.nextFreeSlot",
                &result.state_commitment_preimage.next_free_slot,
            )?,
            block_number: parse_quantity(
                "stateCommitmentPreimage.blockNumber",
                &result.state_commitment_preimage.block_number,
            )?,
            last_256_block_hashes_blake: parse_fixed_hex(
                "stateCommitmentPreimage.last256BlockHashesBlake",
                &result.state_commitment_preimage.last_256_block_hashes_blake,
            )?,
            last_block_timestamp: parse_quantity(
                "stateCommitmentPreimage.lastBlockTimestamp",
                &result.state_commitment_preimage.last_block_timestamp,
            )?,
        },
        l1_verification_data: L1VerificationData {
            batch_number: result.l1_verification_data.batch_number,
            number_of_layer1_txs: result.l1_verification_data.number_of_layer1_txs,
            priority_operations_hash: parse_fixed_hex(
                "l1VerificationData.priorityOperationsHash",
                &result.l1_verification_data.priority_operations_hash,
            )?,
            dependency_roots_rolling_hash: parse_fixed_hex(
                "l1VerificationData.dependencyRootsRollingHash",
                &result.l1_verification_data.dependency_roots_rolling_hash,
            )?,
            l2_to_l1_logs_root_hash: parse_fixed_hex(
                "l1VerificationData.l2ToL1LogsRootHash",
                &result.l1_verification_data.l2_to_l1_logs_root_hash,
            )?,
            commitment: parse_fixed_hex(
                "l1VerificationData.commitment",
                &result.l1_verification_data.commitment,
            )?,
        },
    })
}

impl WireInnerStorageProof {
    fn parse(self) -> Result<InnerStorageProof, RpcParseError> {
        match self {
            Self::Existing {
                index,
                value,
                next_index,
                siblings,
            } => Ok(InnerStorageProof::Existing(ProofEntry {
                index,
                value: parse_fixed_hex("proof.value", &value)?,
                next_index,
                siblings: parse_hashes("proof.siblings", &siblings)?,
            })),
            Self::NonExisting {
                left_neighbor,
                right_neighbor,
            } => Ok(InnerStorageProof::NonExisting {
                left_neighbor: left_neighbor.parse("proof.leftNeighbor")?,
                right_neighbor: right_neighbor.parse("proof.rightNeighbor")?,
            }),
        }
    }
}

impl WireProofEntryWithKey {
    fn parse(self, field: &'static str) -> Result<ProofEntryWithKey, RpcParseError> {
        Ok(ProofEntryWithKey {
            entry: ProofEntry {
                index: self.index,
                value: parse_fixed_hex(field, &self.value)?,
                next_index: self.next_index,
                siblings: parse_hashes(field, &self.siblings)?,
            },
            leaf_key: parse_fixed_hex(field, &self.leaf_key)?,
        })
    }
}

fn parse_hashes(field: &'static str, values: &[String]) -> Result<Vec<[u8; 32]>, RpcParseError> {
    values
        .iter()
        .map(|value| parse_fixed_hex(field, value))
        .collect()
}

fn parse_quantity(field: &'static str, value: &str) -> Result<u64, RpcParseError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(RpcParseError::MissingHexPrefix(field))?;
    if hex.is_empty() {
        return Err(RpcParseError::EmptyQuantity(field));
    }
    if hex.len() > 1 && hex.starts_with('0') {
        return Err(RpcParseError::NonCanonicalQuantity(field));
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RpcParseError::InvalidHex(field));
    }
    u64::from_str_radix(hex, 16).map_err(|_| RpcParseError::QuantityOverflow(field))
}

fn parse_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], RpcParseError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(RpcParseError::MissingHexPrefix(field))?;
    let expected = N.checked_mul(2).ok_or(RpcParseError::WrongHexLength {
        field,
        expected: usize::MAX,
        actual: hex.len(),
    })?;
    if hex.len() != expected {
        return Err(RpcParseError::WrongHexLength {
            field,
            expected,
            actual: hex.len(),
        });
    }
    let mut output = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = core::str::from_utf8(pair).map_err(|_| RpcParseError::InvalidHex(field))?;
        output[index] =
            u8::from_str_radix(pair, 16).map_err(|_| RpcParseError::InvalidHex(field))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXISTING: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/zksync-native/v0.20.8/local/existing-nonzero/raw-response.json"
    ));
    const NON_EXISTING: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/zksync-native/v0.20.8/local/never-existing/raw-response.json"
    ));

    #[test]
    fn parses_real_existing_and_nonexisting_wire_variants() {
        let existing = parse_zks_get_proof_response(EXISTING);
        assert_eq!(
            existing
                .as_ref()
                .map(|value| value.state_commitment_preimage.last_block_timestamp),
            Ok(0x6aa9_04ac)
        );
        let nonexisting = parse_zks_get_proof_response(NON_EXISTING);
        assert!(nonexisting.is_ok());
        assert!(matches!(
            nonexisting.map(|value| value.proof.storage_proofs[0].proof.clone()),
            Ok(InnerStorageProof::NonExisting { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields_wrong_width_and_noncanonical_quantities() {
        let input = core::str::from_utf8(EXISTING).unwrap_or_default();
        let unknown = input.replacen("\"result\":{", "\"result\":{\"unknown\":1,", 1);
        assert!(parse_zks_get_proof_response(unknown.as_bytes()).is_err());
        let wrong_width = input.replacen("0xe441cf0795af14ddb9f7984da85cd36db1b8790d", "0xe441", 1);
        assert!(matches!(
            parse_zks_get_proof_response(wrong_width.as_bytes()),
            Err(RpcParseError::WrongHexLength { .. })
        ));
        let leading_zero = input.replacen("\"blockNumber\":\"0x4\"", "\"blockNumber\":\"0x04\"", 1);
        assert!(matches!(
            parse_zks_get_proof_response(leading_zero.as_bytes()),
            Err(RpcParseError::NonCanonicalQuantity(
                "stateCommitmentPreimage.blockNumber"
            ))
        ));
    }

    #[test]
    fn json_rpc_error_never_defaults_to_empty_result() {
        let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"missing"}}"#;
        assert!(matches!(
            parse_zks_get_proof_response(error),
            Err(RpcParseError::Json(_))
        ));
    }
}
