// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::ResolvedTrustUpdateRegistrar,
    rpc::{parse_quantity, JsonRpcClient},
    EngineError,
};
use alloy_consensus::{transaction::RlpEcdsaEncodableTx, SignableTransaction, TxLegacy};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

const TRUST_STATE_BYTES: usize = 5 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusTrustState {
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_header_root: [u8; 32],
    pub current_sync_committee_root: [u8; 32],
    pub next_sync_committee_root: [u8; 32],
    pub next_sync_committee_known: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustSnapshot {
    pub block_number: u64,
    pub digest: [u8; 32],
    pub state: ConsensusTrustState,
}

pub trait DestinationStateSource: Send + Sync + 'static {
    fn current_trust(&self) -> Result<TrustSnapshot, EngineError>;
}

#[derive(Clone)]
pub struct DestinationLightClient {
    rpc: JsonRpcClient,
    address: [u8; 20],
    expected: Option<ExpectedIdentity>,
    client_id: Option<String>,
}

#[derive(Clone)]
pub struct ExpectedIdentity {
    pub router: [u8; 20],
    pub source_profile_id: [u8; 32],
    pub ibc_store: [u8; 20],
    pub absence_profile_id: u32,
    pub verifier: [u8; 20],
    pub vkeys: [[u8; 32]; 4],
    pub counterparty_client_id: String,
    pub counterparty_merkle_prefix: Vec<Vec<u8>>,
}

impl DestinationLightClient {
    pub fn resolve_and_validate(
        rpc: JsonRpcClient,
        client_id: &str,
        expected: &ExpectedIdentity,
    ) -> Result<Self, EngineError> {
        let block = destination_head(&rpc)?;
        let address = resolve_router_client(&rpc, expected.router, client_id, block)?;
        let client = Self {
            rpc,
            address,
            expected: Some(expected.clone()),
            client_id: Some(client_id.to_owned()),
        };
        client.validate_identity_at(expected, block)?;
        client.validate_counterparty_at(expected, block)?;
        Ok(client)
    }

    pub fn validate_identity(&self, expected: &ExpectedIdentity) -> Result<(), EngineError> {
        self.validate_identity_at(expected, destination_head(&self.rpc)?)
    }

    #[must_use]
    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_identity_at(
        &self,
        expected: &ExpectedIdentity,
        block: u64,
    ) -> Result<(), EngineError> {
        for (signature, expected_word) in [
            ("SOURCE_PROFILE_ID()", expected.source_profile_id),
            ("TRUST_UPDATE_VKEY()", expected.vkeys[0]),
            ("SETTLEMENT_UPDATE_VKEY()", expected.vkeys[1]),
            ("MEMBERSHIP_VKEY()", expected.vkeys[2]),
            ("NON_MEMBERSHIP_VKEY()", expected.vkeys[3]),
            ("IBC_STORE()", address_word(expected.ibc_store)),
            ("SP1_VERIFIER()", address_word(expected.verifier)),
            ("IBC_ROUTER()", address_word(expected.router)),
        ] {
            if call_word(&self.rpc, self.address, signature, &[], block)? != expected_word {
                return Err(EngineError::Unavailable(format!(
                    "destination light client getter {signature} does not match configuration"
                )));
            }
        }
        let absence = call_word(&self.rpc, self.address, "ABSENCE_PROFILE_ID()", &[], block)?;
        if absence[..28].iter().any(|byte| *byte != 0)
            || u32::from_be_bytes(
                absence[28..]
                    .try_into()
                    .map_err(|_| EngineError::Internal("decode absence profile".into()))?,
            ) != expected.absence_profile_id
        {
            return Err(EngineError::Unavailable(
                "destination light client absence profile does not match configuration".into(),
            ));
        }
        Ok(())
    }

    fn validate_counterparty_at(
        &self,
        expected: &ExpectedIdentity,
        block: u64,
    ) -> Result<(), EngineError> {
        let client_id = self
            .client_id
            .as_deref()
            .ok_or_else(|| EngineError::Internal("destination client ID is missing".into()))?;
        let (actual_client_id, actual_prefix) =
            resolve_router_counterparty(&self.rpc, expected.router, client_id, block)?;
        if actual_client_id != expected.counterparty_client_id
            || actual_prefix != expected.counterparty_merkle_prefix
        {
            return Err(EngineError::Unavailable(
                "Router counterparty does not match configuration".into(),
            ));
        }
        Ok(())
    }
}

fn resolve_router_client(
    rpc: &JsonRpcClient,
    router: [u8; 20],
    client_id: &str,
    block: u64,
) -> Result<[u8; 20], EngineError> {
    let args = encode_string_argument(client_id)?;
    let word = call_word(rpc, router, "getClient(string)", &args, block)?;
    if word[..12].iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(
            "Router getClient returned a noncanonical address".into(),
        ));
    }
    let address: [u8; 20] = word[12..]
        .try_into()
        .map_err(|_| EngineError::Internal("decode Router client address".into()))?;
    if address == [0; 20] {
        return Err(EngineError::Unavailable(
            "Router getClient returned the zero address".into(),
        ));
    }
    Ok(address)
}

fn resolve_router_counterparty(
    rpc: &JsonRpcClient,
    router: [u8; 20],
    client_id: &str,
    block: u64,
) -> Result<(String, Vec<Vec<u8>>), EngineError> {
    let args = encode_string_argument(client_id)?;
    let encoded = call_bytes(rpc, router, "getCounterparty(string)", &args, block)?;
    decode_counterparty(&encoded)
}

fn encode_string_argument(value: &str) -> Result<Vec<u8>, EngineError> {
    let bytes = value.as_bytes();
    let length = u64::try_from(bytes.len())
        .map_err(|_| EngineError::InvalidRequest("client ID is too long".into()))?;
    let padded = bytes.len().div_ceil(32) * 32;
    let mut args = vec![0_u8; 64 + padded];
    args[31] = 32;
    args[56..64].copy_from_slice(&length.to_be_bytes());
    args[64..64 + bytes.len()].copy_from_slice(bytes);
    Ok(args)
}

fn decode_counterparty(encoded: &[u8]) -> Result<(String, Vec<Vec<u8>>), EngineError> {
    const MAX_RETURN_BYTES: usize = 64 * 1024;
    const MAX_PREFIX_PARTS: usize = 16;
    if encoded.len() < 96 || encoded.len() > MAX_RETURN_BYTES || !encoded.len().is_multiple_of(32) {
        return Err(EngineError::Unavailable(
            "Router getCounterparty returned malformed ABI data".into(),
        ));
    }
    let tuple_start = abi_offset(encoded, 0, "counterparty tuple")?;
    let string_start = tuple_start
        .checked_add(abi_offset(encoded, tuple_start, "counterparty client ID")?)
        .ok_or_else(|| EngineError::Unavailable("counterparty client offset overflow".into()))?;
    let array_start = tuple_start
        .checked_add(abi_offset(
            encoded,
            tuple_start + 32,
            "counterparty Merkle prefix",
        )?)
        .ok_or_else(|| EngineError::Unavailable("counterparty prefix offset overflow".into()))?;
    let client_bytes = abi_dynamic_bytes(encoded, string_start, "counterparty client ID")?;
    let client_id = String::from_utf8(client_bytes).map_err(|_| {
        EngineError::Unavailable("Router counterparty client ID is not UTF-8".into())
    })?;
    if client_id.is_empty() {
        return Err(EngineError::Unavailable(
            "Router counterparty client ID is empty".into(),
        ));
    }

    let count = abi_usize(encoded, array_start, "counterparty prefix count")?;
    if count == 0 || count > MAX_PREFIX_PARTS {
        return Err(EngineError::Unavailable(
            "Router counterparty Merkle prefix has invalid cardinality".into(),
        ));
    }
    let elements_start = array_start
        .checked_add(32)
        .ok_or_else(|| EngineError::Unavailable("counterparty prefix offset overflow".into()))?;
    let heads_end = elements_start
        .checked_add(count * 32)
        .ok_or_else(|| EngineError::Unavailable("counterparty prefix size overflow".into()))?;
    if heads_end > encoded.len() {
        return Err(EngineError::Unavailable(
            "Router counterparty Merkle prefix is truncated".into(),
        ));
    }
    let mut prefix = Vec::with_capacity(count);
    for index in 0..count {
        let relative = abi_offset(
            encoded,
            elements_start + index * 32,
            "counterparty prefix entry",
        )?;
        let start = elements_start.checked_add(relative).ok_or_else(|| {
            EngineError::Unavailable("counterparty prefix entry offset overflow".into())
        })?;
        prefix.push(abi_dynamic_bytes(
            encoded,
            start,
            "counterparty prefix entry",
        )?);
    }
    Ok((client_id, prefix))
}

fn abi_offset(encoded: &[u8], start: usize, field: &str) -> Result<usize, EngineError> {
    let value = abi_usize(encoded, start, field)?;
    if value % 32 != 0 {
        return Err(EngineError::Unavailable(format!(
            "{field} ABI offset is not word-aligned"
        )));
    }
    Ok(value)
}

fn abi_usize(encoded: &[u8], start: usize, field: &str) -> Result<usize, EngineError> {
    let end = start
        .checked_add(32)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} ABI offset overflow")))?;
    let word = encoded
        .get(start..end)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} ABI word is truncated")))?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(format!(
            "{field} ABI value does not fit u64"
        )));
    }
    let value = u64::from_be_bytes(
        word[24..]
            .try_into()
            .map_err(|_| EngineError::Internal("decode ABI u64".into()))?,
    );
    usize::try_from(value)
        .map_err(|_| EngineError::Unavailable(format!("{field} does not fit this platform")))
}

fn abi_dynamic_bytes(encoded: &[u8], start: usize, field: &str) -> Result<Vec<u8>, EngineError> {
    let length = abi_usize(encoded, start, field)?;
    let data_start = start
        .checked_add(32)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} offset overflow")))?;
    let data_end = data_start
        .checked_add(length)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} length overflow")))?;
    let padded_end = data_start
        .checked_add(length.div_ceil(32) * 32)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} padded length overflow")))?;
    let value = encoded
        .get(data_start..data_end)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} data is truncated")))?;
    let padding = encoded
        .get(data_end..padded_end)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} padding is truncated")))?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(format!(
            "{field} has nonzero ABI padding"
        )));
    }
    Ok(value.to_vec())
}

fn call_word(
    rpc: &JsonRpcClient,
    target: [u8; 20],
    signature: &str,
    args: &[u8],
    block: u64,
) -> Result<[u8; 32], EngineError> {
    let bytes = call_bytes(rpc, target, signature, args, block)?;
    bytes.try_into().map_err(|_| {
        EngineError::Unavailable(format!("{signature} must return exactly one ABI word"))
    })
}

fn call_bytes(
    rpc: &JsonRpcClient,
    target: [u8; 20],
    signature: &str,
    args: &[u8],
    block: u64,
) -> Result<Vec<u8>, EngineError> {
    let mut data = Vec::with_capacity(4 + args.len());
    data.extend_from_slice(&Keccak256::digest(signature.as_bytes())[..4]);
    data.extend_from_slice(args);
    let result: String = rpc
        .call(
            "eth_call",
            &json!([{
                "to": format!("0x{}", hex::encode(target)),
                "data": format!("0x{}", hex::encode(data)),
            }, format!("0x{block:x}")]),
        )?
        .ok_or_else(|| EngineError::Unavailable(format!("{signature} returned null")))?;
    let body = result
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{signature} result lacks 0x prefix")))?;
    let bytes = hex::decode(body)
        .map_err(|_| EngineError::Unavailable(format!("{signature} returned invalid hex")))?;
    Ok(bytes)
}

fn address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

impl DestinationStateSource for DestinationLightClient {
    fn current_trust(&self) -> Result<TrustSnapshot, EngineError> {
        let block_number = destination_head(&self.rpc)?;
        if let Some(expected) = &self.expected {
            let client_id = self
                .client_id
                .as_deref()
                .ok_or_else(|| EngineError::Internal("destination client ID is missing".into()))?;
            let resolved =
                resolve_router_client(&self.rpc, expected.router, client_id, block_number)?;
            if resolved != self.address {
                return Err(EngineError::Unavailable(
                    "Router client mapping changed while the Proof API was running".into(),
                ));
            }
            self.validate_identity_at(expected, block_number)?;
            self.validate_counterparty_at(expected, block_number)?;
        }
        read_trust_snapshot_at(&self.rpc, self.address, block_number)
    }
}

fn read_trust_snapshot(
    rpc: &JsonRpcClient,
    light_client_address: [u8; 20],
) -> Result<TrustSnapshot, EngineError> {
    let block_number = destination_head(rpc)?;
    read_trust_snapshot_at(rpc, light_client_address, block_number)
}

fn read_trust_snapshot_at(
    rpc: &JsonRpcClient,
    light_client_address: [u8; 20],
    block_number: u64,
) -> Result<TrustSnapshot, EngineError> {
    let selector = &Keccak256::digest(b"getConsensusTrustState()")[..4];
    let result: String = rpc
        .call(
            "eth_call",
            &json!([
                {
                    "to": format!("0x{}", hex::encode(light_client_address)),
                    "data": format!("0x{}", hex::encode(selector)),
                },
                format!("0x{block_number:x}")
            ]),
        )?
        .ok_or_else(|| EngineError::Unavailable("destination eth_call returned null".into()))?;
    let (encoded, state) = decode_trust_state(&result)?;
    Ok(TrustSnapshot {
        block_number,
        digest: Keccak256::digest(encoded).into(),
        state,
    })
}

pub trait TrustUpdateRegistrar: Send + Sync + 'static {
    fn register_trust_update(
        &self,
        update_envelope: &[u8],
        expected_before: &TrustSnapshot,
        expected_after: &TrustSnapshot,
    ) -> Result<(), EngineError>;
}

impl TrustUpdateRegistrar for () {
    fn register_trust_update(
        &self,
        _: &[u8],
        _: &TrustSnapshot,
        _: &TrustSnapshot,
    ) -> Result<(), EngineError> {
        Err(EngineError::Internal(
            "trust-update registrar is not configured".into(),
        ))
    }
}

#[derive(Clone)]
pub struct DestinationTrustUpdateRegistrar {
    inner: Arc<DestinationTrustUpdateRegistrarInner>,
}

struct DestinationTrustUpdateRegistrarInner {
    rpc: JsonRpcClient,
    light_client_address: [u8; 20],
    router_address: [u8; 20],
    client_id: String,
    signer: PrivateKeySigner,
    config: ResolvedTrustUpdateRegistrar,
    transaction_lock: Mutex<()>,
}

impl DestinationTrustUpdateRegistrar {
    pub fn new(
        rpc: JsonRpcClient,
        light_client_address: [u8; 20],
        router_address: [u8; 20],
        client_id: String,
        config: ResolvedTrustUpdateRegistrar,
    ) -> Result<Self, EngineError> {
        let signer = config
            .private_key
            .parse::<PrivateKeySigner>()
            .map_err(|_| {
                EngineError::Internal(
                    "destination trust-update signer private key is invalid".into(),
                )
            })?;
        let actual_chain_id = rpc
            .call::<String>("eth_chainId", &json!([]))?
            .ok_or_else(|| EngineError::Unavailable("destination eth_chainId returned null".into()))
            .and_then(|value| parse_quantity("destination eth_chainId", &value))?;
        if actual_chain_id != config.chain_id {
            return Err(EngineError::Unavailable(format!(
                "destination chain ID {actual_chain_id} does not match configured {}",
                config.chain_id
            )));
        }
        require_router_update_permission(&rpc, router_address, signer.address().into_array())?;
        let balance = rpc
            .call::<String>(
                "eth_getBalance",
                &json!([format!("0x{}", hex::encode(signer.address())), "latest"]),
            )?
            .ok_or_else(|| EngineError::Unavailable("destination balance returned null".into()))?;
        if parse_u128_quantity("destination trust-update signer balance", &balance)? == 0 {
            let gas_price = rpc
                .call::<String>("eth_gasPrice", &json!([]))?
                .ok_or_else(|| {
                    EngineError::Unavailable("destination gas price returned null".into())
                })?;
            if parse_u128_quantity("destination gas price", &gas_price)? != 0 {
                return Err(EngineError::Unavailable(
                    "destination trust-update signer has zero balance on a nonzero-gas chain"
                        .into(),
                ));
            }
        }
        Ok(Self {
            inner: Arc::new(DestinationTrustUpdateRegistrarInner {
                rpc,
                light_client_address,
                router_address,
                client_id,
                signer,
                config,
                transaction_lock: Mutex::new(()),
            }),
        })
    }

    fn submit_transaction(
        &self,
        target: [u8; 20],
        calldata: Vec<u8>,
        operation: &str,
    ) -> Result<(), EngineError> {
        let signer_address = self.inner.signer.address();
        let from = format!("0x{}", hex::encode(signer_address));
        let to = format!("0x{}", hex::encode(target));
        let data = format!("0x{}", hex::encode(&calldata));
        let nonce = self
            .inner
            .rpc
            .call::<String>("eth_getTransactionCount", &json!([from, "pending"]))?
            .ok_or_else(|| EngineError::Unavailable("destination nonce returned null".into()))
            .and_then(|value| parse_quantity("destination nonce", &value))?;
        let gas_price = self
            .inner
            .rpc
            .call::<String>("eth_gasPrice", &json!([]))?
            .ok_or_else(|| EngineError::Unavailable("destination gas price returned null".into()))
            .and_then(|value| parse_u128_quantity("destination gas price", &value))?;
        let estimate = self
            .inner
            .rpc
            .call::<String>(
                "eth_estimateGas",
                &json!([{"from": from, "to": to, "data": data, "value": "0x0"}]),
            )?
            .ok_or_else(|| {
                EngineError::Unavailable("destination gas estimate returned null".into())
            })
            .and_then(|value| parse_quantity("destination gas estimate", &value))?;
        let gas_limit = estimate
            .checked_mul(6)
            .and_then(|value| value.checked_div(5))
            .and_then(|value| value.checked_add(50_000))
            .ok_or_else(|| EngineError::Internal("destination gas estimate overflow".into()))?;
        if gas_limit > self.inner.config.max_gas {
            return Err(EngineError::Unavailable(format!(
                "{operation} gas {gas_limit} exceeds configured maximum {}",
                self.inner.config.max_gas
            )));
        }
        let transaction = TxLegacy {
            chain_id: Some(self.inner.config.chain_id),
            nonce,
            gas_price,
            gas_limit,
            to: TxKind::Call(Address::from(target)),
            value: U256::ZERO,
            input: Bytes::from(calldata),
        };
        let signature = self
            .inner
            .signer
            .sign_hash_sync(&transaction.signature_hash())
            .map_err(|error| EngineError::Internal(format!("sign {operation}: {error}")))?;
        let mut raw = Vec::with_capacity(transaction.rlp_encoded_length_with_signature(&signature));
        transaction.rlp_encode_signed(&signature, &mut raw);
        let expected_hash: [u8; 32] = Keccak256::digest(&raw).into();
        let returned_hash = self
            .inner
            .rpc
            .call::<String>(
                "eth_sendRawTransaction",
                &json!([format!("0x{}", hex::encode(&raw))]),
            )?
            .ok_or_else(|| {
                EngineError::Unavailable("destination send transaction returned null".into())
            })?;
        if decode_fixed_hex::<32>("destination transaction hash", &returned_hash)? != expected_hash
        {
            return Err(EngineError::Unavailable(
                "destination returned a different transaction hash".into(),
            ));
        }
        self.wait_for_receipt(expected_hash, operation)
    }

    fn wait_for_receipt(
        &self,
        transaction_hash: [u8; 32],
        operation: &str,
    ) -> Result<(), EngineError> {
        let started = Instant::now();
        let hash = format!("0x{}", hex::encode(transaction_hash));
        loop {
            if started.elapsed() >= self.inner.config.receipt_timeout {
                return Err(EngineError::Unavailable(format!(
                    "{operation} transaction {hash} timed out"
                )));
            }
            if let Some(receipt) = self
                .inner
                .rpc
                .call::<DestinationReceipt>("eth_getTransactionReceipt", &json!([hash]))?
            {
                if decode_fixed_hex::<32>("receipt transactionHash", &receipt.transaction_hash)?
                    != transaction_hash
                {
                    return Err(EngineError::Unavailable(
                        "destination receipt transaction hash mismatch".into(),
                    ));
                }
                return match parse_quantity("destination receipt status", &receipt.status)? {
                    1 => Ok(()),
                    0 => Err(EngineError::Backend(format!(
                        "{operation} transaction reverted"
                    ))),
                    _ => Err(EngineError::Unavailable(
                        "destination receipt status is not boolean".into(),
                    )),
                };
            }
            std::thread::sleep(self.inner.config.receipt_poll_interval);
        }
    }
}

fn require_router_update_permission(
    rpc: &JsonRpcClient,
    router: [u8; 20],
    signer: [u8; 20],
) -> Result<(), EngineError> {
    let block = destination_head(rpc)?;
    let authority_word = call_word(rpc, router, "authority()", &[], block)?;
    if authority_word[..12].iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(
            "Router authority returned a noncanonical address".into(),
        ));
    }
    let authority: [u8; 20] = authority_word[12..]
        .try_into()
        .map_err(|_| EngineError::Internal("decode Router authority".into()))?;
    if authority == [0; 20] {
        return Err(EngineError::Unavailable(
            "Router authority returned the zero address".into(),
        ));
    }
    let mut args = Vec::with_capacity(96);
    args.extend_from_slice(&address_word(signer));
    args.extend_from_slice(&address_word(router));
    let mut selector_word = [0_u8; 32];
    selector_word[..4].copy_from_slice(&Keccak256::digest(b"updateClient(string,bytes)")[..4]);
    args.extend_from_slice(&selector_word);
    let result = call_bytes(
        rpc,
        authority,
        "canCall(address,address,bytes4)",
        &args,
        block,
    )?;
    if result.len() != 64 || !decode_bool_word("Router updateClient permission", &result[..32])? {
        return Err(EngineError::Unavailable(
            "destination trust-update signer is not authorized for Router updateClient".into(),
        ));
    }
    Ok(())
}

impl TrustUpdateRegistrar for DestinationTrustUpdateRegistrar {
    fn register_trust_update(
        &self,
        update_envelope: &[u8],
        expected_before: &TrustSnapshot,
        expected_after: &TrustSnapshot,
    ) -> Result<(), EngineError> {
        let _guard = self.inner.transaction_lock.lock().map_err(|_| {
            EngineError::Internal("destination trust-update signer lock was poisoned".into())
        })?;
        let current = read_trust_snapshot(&self.inner.rpc, self.inner.light_client_address)?;
        if current.digest == expected_after.digest {
            return Ok(());
        }
        if current.digest != expected_before.digest {
            return Err(EngineError::Unavailable(
                "destination trust changed before automatic catch-up; retry".into(),
            ));
        }
        let calldata = router_update_client_calldata(&self.inner.client_id, update_envelope)?;
        self.submit_transaction(
            self.inner.router_address,
            calldata,
            "automatic trust update",
        )?;
        let stored = read_trust_snapshot(&self.inner.rpc, self.inner.light_client_address)?;
        if stored.digest != expected_after.digest {
            return Err(EngineError::Unavailable(
                "automatic trust-update receipt succeeded but destination trust is unexpected"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DestinationReceipt {
    transaction_hash: String,
    status: String,
}

fn router_update_client_calldata(
    client_id: &str,
    update_envelope: &[u8],
) -> Result<Vec<u8>, EngineError> {
    if client_id.is_empty() || update_envelope.is_empty() {
        return Err(EngineError::Internal(
            "Router updateClient requires a client ID and update envelope".into(),
        ));
    }
    let client = client_id.as_bytes();
    let client_padded = client
        .len()
        .checked_add(31)
        .map(|value| value / 32 * 32)
        .ok_or_else(|| EngineError::Internal("client ID ABI length overflow".into()))?;
    let update_padded = update_envelope
        .len()
        .checked_add(31)
        .map(|value| value / 32 * 32)
        .ok_or_else(|| EngineError::Internal("update ABI length overflow".into()))?;
    let update_offset = 96_usize
        .checked_add(client_padded)
        .ok_or_else(|| EngineError::Internal("Router update offset overflow".into()))?;
    let capacity = 4_usize
        .checked_add(update_offset)
        .and_then(|value| value.checked_add(32 + update_padded))
        .ok_or_else(|| EngineError::Internal("Router calldata length overflow".into()))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&Keccak256::digest(b"updateClient(string,bytes)")[..4]);
    push_usize_word(&mut output, 64)?;
    push_usize_word(&mut output, update_offset)?;
    push_usize_word(&mut output, client.len())?;
    output.extend_from_slice(client);
    output.resize(4 + update_offset, 0);
    push_usize_word(&mut output, update_envelope.len())?;
    output.extend_from_slice(update_envelope);
    output.resize(capacity, 0);
    Ok(output)
}

fn parse_u128_quantity(field: &str, value: &str) -> Result<u128, EngineError> {
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
    u128::from_str_radix(body, 16)
        .map_err(|_| EngineError::Unavailable(format!("{field} exceeds u128")))
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    if body.len() % 2 != 0 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError::Unavailable(format!("{field} is invalid hex")));
    }
    hex::decode(body).map_err(|_| EngineError::Unavailable(format!("{field} is invalid hex")))
}

fn decode_fixed_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], EngineError> {
    decode_hex(field, value)?
        .try_into()
        .map_err(|_| EngineError::Unavailable(format!("{field} must be {N} bytes")))
}

fn push_usize_word(output: &mut Vec<u8>, value: usize) -> Result<(), EngineError> {
    let value =
        u64::try_from(value).map_err(|_| EngineError::Internal("ABI value exceeds u64".into()))?;
    output.extend_from_slice(&[0_u8; 24]);
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

pub(crate) fn consensus_trust_digest(state: &ConsensusTrustState) -> [u8; 32] {
    let mut encoded = [0_u8; TRUST_STATE_BYTES];
    encoded[24..32].copy_from_slice(&state.finalized_beacon_slot.to_be_bytes());
    encoded[32..64].copy_from_slice(&state.finalized_beacon_header_root);
    encoded[64..96].copy_from_slice(&state.current_sync_committee_root);
    encoded[96..128].copy_from_slice(&state.next_sync_committee_root);
    encoded[159] = u8::from(state.next_sync_committee_known);
    Keccak256::digest(encoded).into()
}

fn destination_head(rpc: &JsonRpcClient) -> Result<u64, EngineError> {
    let head: String = rpc.call("eth_blockNumber", &json!([]))?.ok_or_else(|| {
        EngineError::Unavailable("destination eth_blockNumber returned null".into())
    })?;
    parse_quantity("destination eth_blockNumber", &head)
}

fn decode_trust_state(
    value: &str,
) -> Result<([u8; TRUST_STATE_BYTES], ConsensusTrustState), EngineError> {
    let body = value.strip_prefix("0x").ok_or_else(|| {
        EngineError::Unavailable("destination trust state lacks 0x prefix".into())
    })?;
    let bytes = hex::decode(body)
        .map_err(|_| EngineError::Unavailable("destination trust state is invalid hex".into()))?;
    let encoded: [u8; TRUST_STATE_BYTES] = bytes.try_into().map_err(|_| {
        EngineError::Unavailable(format!(
            "destination trust state must be exactly {TRUST_STATE_BYTES} bytes"
        ))
    })?;

    let finalized_slot = decode_u64_word("finalized Beacon slot", &encoded[0..32])?;
    if finalized_slot == 0
        || encoded[32..64].iter().all(|byte| *byte == 0)
        || encoded[64..96].iter().all(|byte| *byte == 0)
    {
        return Err(EngineError::Unavailable(
            "destination trust state contains zero required fields".into(),
        ));
    }
    let next_known = decode_bool_word("next sync committee known", &encoded[128..160])?;
    let next_root_is_zero = encoded[96..128].iter().all(|byte| *byte == 0);
    if next_known == next_root_is_zero {
        return Err(EngineError::Unavailable(
            "destination trust state has inconsistent next-committee fields".into(),
        ));
    }
    let state = ConsensusTrustState {
        finalized_beacon_slot: finalized_slot,
        finalized_beacon_header_root: word(&encoded[32..64]),
        current_sync_committee_root: word(&encoded[64..96]),
        next_sync_committee_root: word(&encoded[96..128]),
        next_sync_committee_known: next_known,
    };
    Ok((encoded, state))
}

fn word(bytes: &[u8]) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word.copy_from_slice(bytes);
    word
}

fn decode_u64_word(field: &str, word: &[u8]) -> Result<u64, EngineError> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(format!(
            "destination {field} is not a canonical u64"
        )));
    }
    let mut value = [0_u8; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn decode_bool_word(field: &str, word: &[u8]) -> Result<bool, EngineError> {
    if word.len() != 32 || word[..31].iter().any(|byte| *byte != 0) {
        return Err(EngineError::Unavailable(format!(
            "destination {field} is not a canonical bool"
        )));
    }
    match word[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(EngineError::Unavailable(format!(
            "destination {field} is not a canonical bool"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::ResolvedRpc;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    fn rpc(responses: Vec<String>) -> JsonRpcClient {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for result in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 8192];
                let _ = stream.read(&mut request).unwrap();
                let body = json!({"jsonrpc":"2.0", "id":1, "result":result}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        JsonRpcClient::new(
            &ResolvedRpc {
                url: url::Url::parse(&format!("http://{address}/")).unwrap(),
                chain_id: 1337,
                authorization: None,
                max_response_bytes: 64 * 1024,
                max_batch_lookback: 0,
            },
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn rpc_handler(
        requests: usize,
        handler: impl FnMut(serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> JsonRpcClient {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let mut handler = handler;
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 8192];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if read < buffer.len() {
                        break;
                    }
                }
                let body_start = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .unwrap();
                let rpc_request: serde_json::Value =
                    serde_json::from_slice(&request[body_start..]).unwrap();
                let result = handler(rpc_request);
                let body = json!({"jsonrpc":"2.0", "id":1, "result":result}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        JsonRpcClient::new(
            &ResolvedRpc {
                url: url::Url::parse(&format!("http://{address}/")).unwrap(),
                chain_id: 1337,
                authorization: None,
                max_response_bytes: 64 * 1024,
                max_batch_lookback: 0,
            },
            Duration::from_secs(2),
        )
        .unwrap()
    }

    fn hex_word(value: [u8; 32]) -> String {
        format!("0x{}", hex::encode(value))
    }

    fn counterparty() -> String {
        let mut encoded = vec![0_u8; 256];
        encoded[31] = 32;
        encoded[63] = 64;
        encoded[95] = 128;
        encoded[127] = 8;
        encoded[128..136].copy_from_slice(b"client-0");
        encoded[191] = 1;
        encoded[223] = 32;
        format!("0x{}", hex::encode(encoded))
    }

    fn encoded_state(next_known: bool) -> [u8; TRUST_STATE_BYTES] {
        let mut encoded = [0_u8; TRUST_STATE_BYTES];
        encoded[24..32].copy_from_slice(&7_u64.to_be_bytes());
        encoded[32..64].fill(0x11);
        encoded[64..96].fill(0x22);
        if next_known {
            encoded[96..128].fill(0x33);
            encoded[159] = 1;
        }
        encoded
    }

    #[test]
    fn trust_state_digest_matches_exact_solidity_static_encoding() {
        let encoded = encoded_state(true);
        let value = format!("0x{}", hex::encode(encoded));
        let (_, state) = decode_trust_state(&value).unwrap();
        let digest: [u8; 32] = Keccak256::digest(encoded).into();
        assert_eq!(consensus_trust_digest(&state), digest);
    }

    #[test]
    fn rejects_noncanonical_or_inconsistent_trust_state() {
        let mut dirty_slot = encoded_state(false);
        dirty_slot[0] = 1;
        assert!(decode_trust_state(&format!("0x{}", hex::encode(dirty_slot))).is_err());

        let mut dirty_bool = encoded_state(false);
        dirty_bool[159] = 2;
        assert!(decode_trust_state(&format!("0x{}", hex::encode(dirty_bool))).is_err());

        let mut inconsistent = encoded_state(false);
        inconsistent[96..128].fill(0x33);
        assert!(decode_trust_state(&format!("0x{}", hex::encode(inconsistent))).is_err());
    }

    #[test]
    fn counterparty_abi_decoder_is_strict() {
        let mut encoded = vec![0_u8; 256];
        encoded[31] = 32;
        encoded[63] = 64;
        encoded[95] = 128;
        encoded[127] = 8;
        encoded[128..136].copy_from_slice(b"client-0");
        encoded[191] = 1;
        encoded[223] = 32;
        let decoded = decode_counterparty(&encoded);
        assert_eq!(decoded, Ok(("client-0".into(), vec![Vec::new()])));

        encoded[255] = 1;
        assert!(decode_counterparty(&encoded).is_err());
    }

    #[test]
    fn router_update_client_calldata_uses_canonical_dynamic_offsets() {
        let calldata = router_update_client_calldata("client-0", &[0xaa, 0xbb]).unwrap();
        assert_eq!(
            &calldata[..4],
            &Keccak256::digest(b"updateClient(string,bytes)")[..4]
        );
        assert_eq!(&calldata[28..36], &64_u64.to_be_bytes());
        assert_eq!(&calldata[60..68], &128_u64.to_be_bytes());
        assert_eq!(&calldata[92..100], &8_u64.to_be_bytes());
        assert_eq!(&calldata[100..108], b"client-0");
        assert_eq!(&calldata[156..164], &2_u64.to_be_bytes());
        assert_eq!(&calldata[164..166], &[0xaa, 0xbb]);
        assert!(router_update_client_calldata("", &[1]).is_err());
        assert!(router_update_client_calldata("client-0", &[]).is_err());
    }

    #[test]
    fn registrar_requires_immediate_router_update_permission() {
        let router = [0x11; 20];
        let authority = [0x22; 20];
        let registrar = [0x33; 20];
        let mut allowed = [0_u8; 64];
        allowed[31] = 1;
        assert!(require_router_update_permission(
            &rpc(vec![
                "0xa".into(),
                hex_word(address_word(authority)),
                format!("0x{}", hex::encode(allowed)),
            ]),
            router,
            registrar,
        )
        .is_ok());

        assert!(require_router_update_permission(
            &rpc(vec![
                "0xa".into(),
                hex_word(address_word(authority)),
                format!("0x{}", hex::encode([0_u8; 64])),
            ]),
            router,
            registrar,
        )
        .is_err());
    }

    #[test]
    fn router_resolution_validates_all_deployed_identity_bindings() {
        let router = [0x11; 20];
        let light_client = [0x22; 20];
        let store = [0x33; 20];
        let verifier = [0x44; 20];
        let vkeys = [[0x51; 32], [0x52; 32], [0x53; 32], [0x54; 32]];
        let expected = ExpectedIdentity {
            router,
            source_profile_id: [0x50; 32],
            ibc_store: store,
            absence_profile_id: 1,
            verifier,
            vkeys,
            counterparty_client_id: "client-0".into(),
            counterparty_merkle_prefix: vec![vec![]],
        };
        let mut responses = vec!["0xa".into(), hex_word(address_word(light_client))];
        responses.extend([
            hex_word(expected.source_profile_id),
            hex_word(vkeys[0]),
            hex_word(vkeys[1]),
            hex_word(vkeys[2]),
            hex_word(vkeys[3]),
            hex_word(address_word(store)),
            hex_word(address_word(verifier)),
            hex_word(address_word(router)),
            hex_word({
                let mut word = [0_u8; 32];
                word[31] = 1;
                word
            }),
            counterparty(),
        ]);
        let client =
            DestinationLightClient::resolve_and_validate(rpc(responses), "6565", &expected)
                .unwrap();
        assert_eq!(client.address, light_client);
    }

    #[test]
    fn abi_and_trust_helpers_reject_malformed_values() {
        assert_eq!(encode_string_argument("client-0").unwrap().len(), 96);
        assert!(decode_counterparty(&[]).is_err());
        let mut noncanonical = vec![0_u8; 32];
        noncanonical[0] = 1;
        assert!(abi_usize(&noncanonical, 0, "value").is_err());
        let mut unaligned = vec![0_u8; 32];
        unaligned[31] = 1;
        assert!(abi_offset(&unaligned, 0, "offset").is_err());
        assert!(abi_dynamic_bytes(&[0_u8; 31], 0, "bytes").is_err());
        assert_eq!(address_word([1; 20])[12..], [1; 20]);
        assert!(decode_trust_state("missing-prefix").is_err());
        assert!(decode_trust_state("0xzz").is_err());
        assert!(decode_u64_word("slot", &[0_u8; 31]).is_err());
        assert!(decode_bool_word("known", &[0_u8; 31]).is_err());
    }

    #[test]
    fn current_trust_reads_and_hashes_one_destination_snapshot() {
        let encoded = encoded_state(false);
        let client = DestinationLightClient {
            rpc: rpc(vec!["0xb".into(), format!("0x{}", hex::encode(encoded))]),
            address: [0x22; 20],
            expected: None,
            client_id: None,
        };
        let trust = client.current_trust().unwrap();
        assert_eq!(trust.block_number, 11);
        assert_eq!(trust.state.finalized_beacon_slot, 7);
        assert_eq!(trust.digest, <[u8; 32]>::from(Keccak256::digest(encoded)));
    }

    #[test]
    fn registrar_signs_waits_and_confirms_the_trust_transition() {
        let router = [0x11; 20];
        let light_client = [0x22; 20];
        let authority = [0x33; 20];
        let before_encoded = encoded_state(false);
        let after_encoded = encoded_state(true);
        let (_, before_state) =
            decode_trust_state(&format!("0x{}", hex::encode(before_encoded))).unwrap();
        let (_, after_state) =
            decode_trust_state(&format!("0x{}", hex::encode(after_encoded))).unwrap();
        let before = TrustSnapshot {
            block_number: 9,
            digest: Keccak256::digest(before_encoded).into(),
            state: before_state,
        };
        let after = TrustSnapshot {
            block_number: 10,
            digest: Keccak256::digest(after_encoded).into(),
            state: after_state,
        };
        let sent_hash = Arc::new(Mutex::new(None::<[u8; 32]>));
        let handler_hash = Arc::clone(&sent_hash);
        let mut trust_reads = 0_usize;
        let rpc = rpc_handler(14, move |request| {
            let method = request["method"].as_str().unwrap();
            match method {
                "eth_chainId" => json!("0x539"),
                "eth_blockNumber" => json!("0xa"),
                "eth_getBalance" => json!("0x1"),
                "eth_getTransactionCount" | "eth_gasPrice" => json!("0x0"),
                "eth_estimateGas" => json!("0x186a0"),
                "eth_sendRawTransaction" => {
                    let raw = request["params"][0].as_str().unwrap();
                    let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
                    let hash: [u8; 32] = Keccak256::digest(bytes).into();
                    *handler_hash.lock().unwrap() = Some(hash);
                    json!(format!("0x{}", hex::encode(hash)))
                }
                "eth_getTransactionReceipt" => {
                    let hash = handler_hash.lock().unwrap().unwrap();
                    json!({
                        "transactionHash": format!("0x{}", hex::encode(hash)),
                        "status": "0x1"
                    })
                }
                "eth_call" => {
                    let data = request["params"][0]["data"].as_str().unwrap();
                    let selector = &data[..10];
                    let authority_selector =
                        format!("0x{}", hex::encode(&Keccak256::digest(b"authority()")[..4]));
                    let can_call_selector = format!(
                        "0x{}",
                        hex::encode(&Keccak256::digest(b"canCall(address,address,bytes4)")[..4])
                    );
                    if selector == authority_selector {
                        json!(hex_word(address_word(authority)))
                    } else if selector == can_call_selector {
                        let mut allowed = [0_u8; 64];
                        allowed[31] = 1;
                        json!(format!("0x{}", hex::encode(allowed)))
                    } else {
                        trust_reads += 1;
                        let state = if trust_reads == 1 {
                            before_encoded
                        } else {
                            after_encoded
                        };
                        json!(format!("0x{}", hex::encode(state)))
                    }
                }
                _ => json!(null),
            }
        });
        let registrar = DestinationTrustUpdateRegistrar::new(
            rpc,
            light_client,
            router,
            "6565".into(),
            ResolvedTrustUpdateRegistrar {
                private_key: format!("0x{}", "11".repeat(32)),
                chain_id: 1337,
                receipt_timeout: Duration::from_secs(2),
                receipt_poll_interval: Duration::ZERO,
                max_gas: 1_000_000,
            },
        )
        .unwrap();

        registrar
            .register_trust_update(&[0xaa, 0xbb], &before, &after)
            .unwrap();
        assert!(sent_hash.lock().unwrap().is_some());
    }

    #[test]
    fn registrar_configuration_and_receipts_fail_closed() {
        let config = ResolvedTrustUpdateRegistrar {
            private_key: "not-a-key".into(),
            chain_id: 1337,
            receipt_timeout: Duration::from_millis(1),
            receipt_poll_interval: Duration::ZERO,
            max_gas: 100_000,
        };
        assert!(DestinationTrustUpdateRegistrar::new(
            rpc(Vec::new()),
            [1; 20],
            [2; 20],
            "6565".into(),
            config,
        )
        .is_err());

        assert!(parse_u128_quantity("value", "1").is_err());
        assert!(parse_u128_quantity("value", "0x00").is_err());
        assert!(parse_u128_quantity("value", "0xgg").is_err());
        assert!(decode_hex("value", "01").is_err());
        assert!(decode_hex("value", "0x0").is_err());
        assert!(decode_fixed_hex::<2>("value", "0x01").is_err());
        assert!(TrustUpdateRegistrar::register_trust_update(
            &(),
            &[],
            &TrustSnapshot {
                block_number: 0,
                digest: [0; 32],
                state: ConsensusTrustState {
                    finalized_beacon_slot: 0,
                    finalized_beacon_header_root: [0; 32],
                    current_sync_committee_root: [0; 32],
                    next_sync_committee_root: [0; 32],
                    next_sync_committee_known: false,
                },
            },
            &TrustSnapshot {
                block_number: 0,
                digest: [0; 32],
                state: ConsensusTrustState {
                    finalized_beacon_slot: 0,
                    finalized_beacon_header_root: [0; 32],
                    current_sync_committee_root: [0; 32],
                    next_sync_committee_root: [0; 32],
                    next_sync_committee_known: false,
                },
            },
        )
        .is_err());
    }
}
