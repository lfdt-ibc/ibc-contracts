// SPDX-License-Identifier: Apache-2.0

//! Client for the beacon API of Maru, Linea's consensus client, and the RLP encodings its QBFT
//! validators sign.
//!
//! The encodings mirror Maru's RLP serializers:
//! <https://github.com/Consensys/linea-monorepo/tree/main/maru/serialization/src/main/kotlin/maru/serialization/rlp>

use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, ensure, Context, Result};
use rlp::RlpStream;
use serde::{de::DeserializeOwned, Deserialize, Deserializer};

/// How often and how long to poll for a beacon block that the execution client already has.
const HEAD_POLL_INTERVAL: Duration = Duration::from_millis(500);
const HEAD_POLL_ATTEMPTS: usize = 20;

/// A Maru beacon block header.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    #[serde(rename = "slot", deserialize_with = "decimal")]
    pub number: u64,
    #[serde(deserialize_with = "decimal")]
    pub round: u32,
    #[serde(deserialize_with = "decimal")]
    pub timestamp: u64,
    #[serde(rename = "proposer_index")]
    pub proposer: Address,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

/// The execution payload carried by a Maru beacon block body.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ExecutionPayload {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bytes,
    pub prev_randao: B256,
    #[serde(deserialize_with = "decimal")]
    pub block_number: u64,
    #[serde(deserialize_with = "decimal")]
    pub gas_limit: u64,
    #[serde(deserialize_with = "decimal")]
    pub gas_used: u64,
    #[serde(deserialize_with = "decimal")]
    pub timestamp: u64,
    pub extra_data: Bytes,
    #[serde(deserialize_with = "decimal")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions: Vec<Bytes>,
}

/// A Maru beacon block with the commit seals of its QBFT validators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBeaconBlock {
    pub header: BeaconBlockHeader,
    /// The commit seals of the parent block, which are part of the body.
    pub prev_commit_seals: Vec<Bytes>,
    pub execution_payload: ExecutionPayload,
    /// The commit seals over the header hash, as Maru stores them.
    pub commit_seals: Vec<Bytes>,
}

#[derive(Deserialize)]
struct Response<T> {
    data: T,
}

#[derive(Deserialize)]
struct Message<T> {
    message: T,
}

#[derive(Deserialize)]
struct ApiBlock {
    #[serde(deserialize_with = "decimal")]
    slot: u64,
    body: ApiBlockBody,
}

#[derive(Deserialize)]
struct ApiBlockBody {
    attestations: Vec<ApiAttestation>,
    execution_payload: ExecutionPayload,
}

/// Maru reports commit seals as attestations: the ones of the block itself followed by the ones of
/// its parent, which the block body carries.
#[derive(Deserialize)]
struct ApiAttestation {
    data: ApiAttestationData,
    signature: Bytes,
}

#[derive(Deserialize)]
struct ApiAttestationData {
    #[serde(deserialize_with = "decimal")]
    slot: u64,
}

#[derive(Deserialize)]
struct ApiValidator {
    validator: ApiValidatorData,
}

#[derive(Deserialize)]
struct ApiValidatorData {
    pubkey: Address,
}

fn decimal<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

impl BeaconBlockHeader {
    /// The header hash, which is the digest the commit seals sign.
    pub fn hash(&self) -> B256 {
        keccak256(self.rlp(&self.state_root))
    }

    /// The beacon state root a header with `validators` must carry.
    ///
    /// The beacon state is `[header, validators]`, where the header has a zero state root, so the
    /// header state root commits to the validator set of its block.
    pub fn compute_state_root(&self, validators: &[Address]) -> B256 {
        let mut stream = RlpStream::new_list(2);
        stream.append_raw(&self.rlp(&B256::ZERO), 1);
        stream.begin_list(validators.len());
        for validator in validators {
            stream.begin_list(1).append(&validator.as_slice());
        }
        keccak256(stream.out())
    }

    /// Encodes the header with `state_root`. Maru writes integers as fixed-width byte strings.
    fn rlp(&self, state_root: &B256) -> Vec<u8> {
        let mut stream = RlpStream::new_list(7);
        stream
            .append(&self.number.to_be_bytes().as_slice())
            .append(&self.round.to_be_bytes().as_slice())
            .append(&self.timestamp.to_be_bytes().as_slice());
        stream.begin_list(1).append(&self.proposer.as_slice());
        stream
            .append(&self.parent_root.as_slice())
            .append(&state_root.as_slice())
            .append(&self.body_root.as_slice());
        stream.out().to_vec()
    }
}

impl SealedBeaconBlock {
    /// Builds a sealed block from the header and block responses of the beacon API.
    fn from_api(header: BeaconBlockHeader, block: ApiBlock) -> Result<Self> {
        ensure!(
            header.number == block.slot,
            "beacon header {} does not belong to beacon block {}",
            header.number,
            block.slot
        );
        let (commit_seals, prev_commit_seals) = block
            .body
            .attestations
            .into_iter()
            .partition::<Vec<_>, _>(|attestation| attestation.data.slot == block.slot);
        let sealed = Self {
            header,
            prev_commit_seals: prev_commit_seals.into_iter().map(|a| a.signature).collect(),
            execution_payload: block.body.execution_payload,
            commit_seals: commit_seals.into_iter().map(|a| a.signature).collect(),
        };

        let body_root = keccak256(sealed.body_rlp());
        ensure!(
            body_root == sealed.header.body_root,
            "rebuilt body of beacon block {} hashes to {body_root}, expected {}",
            sealed.header.number,
            sealed.header.body_root
        );
        Ok(sealed)
    }

    /// Encodes the body `[prevCommitSeals, executionPayload]`, which hashes to the header body
    /// root. Maru writes integers as fixed-width byte strings.
    pub fn body_rlp(&self) -> Bytes {
        let payload = &self.execution_payload;
        let mut stream = RlpStream::new_list(2);
        stream.begin_list(self.prev_commit_seals.len());
        for seal in &self.prev_commit_seals {
            stream.begin_list(1).append(&seal.as_ref());
        }
        stream
            .begin_list(14)
            .append(&payload.parent_hash.as_slice())
            .append(&payload.fee_recipient.as_slice())
            .append(&payload.state_root.as_slice())
            .append(&payload.receipts_root.as_slice())
            .append(&payload.logs_bloom.as_ref())
            .append(&payload.prev_randao.as_slice())
            .append(&payload.block_number.to_be_bytes().as_slice())
            .append(&payload.gas_limit.to_be_bytes().as_slice())
            .append(&payload.gas_used.to_be_bytes().as_slice())
            .append(&payload.timestamp.to_be_bytes().as_slice())
            .append(&payload.extra_data.as_ref())
            .append(&java_big_integer_bytes(payload.base_fee_per_gas))
            .append(&payload.block_hash.as_slice());
        stream.begin_list(payload.transactions.len());
        for transaction in &payload.transactions {
            stream.append(&transaction.as_ref());
        }
        stream.out().to_vec().into()
    }
}

/// Encodes `value` as Java's `BigInteger.toByteArray` does: minimal big-endian two's complement,
/// so zero is one zero byte and values with the top bit set get a leading zero byte.
fn java_big_integer_bytes(value: U256) -> Vec<u8> {
    let mut bytes = value.to_be_bytes_trimmed_vec();
    if bytes.first().is_none_or(|byte| byte & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

/// A client for the beacon API of a Maru node.
pub struct MaruApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl MaruApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Fetches the sealed beacon block `block_id`, which is `head` or a beacon block number.
    pub async fn sealed_block(&self, block_id: &str) -> Result<SealedBeaconBlock> {
        let block: Response<Message<ApiBlock>> = self
            .get(&format!("/eth/v2/beacon/blocks/{block_id}"))
            .await?;
        let block = block.data.message;
        // The block response lacks the round, timestamp and body root of the header.
        let header: Response<Message<BeaconBlockHeader>> = self
            .get(&format!("/eth/v1/beacon/headers/{}", block.slot))
            .await?;
        SealedBeaconBlock::from_api(header.data.message, block)
    }

    /// Fetches the sealed beacon block that carries the execution block `execution_number`.
    pub async fn sealed_block_at(&self, execution_number: u64) -> Result<SealedBeaconBlock> {
        let head = self.sealed_block("head").await?;
        let head_execution_number = head.execution_payload.block_number;
        if execution_number == head_execution_number {
            return Ok(head);
        }

        // Every beacon block carries the next execution block, so the two numbers advance together.
        let number = head_execution_number
            .checked_sub(execution_number)
            .and_then(|distance| head.header.number.checked_sub(distance))
            .ok_or_else(|| {
                anyhow!(
                    "no beacon block carries execution block {execution_number}: the beacon head {} carries execution block {head_execution_number}",
                    head.header.number
                )
            })?;
        let block = self.sealed_block(&number.to_string()).await?;
        ensure!(
            block.execution_payload.block_number == execution_number,
            "beacon block {number} carries execution block {}, expected {execution_number}",
            block.execution_payload.block_number
        );
        Ok(block)
    }

    /// Fetches the latest sealed beacon block, waiting for the beacon head to carry at least the
    /// execution block `min_execution_number`.
    ///
    /// The execution client imports a block before Maru serves its sealed beacon block, so the
    /// beacon head can briefly trail the execution head.
    pub async fn latest_sealed_block(
        &self,
        min_execution_number: u64,
    ) -> Result<SealedBeaconBlock> {
        let mut head = self.sealed_block("head").await?;
        for _ in 0..HEAD_POLL_ATTEMPTS {
            if head.execution_payload.block_number >= min_execution_number {
                break;
            }
            tokio::time::sleep(HEAD_POLL_INTERVAL).await;
            head = self.sealed_block("head").await?;
        }
        ensure!(
            head.execution_payload.block_number >= min_execution_number,
            "beacon head carries execution block {}, behind the required block {min_execution_number}",
            head.execution_payload.block_number
        );
        Ok(head)
    }

    /// Fetches the validator set of `header` in ascending order and checks it against the header
    /// state root.
    pub async fn validators(&self, header: &BeaconBlockHeader) -> Result<Vec<Address>> {
        // Maru looks beacon states up by block root. Validator sets only change at forks, so the
        // head state is a fallback for blocks whose state the node no longer serves. Either way the
        // set is only used if the header commits to it.
        let mut last_err = None;
        for state_id in [header.hash().to_string(), "head".to_string()] {
            let response: Result<Response<Vec<ApiValidator>>> = self
                .get(&format!("/eth/v1/beacon/states/{state_id}/validators"))
                .await;
            match response {
                Ok(response) => {
                    let mut validators: Vec<_> = response
                        .data
                        .into_iter()
                        .map(|validator| validator.validator.pubkey)
                        .collect();
                    validators.sort();
                    if header.compute_state_root(&validators) == header.state_root {
                        return Ok(validators);
                    }
                    last_err = Some(anyhow!(
                        "validator set of beacon state {state_id} does not match the state root of beacon block {}",
                        header.number
                    ));
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.expect("at least one state is queried"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        self.client
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .with_context(|| format!("failed to query {url}"))?
            .json()
            .await
            .with_context(|| format!("failed to decode response of {url}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        java_big_integer_bytes, ApiBlock, ApiValidator, BeaconBlockHeader, Message, Response,
        SealedBeaconBlock,
    };
    use alloy::primitives::{address, b256, Signature, U256};
    use proof_api_lib::utils::eth_bft::sort_commit_seals;

    /// A block with one transaction captured from a Maru 1.6.0 and Besu 26.4.0 devnet.
    fn live_block() -> SealedBeaconBlock {
        let header: Response<Message<BeaconBlockHeader>> =
            serde_json::from_str(include_str!("testdata/header.json")).unwrap();
        let block: Response<Message<ApiBlock>> =
            serde_json::from_str(include_str!("testdata/block.json")).unwrap();
        SealedBeaconBlock::from_api(header.data.message, block.data.message).unwrap()
    }

    #[test]
    fn rebuilds_live_block_hashes() {
        let block = live_block();
        let validator = address!("0x083e11f14b68d5ebeb4be3e3e0237ebbc5675ab5");
        let validators: Response<Vec<ApiValidator>> =
            serde_json::from_str(include_str!("testdata/validators.json")).unwrap();
        let validators: Vec<_> = validators
            .data
            .into_iter()
            .map(|validator| validator.validator.pubkey)
            .collect();
        assert_eq!(validators, vec![validator]);

        assert_eq!(block.execution_payload.transactions.len(), 1);
        assert_eq!(block.prev_commit_seals.len(), 1);
        // `from_api` already checked the body root.
        assert_eq!(
            block.header.hash(),
            b256!("0xf58fb07623ceeda6611dc78c82de6d7790b60ee82cdea85cc2d5bb283dad3aee")
        );
        assert_eq!(
            block.header.compute_state_root(&validators),
            block.header.state_root
        );
        assert_ne!(
            block.header.compute_state_root(&[]),
            block.header.state_root
        );

        let digest = block.header.hash();
        let seals = sort_commit_seals(&digest, &block.commit_seals).unwrap();
        assert_eq!(seals.len(), 1);
        assert_eq!(
            Signature::from_raw(&seals[0])
                .unwrap()
                .recover_address_from_prehash(&digest)
                .unwrap(),
            validator
        );
    }

    #[test]
    fn rejects_body_that_does_not_match_header() {
        let mut block = live_block();
        block.execution_payload.gas_used += 1;
        let header: Response<Message<BeaconBlockHeader>> =
            serde_json::from_str(include_str!("testdata/header.json")).unwrap();
        let mut api_block: Response<Message<ApiBlock>> =
            serde_json::from_str(include_str!("testdata/block.json")).unwrap();
        api_block.data.message.body.execution_payload = block.execution_payload;
        assert!(SealedBeaconBlock::from_api(header.data.message, api_block.data.message).is_err());
    }

    #[test]
    fn encodes_base_fee_as_java_big_integer() {
        assert_eq!(java_big_integer_bytes(U256::ZERO), [0]);
        assert_eq!(java_big_integer_bytes(U256::from(7)), [7]);
        assert_eq!(java_big_integer_bytes(U256::from(0x7f)), [0x7f]);
        assert_eq!(java_big_integer_bytes(U256::from(0x80)), [0, 0x80]);
        assert_eq!(java_big_integer_bytes(U256::from(0x1234)), [0x12, 0x34]);
        assert_eq!(java_big_integer_bytes(U256::from(0xff00)), [0, 0xff, 0]);
    }
}
