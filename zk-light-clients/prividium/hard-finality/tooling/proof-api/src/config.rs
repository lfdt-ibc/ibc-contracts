// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TIMEOUT_SECONDS: u64 = 3600;
const MAX_PROOF_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const MAX_QUEUED_REQUESTS: usize = 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BATCH_LOOKBACK: u64 = 100_000;
const MAX_AUTOMATIC_TRUST_UPDATES: usize = 8;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub source_profile_path: PathBuf,
    pub source_profile_sha256: String,
    pub bind_address: String,
    pub client: ClientConfig,
    pub prover: ProverConfig,
    pub l2_rpc: RpcConfig,
    pub l1_rpc: BasicRpcConfig,
    pub destination: DestinationConfig,
    pub ibc_storage: IbcStorageConfig,
    pub settlement: SettlementConfig,
    pub bootstrap: BootstrapConfig,
    #[serde(default)]
    pub api_token_env: Option<String>,
    #[serde(default = "default_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_max_queued_requests")]
    pub max_queued_requests: usize,
    #[serde(default = "default_max_concurrent_height_requests")]
    pub max_concurrent_height_requests: usize,
    #[serde(default = "default_max_automatic_trust_updates")]
    pub max_automatic_trust_updates: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientConfig {
    pub chain_id: String,
    pub client_id: String,
    pub counterparty_client_id: String,
    pub counterparty_merkle_prefix: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProverConfig {
    pub network_rpc_url: String,
    pub network_private_key_env: String,
    #[serde(default = "default_proof_timeout_seconds")]
    pub proof_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcConfig {
    pub url: String,
    pub chain_id: u64,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_batch_lookback")]
    pub max_batch_lookback: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BasicRpcConfig {
    pub url: String,
    pub chain_id: u64,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationConfig {
    pub rpc: BasicRpcConfig,
    pub router_address: String,
    pub verifier_address: String,
    pub trust_update_vkey: String,
    pub settlement_update_vkey: String,
    pub membership_vkey: String,
    pub non_membership_vkey: String,
    pub trust_update_registrar: TrustUpdateRegistrarConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustUpdateRegistrarConfig {
    pub private_key_env: String,
    pub chain_id: u64,
    #[serde(default = "default_registrar_receipt_timeout_seconds")]
    pub receipt_timeout_seconds: u64,
    #[serde(default = "default_registrar_receipt_poll_milliseconds")]
    pub receipt_poll_milliseconds: u64,
    #[serde(default = "default_registrar_max_gas")]
    pub max_gas: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IbcStorageConfig {
    pub supported_path_shape_id: String,
    pub storage_profile_id: String,
    pub store_address: String,
    pub mapping_base_slot: String,
    pub native_root_probe_slot: String,
    pub absence_profile_id: u32,
    pub max_client_id_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementConfig {
    pub diamond_proxy_address: String,
    pub stored_batch_hash_mapping_base_slot: String,
    pub total_batches_executed_slot: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapConfig {
    pub beacon_url: String,
    #[serde(default)]
    pub token_env: Option<String>,
    pub finalized_checkpoint_root: String,
    pub source_profile_id: String,
    pub initial_trust_path: PathBuf,
    pub initial_trust_sha256: String,
    pub sync_committee_size: usize,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ValidatedConfig {
    pub bind_address: SocketAddr,
    pub client: ClientConfig,
    pub counterparty_merkle_prefix: Vec<Vec<u8>>,
    pub prover: ResolvedProver,
    pub l2_rpc: ResolvedRpc,
    pub l1_rpc: ResolvedRpc,
    pub destination: ResolvedDestination,
    pub ibc_storage: ResolvedIbcStorage,
    pub settlement: ResolvedSettlement,
    pub bootstrap: ResolvedBootstrap,
    pub api_authorization: Option<String>,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_queued_requests: usize,
    pub max_concurrent_height_requests: usize,
    pub max_automatic_trust_updates: usize,
}

#[derive(Clone, Debug)]
pub struct ResolvedProver {
    pub network_rpc_url: Url,
    pub network_private_key: String,
    pub proof_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ResolvedRpc {
    pub url: Url,
    pub chain_id: u64,
    pub authorization: Option<String>,
    pub max_response_bytes: usize,
    pub max_batch_lookback: u64,
}

#[derive(Clone, Debug)]
pub struct ResolvedDestination {
    pub rpc: ResolvedRpc,
    pub router_address: [u8; 20],
    pub verifier_address: [u8; 20],
    pub trust_update_vkey: [u8; 32],
    pub settlement_update_vkey: [u8; 32],
    pub membership_vkey: [u8; 32],
    pub non_membership_vkey: [u8; 32],
    pub trust_update_registrar: ResolvedTrustUpdateRegistrar,
}

#[derive(Clone, Debug)]
pub struct ResolvedTrustUpdateRegistrar {
    pub private_key: String,
    pub chain_id: u64,
    pub receipt_timeout: Duration,
    pub receipt_poll_interval: Duration,
    pub max_gas: u64,
}

#[derive(Clone, Debug)]
pub struct ResolvedIbcStorage {
    pub store_address: [u8; 20],
    pub mapping_base_slot: [u8; 32],
    pub native_root_probe_slot: [u8; 32],
    pub absence_profile_id: u32,
    pub max_client_id_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ResolvedSettlement {
    pub diamond_proxy_address: [u8; 20],
    pub stored_batch_hash_mapping_base_slot: [u8; 32],
    pub total_batches_executed_slot: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ResolvedBootstrap {
    pub source_profile_id_bytes: [u8; 32],
    pub url: Url,
    pub authorization: Option<String>,
    pub finalized_checkpoint_root: String,
    pub source_profile_id: String,
    pub initial_trust_path: PathBuf,
    pub initial_trust_sha256: String,
    pub sync_committee_size: usize,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub max_response_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let metadata = fs::metadata(path)
            .map_err(|error| ConfigError(format!("cannot inspect {}: {error}", path.display())))?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError("configuration exceeds 1 MiB".into()));
        }
        let bytes = fs::read(path)
            .map_err(|error| ConfigError(format!("cannot read {}: {error}", path.display())))?;
        let mut decoder = serde_json::Deserializer::from_slice(&bytes);
        let config = Self::deserialize(&mut decoder)
            .map_err(|error| ConfigError(format!("invalid configuration JSON: {error}")))?;
        decoder
            .end()
            .map_err(|error| ConfigError(format!("trailing configuration data: {error}")))?;
        Ok(config)
    }

    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        validate_source_profile(&self)?;
        let bind_address = self
            .bind_address
            .parse::<SocketAddr>()
            .map_err(|error| ConfigError(format!("invalid bindAddress: {error}")))?;
        validate_identifier("client.chainId", &self.client.chain_id)?;
        validate_identifier("client.clientId", &self.client.client_id)?;
        validate_identifier(
            "client.counterpartyClientId",
            &self.client.counterparty_client_id,
        )?;
        let counterparty_merkle_prefix =
            decode_merkle_prefix(&self.client.counterparty_merkle_prefix)?;
        if self.request_timeout_seconds == 0 || self.request_timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(ConfigError(format!(
                "requestTimeoutSeconds must be in 1..={MAX_TIMEOUT_SECONDS}"
            )));
        }
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > MAX_CONCURRENT_REQUESTS
        {
            return Err(ConfigError(format!(
                "maxConcurrentRequests must be in 1..={MAX_CONCURRENT_REQUESTS}"
            )));
        }
        if self.max_queued_requests == 0 || self.max_queued_requests > MAX_QUEUED_REQUESTS {
            return Err(ConfigError(format!(
                "maxQueuedRequests must be in 1..={MAX_QUEUED_REQUESTS}"
            )));
        }
        if self.max_concurrent_height_requests == 0
            || self.max_concurrent_height_requests > MAX_CONCURRENT_REQUESTS
        {
            return Err(ConfigError(format!(
                "maxConcurrentHeightRequests must be in 1..={MAX_CONCURRENT_REQUESTS}"
            )));
        }
        if self.max_automatic_trust_updates == 0
            || self.max_automatic_trust_updates > MAX_AUTOMATIC_TRUST_UPDATES
        {
            return Err(ConfigError(format!(
                "maxAutomaticTrustUpdates must be in 1..={MAX_AUTOMATIC_TRUST_UPDATES}"
            )));
        }
        let api_authorization = self
            .api_token_env
            .as_deref()
            .map(|name| resolve_token(name, "apiTokenEnv"))
            .transpose()?
            .map(|token| format!("Bearer {token}"));
        if !bind_address.ip().is_loopback() && api_authorization.is_none() {
            return Err(ConfigError(
                "apiTokenEnv is required when bindAddress is not loopback".into(),
            ));
        }
        Ok(ValidatedConfig {
            bind_address,
            client: self.client,
            counterparty_merkle_prefix,
            prover: self.prover.resolve()?,
            l2_rpc: self.l2_rpc.resolve()?,
            l1_rpc: self.l1_rpc.resolve("l1Rpc")?,
            destination: self.destination.resolve()?,
            ibc_storage: self.ibc_storage.resolve()?,
            settlement: self.settlement.resolve()?,
            bootstrap: self.bootstrap.resolve()?,
            api_authorization,
            request_timeout: Duration::from_secs(self.request_timeout_seconds),
            max_concurrent_requests: self.max_concurrent_requests,
            max_queued_requests: self.max_queued_requests,
            max_concurrent_height_requests: self.max_concurrent_height_requests,
            max_automatic_trust_updates: self.max_automatic_trust_updates,
        })
    }
}

impl ProverConfig {
    fn resolve(self) -> Result<ResolvedProver, ConfigError> {
        if self.proof_timeout_seconds == 0 || self.proof_timeout_seconds > MAX_PROOF_TIMEOUT_SECONDS
        {
            return Err(ConfigError(format!(
                "prover.proofTimeoutSeconds must be in 1..={MAX_PROOF_TIMEOUT_SECONDS}"
            )));
        }
        let network_rpc_url = parse_url("prover.networkRpcUrl", &self.network_rpc_url)?;
        require_secure_authenticated_url("prover.networkRpcUrl", &network_rpc_url, true)?;
        let network_private_key =
            resolve_private_key(&self.network_private_key_env, "prover.networkPrivateKeyEnv")?;
        Ok(ResolvedProver {
            network_rpc_url,
            network_private_key,
            proof_timeout: Duration::from_secs(self.proof_timeout_seconds),
        })
    }
}

impl RpcConfig {
    fn resolve(self) -> Result<ResolvedRpc, ConfigError> {
        validate_response_limit("l2Rpc.maxResponseBytes", self.max_response_bytes)?;
        if self.chain_id == 0 {
            return Err(ConfigError("l2Rpc.chainId must be nonzero".into()));
        }
        if self.max_batch_lookback > MAX_BATCH_LOOKBACK {
            return Err(ConfigError(format!(
                "l2Rpc.maxBatchLookback must be in 0..={MAX_BATCH_LOOKBACK}"
            )));
        }
        let url = parse_url("l2Rpc.url", &self.url)?;
        let authorization = resolve_optional_token(self.token_env.as_deref(), "l2Rpc.tokenEnv")?;
        require_secure_authenticated_url("l2Rpc.url", &url, authorization.is_some())?;
        Ok(ResolvedRpc {
            url,
            chain_id: self.chain_id,
            authorization,
            max_response_bytes: self.max_response_bytes,
            max_batch_lookback: self.max_batch_lookback,
        })
    }
}

impl BasicRpcConfig {
    fn resolve(self, field: &str) -> Result<ResolvedRpc, ConfigError> {
        validate_response_limit(
            &format!("{field}.maxResponseBytes"),
            self.max_response_bytes,
        )?;
        if self.chain_id == 0 {
            return Err(ConfigError(format!("{field}.chainId must be nonzero")));
        }
        let url = parse_url(&format!("{field}.url"), &self.url)?;
        let authorization =
            resolve_optional_token(self.token_env.as_deref(), &format!("{field}.tokenEnv"))?;
        require_secure_authenticated_url(&format!("{field}.url"), &url, authorization.is_some())?;
        Ok(ResolvedRpc {
            url,
            chain_id: self.chain_id,
            authorization,
            max_response_bytes: self.max_response_bytes,
            max_batch_lookback: 0,
        })
    }
}

impl DestinationConfig {
    fn resolve(self) -> Result<ResolvedDestination, ConfigError> {
        let router_address =
            decode_prefixed_hex("destination.routerAddress", &self.router_address)?;
        require_nonzero("destination.routerAddress", &router_address)?;
        let verifier_address =
            decode_prefixed_hex("destination.verifierAddress", &self.verifier_address)?;
        require_nonzero("destination.verifierAddress", &verifier_address)?;
        let trust_update_vkey =
            decode_prefixed_hex("destination.trustUpdateVkey", &self.trust_update_vkey)?;
        let settlement_update_vkey = decode_prefixed_hex(
            "destination.settlementUpdateVkey",
            &self.settlement_update_vkey,
        )?;
        let membership_vkey =
            decode_prefixed_hex("destination.membershipVkey", &self.membership_vkey)?;
        let non_membership_vkey =
            decode_prefixed_hex("destination.nonMembershipVkey", &self.non_membership_vkey)?;
        for (field, value) in [
            ("destination.trustUpdateVkey", &trust_update_vkey),
            ("destination.settlementUpdateVkey", &settlement_update_vkey),
            ("destination.membershipVkey", &membership_vkey),
            ("destination.nonMembershipVkey", &non_membership_vkey),
        ] {
            require_nonzero(field, value)?;
        }
        Ok(ResolvedDestination {
            rpc: self.rpc.resolve("destination.rpc")?,
            router_address,
            verifier_address,
            trust_update_vkey,
            settlement_update_vkey,
            membership_vkey,
            non_membership_vkey,
            trust_update_registrar: self.trust_update_registrar.resolve()?,
        })
    }
}

impl TrustUpdateRegistrarConfig {
    fn resolve(self) -> Result<ResolvedTrustUpdateRegistrar, ConfigError> {
        if self.chain_id == 0 {
            return Err(ConfigError(
                "destination.trustUpdateRegistrar.chainId must be nonzero".into(),
            ));
        }
        if self.receipt_timeout_seconds == 0 || self.receipt_timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(ConfigError(
                "destination.trustUpdateRegistrar.receiptTimeoutSeconds is out of range".into(),
            ));
        }
        if !(50..=10_000).contains(&self.receipt_poll_milliseconds) {
            return Err(ConfigError(
                "destination.trustUpdateRegistrar.receiptPollMilliseconds must be in 50..=10000"
                    .into(),
            ));
        }
        if !(100_000..=30_000_000).contains(&self.max_gas) {
            return Err(ConfigError(
                "destination.trustUpdateRegistrar.maxGas must be in 100000..=30000000".into(),
            ));
        }
        Ok(ResolvedTrustUpdateRegistrar {
            private_key: resolve_private_key(
                &self.private_key_env,
                "destination.trustUpdateRegistrar.privateKeyEnv",
            )?,
            chain_id: self.chain_id,
            receipt_timeout: Duration::from_secs(self.receipt_timeout_seconds),
            receipt_poll_interval: Duration::from_millis(self.receipt_poll_milliseconds),
            max_gas: self.max_gas,
        })
    }
}

impl IbcStorageConfig {
    fn resolve(self) -> Result<ResolvedIbcStorage, ConfigError> {
        if self.absence_profile_id == 0 {
            return Err(ConfigError(
                "ibcStorage.absenceProfileId must be nonzero".into(),
            ));
        }
        if !(1..=128).contains(&self.max_client_id_bytes) {
            return Err(ConfigError(
                "ibcStorage.maxClientIdBytes must be in 1..=128".into(),
            ));
        }
        let store_address = decode_prefixed_hex("ibcStorage.storeAddress", &self.store_address)?;
        require_nonzero("ibcStorage.storeAddress", &store_address)?;
        Ok(ResolvedIbcStorage {
            store_address,
            mapping_base_slot: decode_prefixed_hex(
                "ibcStorage.mappingBaseSlot",
                &self.mapping_base_slot,
            )?,
            native_root_probe_slot: decode_prefixed_hex(
                "ibcStorage.nativeRootProbeSlot",
                &self.native_root_probe_slot,
            )?,
            absence_profile_id: self.absence_profile_id,
            max_client_id_bytes: self.max_client_id_bytes,
        })
    }
}

impl SettlementConfig {
    fn resolve(self) -> Result<ResolvedSettlement, ConfigError> {
        let address = decode_prefixed_hex(
            "settlement.diamondProxyAddress",
            &self.diamond_proxy_address,
        )?;
        require_nonzero("settlement.diamondProxyAddress", &address)?;
        Ok(ResolvedSettlement {
            diamond_proxy_address: address,
            stored_batch_hash_mapping_base_slot: decode_prefixed_hex(
                "settlement.storedBatchHashMappingBaseSlot",
                &self.stored_batch_hash_mapping_base_slot,
            )?,
            total_batches_executed_slot: decode_prefixed_hex(
                "settlement.totalBatchesExecutedSlot",
                &self.total_batches_executed_slot,
            )?,
        })
    }
}

impl BootstrapConfig {
    fn resolve(self) -> Result<ResolvedBootstrap, ConfigError> {
        validate_response_limit("bootstrap.maxResponseBytes", self.max_response_bytes)?;
        if !(1..=512).contains(&self.sync_committee_size) {
            return Err(ConfigError(
                "bootstrap.syncCommitteeSize must be in 1..=512".into(),
            ));
        }
        if self.slots_per_epoch == 0 || self.epochs_per_sync_committee_period == 0 {
            return Err(ConfigError(
                "bootstrap slot/period constants must be nonzero".into(),
            ));
        }
        self.slots_per_epoch
            .checked_mul(self.epochs_per_sync_committee_period)
            .ok_or_else(|| ConfigError("bootstrap sync period size overflows u64".into()))?;
        let checkpoint = decode_prefixed_hex::<32>(
            "bootstrap.finalizedCheckpointRoot",
            &self.finalized_checkpoint_root,
        )?;
        require_nonzero("bootstrap.finalizedCheckpointRoot", &checkpoint)?;
        let source_profile_id_bytes =
            decode_prefixed_hex::<32>("bootstrap.sourceProfileId", &self.source_profile_id)?;
        require_nonzero("bootstrap.sourceProfileId", &source_profile_id_bytes)?;
        let checksum =
            decode_plain_hex::<32>("bootstrap.initialTrustSha256", &self.initial_trust_sha256)?;
        require_nonzero("bootstrap.initialTrustSha256", &checksum)?;
        if !self.initial_trust_path.is_absolute() {
            return Err(ConfigError(
                "bootstrap.initialTrustPath must be absolute".into(),
            ));
        }
        let url = parse_url("bootstrap.beaconUrl", &self.beacon_url)?;
        let authorization =
            resolve_optional_token(self.token_env.as_deref(), "bootstrap.tokenEnv")?;
        require_secure_authenticated_url("bootstrap.beaconUrl", &url, authorization.is_some())?;
        Ok(ResolvedBootstrap {
            source_profile_id_bytes,
            url,
            authorization,
            finalized_checkpoint_root: self.finalized_checkpoint_root,
            source_profile_id: self.source_profile_id,
            initial_trust_path: self.initial_trust_path,
            initial_trust_sha256: self.initial_trust_sha256,
            sync_committee_size: self.sync_committee_size,
            slots_per_epoch: self.slots_per_epoch,
            epochs_per_sync_committee_period: self.epochs_per_sync_committee_period,
            max_response_bytes: self.max_response_bytes,
        })
    }
}

fn resolve_optional_token(name: Option<&str>, field: &str) -> Result<Option<String>, ConfigError> {
    name.map(|name| resolve_token(name, field))
        .transpose()
        .map(|token| token.map(|token| format!("Bearer {token}")))
}

fn validate_source_profile(config: &Config) -> Result<(), ConfigError> {
    if !config.source_profile_path.is_absolute() {
        return Err(ConfigError("sourceProfilePath must be absolute".into()));
    }
    let bytes = fs::read(&config.source_profile_path).map_err(|error| {
        ConfigError(format!(
            "cannot read SourceProfile {}: {error}",
            config.source_profile_path.display()
        ))
    })?;
    let expected_sha =
        decode_plain_hex::<32>("sourceProfileSha256", &config.source_profile_sha256)?;
    let actual_sha: [u8; 32] = Sha256::digest(&bytes).into();
    if actual_sha != expected_sha {
        return Err(ConfigError("SourceProfile SHA-256 mismatch".into()));
    }
    let profile = prividium_source_profile::SourceProfileV1::parse_json(&bytes)
        .and_then(prividium_source_profile::SourceProfileV1::validate)
        .map_err(|error| ConfigError(format!("invalid SourceProfile: {error:?}")))?;
    let profile_id = profile
        .source_profile_id()
        .map_err(|error| ConfigError(format!("cannot derive SourceProfile ID: {error:?}")))?;
    let profile_max_client_id_bytes =
        usize::try_from(profile.source.prividium_l2.max_client_id_bytes).map_err(|_| {
            ConfigError("SourceProfile maxClientIdBytes does not fit this platform".into())
        })?;
    let profile_sync_committee_size = usize::try_from(profile.source.consensus.sync_committee_size)
        .map_err(|_| {
            ConfigError("SourceProfile syncCommitteeSize does not fit this platform".into())
        })?;
    let configured_profile = decode_prefixed_hex::<32>(
        "bootstrap.sourceProfileId",
        &config.bootstrap.source_profile_id,
    )?;
    if profile_id != configured_profile
        || profile.source.prividium_l2.chain_id != config.l2_rpc.chain_id
        || profile.ibc_store_address
            != decode_prefixed_hex("ibcStorage.storeAddress", &config.ibc_storage.store_address)?
        || profile.ibc_mapping_base_slot
            != decode_prefixed_hex(
                "ibcStorage.mappingBaseSlot",
                &config.ibc_storage.mapping_base_slot,
            )?
        || profile.stored_batch_hash_mapping_base_slot
            != decode_prefixed_hex(
                "settlement.storedBatchHashMappingBaseSlot",
                &config.settlement.stored_batch_hash_mapping_base_slot,
            )?
        || profile.total_batches_executed_slot
            != decode_prefixed_hex(
                "settlement.totalBatchesExecutedSlot",
                &config.settlement.total_batches_executed_slot,
            )?
        || profile.diamond_proxy_address
            != decode_prefixed_hex(
                "settlement.diamondProxyAddress",
                &config.settlement.diamond_proxy_address,
            )?
        || profile.source.prividium_l2.absence_profile_id != config.ibc_storage.absence_profile_id
        || profile_max_client_id_bytes != config.ibc_storage.max_client_id_bytes
        || profile.source.prividium_l2.ibc_storage_profile_id
            != config.ibc_storage.storage_profile_id
        || profile.source.ibc.supported_path_shape_id != config.ibc_storage.supported_path_shape_id
        || profile_sync_committee_size != config.bootstrap.sync_committee_size
        || profile.source.consensus.slots_per_epoch != config.bootstrap.slots_per_epoch
        || profile.source.consensus.epochs_per_sync_committee_period
            != config.bootstrap.epochs_per_sync_committee_period
    {
        return Err(ConfigError(
            "configuration does not match the reviewed SourceProfile".into(),
        ));
    }
    Ok(())
}

fn validate_response_limit(field: &str, value: usize) -> Result<(), ConfigError> {
    if value == 0 || value > MAX_RESPONSE_BYTES {
        return Err(ConfigError(format!(
            "{field} must be in 1..={MAX_RESPONSE_BYTES}"
        )));
    }
    Ok(())
}

fn decode_merkle_prefix(prefix: &[String]) -> Result<Vec<Vec<u8>>, ConfigError> {
    if prefix.is_empty() || prefix.len() > 16 {
        return Err(ConfigError(
            "client.counterpartyMerklePrefix must contain 1..=16 entries".into(),
        ));
    }
    let mut decoded = Vec::with_capacity(prefix.len());
    for entry in prefix {
        let body = entry.strip_prefix("0x").ok_or_else(|| {
            ConfigError("client.counterpartyMerklePrefix entries require 0x prefix".into())
        })?;
        if body.len() > 512
            || body.len() % 2 != 0
            || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConfigError(
                "client.counterpartyMerklePrefix contains invalid hex".into(),
            ));
        }
        decoded.push(hex::decode(body).map_err(|_| {
            ConfigError("client.counterpartyMerklePrefix contains invalid hex".into())
        })?);
    }
    Ok(decoded)
}

fn parse_url(field: &str, value: &str) -> Result<Url, ConfigError> {
    let parsed =
        Url::parse(value).map_err(|error| ConfigError(format!("{field} is invalid: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError(format!(
            "{field} must be an absolute HTTP(S) URL without credentials, query, or fragment"
        )));
    }
    Ok(parsed)
}

fn require_secure_authenticated_url(
    field: &str,
    url: &Url,
    authenticated: bool,
) -> Result<(), ConfigError> {
    if authenticated && url.scheme() != "https" && !url_is_loopback(url) {
        return Err(ConfigError(format!(
            "{field} must use HTTPS when credentials are configured"
        )));
    }
    Ok(())
}

fn url_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn resolve_token(name: &str, field: &str) -> Result<String, ConfigError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ConfigError(format!(
            "{field} is not a valid environment name"
        )));
    }
    let value = env::var(name)
        .map_err(|_| ConfigError(format!("environment variable {name} is not set")))?;
    if value.len() < MIN_TOKEN_BYTES || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError(format!(
            "{name} must contain at least {MIN_TOKEN_BYTES} non-control bytes"
        )));
    }
    Ok(value)
}

fn resolve_private_key(name: &str, field: &str) -> Result<String, ConfigError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ConfigError(format!(
            "{field} is not a valid environment name"
        )));
    }
    let value = env::var(name)
        .map_err(|_| ConfigError(format!("environment variable {name} is not set")))?;
    let body = value.strip_prefix("0x").unwrap_or(&value);
    let key = decode_hex_body::<32>(name, body)?;
    require_nonzero(name, &key)?;
    Ok(format!("0x{}", hex::encode(key)))
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > 128 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError(format!(
            "{field} must contain 1..=128 non-control bytes"
        )));
    }
    Ok(())
}

fn decode_prefixed_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], ConfigError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| ConfigError(format!("{field} lacks 0x prefix")))?;
    decode_hex_body(field, body)
}

fn decode_plain_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], ConfigError> {
    decode_hex_body(field, value)
}

fn decode_hex_body<const N: usize>(field: &str, body: &str) -> Result<[u8; N], ConfigError> {
    if body.len() != N * 2
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError(format!(
            "{field} must be exactly {N} bytes of lowercase hex"
        )));
    }
    hex::decode(body)
        .map_err(|_| ConfigError(format!("{field} is not valid hex")))?
        .try_into()
        .map_err(|_| ConfigError(format!("{field} must be exactly {N} bytes")))
}

fn require_nonzero(field: &str, value: &[u8]) -> Result<(), ConfigError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(ConfigError(format!("{field} must be nonzero")))
    } else {
        Ok(())
    }
}

const fn default_timeout_seconds() -> u64 {
    1_800
}
const fn default_proof_timeout_seconds() -> u64 {
    3_600
}
const fn default_registrar_receipt_timeout_seconds() -> u64 {
    120
}
const fn default_registrar_receipt_poll_milliseconds() -> u64 {
    1_000
}
const fn default_registrar_max_gas() -> u64 {
    8_000_000
}
const fn default_max_concurrent_requests() -> usize {
    4
}
const fn default_max_queued_requests() -> usize {
    16
}
const fn default_max_concurrent_height_requests() -> usize {
    16
}
const fn default_max_automatic_trust_updates() -> usize {
    8
}
const fn default_max_response_bytes() -> usize {
    16 * 1024 * 1024
}
const fn default_max_batch_lookback() -> u64 {
    2_048
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_source_profile(
        directory: &tempfile::TempDir,
    ) -> (std::path::PathBuf, &'static [u8], String) {
        let profile_path = directory.path().join("source-profile.json");
        let profile_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/example.synthetic.json"
        ));
        fs::write(&profile_path, profile_bytes).unwrap();
        let profile = prividium_source_profile::SourceProfileV1::parse_json(profile_bytes)
            .unwrap()
            .validate()
            .unwrap();
        let profile_id = format!("0x{}", hex::encode(profile.source_profile_id().unwrap()));
        (profile_path, profile_bytes, profile_id)
    }

    fn valid_config() -> (Config, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let (profile_path, profile_bytes, profile_id) = test_source_profile(&directory);
        let prover_key_name = "PRIVIDIUM_TEST_SP1_NETWORK_KEY";
        std::env::set_var(prover_key_name, format!("0x{}", "10".repeat(32)));
        let registrar_key_name = "PRIVIDIUM_TEST_TRUST_UPDATE_REGISTRAR_KEY";
        std::env::set_var(registrar_key_name, format!("0x{}", "11".repeat(32)));
        (
            Config {
                source_profile_path: profile_path,
                source_profile_sha256: hex::encode(Sha256::digest(profile_bytes)),
                bind_address: "127.0.0.1:9090".into(),
                client: ClientConfig {
                    chain_id: "1337".into(),
                    client_id: "6565".into(),
                    counterparty_client_id: "1337".into(),
                    counterparty_merkle_prefix: vec!["0x00".into()],
                },
                prover: ProverConfig {
                    network_rpc_url: "http://127.0.0.1:50061/".into(),
                    network_private_key_env: prover_key_name.into(),
                    proof_timeout_seconds: 3_600,
                },
                l2_rpc: RpcConfig {
                    url: "http://127.0.0.1:24101/".into(),
                    chain_id: 6565,
                    token_env: None,
                    max_response_bytes: 4096,
                    max_batch_lookback: 128,
                },
                l1_rpc: BasicRpcConfig {
                    url: "http://localhost:8545/".into(),
                    chain_id: 1,
                    token_env: None,
                    max_response_bytes: 4096,
                },
                destination: DestinationConfig {
                    rpc: BasicRpcConfig {
                        url: "http://127.0.0.1:8546/".into(),
                        chain_id: 1337,
                        token_env: None,
                        max_response_bytes: 4096,
                    },
                    router_address: "0x1111111111111111111111111111111111111111".into(),
                    verifier_address: "0x1212121212121212121212121212121212121212".into(),
                    trust_update_vkey: "0x13".to_owned() + &"13".repeat(31),
                    settlement_update_vkey: "0x14".to_owned() + &"14".repeat(31),
                    membership_vkey: "0x15".to_owned() + &"15".repeat(31),
                    non_membership_vkey: "0x16".to_owned() + &"16".repeat(31),
                    trust_update_registrar: TrustUpdateRegistrarConfig {
                        private_key_env: registrar_key_name.into(),
                        chain_id: 1337,
                        receipt_timeout_seconds: 120,
                        receipt_poll_milliseconds: 1000,
                        max_gas: 8_000_000,
                    },
                },
                ibc_storage: IbcStorageConfig {
                    supported_path_shape_id: "synthetic-raw-bytes-v1".into(),
                    storage_profile_id: "synthetic-direct-mapping-v1".into(),
                    store_address: "0x4444444444444444444444444444444444444444".into(),
                    mapping_base_slot: format!("0x{}", "00".repeat(31) + "22"),
                    native_root_probe_slot: format!("0x{}", "00".repeat(31) + "23"),
                    absence_profile_id: 1,
                    max_client_id_bytes: 128,
                },
                settlement: SettlementConfig {
                    diamond_proxy_address: "0x2222222222222222222222222222222222222222".into(),
                    stored_batch_hash_mapping_base_slot: format!("0x{}", "00".repeat(31) + "11"),
                    total_batches_executed_slot: format!("0x{}", "00".repeat(31) + "10"),
                },
                bootstrap: BootstrapConfig {
                    beacon_url: "http://127.0.0.1:5052/".into(),
                    token_env: None,
                    finalized_checkpoint_root: format!("0x{}", "21".repeat(32)),
                    source_profile_id: profile_id,
                    initial_trust_path: directory.path().join("initial-trust.json"),
                    initial_trust_sha256: "22".repeat(32),
                    sync_committee_size: 8,
                    slots_per_epoch: 32,
                    epochs_per_sync_committee_period: 256,
                    max_response_bytes: 4096,
                },
                api_token_env: None,
                request_timeout_seconds: 60,
                max_concurrent_requests: 4,
                max_queued_requests: 16,
                max_concurrent_height_requests: 8,
                max_automatic_trust_updates: 8,
            },
            directory,
        )
    }

    #[test]
    fn rejects_embedded_credentials_and_url_suffixes() {
        assert!(parse_url("url", "https://user:pass@example.com").is_err());
        assert!(parse_url("url", "https://example.com?secret=value").is_err());
        assert!(parse_url("url", "https://example.com/#fragment").is_err());
    }

    #[test]
    fn rejects_zero_and_uppercase_security_identifiers() {
        let zero = "0".repeat(64);
        assert!(decode_plain_hex::<32>("digest", &zero).is_ok());
        assert!(require_nonzero("digest", &[0_u8; 32]).is_err());
        assert!(decode_plain_hex::<32>("digest", &"A".repeat(64)).is_err());
    }

    #[test]
    fn complete_reviewed_configuration_resolves_every_runtime_binding() {
        let (config, _directory) = valid_config();
        let resolved = config.validate().unwrap();
        assert_eq!(resolved.bind_address, "127.0.0.1:9090".parse().unwrap());
        assert_eq!(resolved.l2_rpc.chain_id, 6565);
        assert_eq!(resolved.destination.rpc.chain_id, 1337);
        assert_eq!(resolved.ibc_storage.store_address, [0x44; 20]);
        assert_eq!(resolved.bootstrap.sync_committee_size, 8);
        assert_eq!(resolved.request_timeout, Duration::from_mins(1));
        assert_eq!(resolved.max_automatic_trust_updates, 8);
        assert!(resolved.api_authorization.is_none());
    }

    #[test]
    fn configuration_file_loading_is_strict() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, b"{} trailing").unwrap();
        assert!(Config::load(&path).is_err());
        assert!(Config::load(&directory.path().join("missing.json")).is_err());

        let oversized = directory.path().join("oversized.json");
        fs::write(
            &oversized,
            vec![b' '; usize::try_from(MAX_CONFIG_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert_eq!(
            Config::load(&oversized).unwrap_err().0,
            "configuration exceeds 1 MiB"
        );

        let legacy = directory.path().join("legacy-batch-registrar.json");
        let example =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.json"))
                .unwrap()
                .replace("trustUpdateRegistrar", "batchRegistrar");
        fs::write(&legacy, example).unwrap();
        assert!(Config::load(&legacy)
            .unwrap_err()
            .0
            .contains("unknown field `batchRegistrar`"));
    }

    #[test]
    fn configuration_bounds_and_security_helpers_fail_closed() {
        let (base, _directory) = valid_config();
        for mutate in [
            |config: &mut Config| config.request_timeout_seconds = 0,
            |config: &mut Config| config.max_concurrent_requests = 0,
            |config: &mut Config| config.max_queued_requests = 0,
            |config: &mut Config| config.max_concurrent_height_requests = 0,
            |config: &mut Config| config.max_automatic_trust_updates = 0,
        ] {
            let mut config = base.clone();
            mutate(&mut config);
            assert!(config.validate().is_err());
        }

        let mut too_many_trust_updates = base.clone();
        too_many_trust_updates.max_automatic_trust_updates = MAX_AUTOMATIC_TRUST_UPDATES + 1;
        assert!(too_many_trust_updates.validate().is_err());

        let mut exposed = base.clone();
        exposed.bind_address = "0.0.0.0:9090".into();
        assert!(exposed.validate().is_err());

        assert!(decode_merkle_prefix(&[]).is_err());
        assert!(decode_merkle_prefix(&["missing-prefix".into()]).is_err());
        assert!(decode_merkle_prefix(&["0x0".into()]).is_err());
        assert!(parse_url("url", "file:///tmp/value").is_err());
        assert!(require_secure_authenticated_url(
            "url",
            &Url::parse("http://example.com").unwrap(),
            true
        )
        .is_err());
        assert!(url_is_loopback(&Url::parse("http://localhost").unwrap()));
        assert!(url_is_loopback(&Url::parse("http://127.0.0.1").unwrap()));
        assert!(!url_is_loopback(
            &Url::parse("https://example.com").unwrap()
        ));
        assert!(validate_response_limit("limit", 0).is_err());
        assert!(validate_identifier("id", "").is_err());
        assert!(decode_prefixed_hex::<20>("address", "11").is_err());
        assert!(decode_plain_hex::<1>("byte", "11").is_ok());
    }

    #[test]
    fn each_nested_configuration_section_enforces_its_own_bounds() {
        let (base, _directory) = valid_config();

        let mut prover = base.prover.clone();
        prover.proof_timeout_seconds = 0;
        assert!(prover.resolve().is_err());
        let mut rpc = base.l2_rpc.clone();
        rpc.chain_id = 0;
        assert!(rpc.resolve().is_err());
        let mut rpc = base.l2_rpc.clone();
        rpc.max_batch_lookback = MAX_BATCH_LOOKBACK + 1;
        assert!(rpc.resolve().is_err());
        let mut basic = base.l1_rpc.clone();
        basic.chain_id = 0;
        assert!(basic.resolve("l1Rpc").is_err());

        let mut destination = base.destination.clone();
        destination.router_address = format!("0x{}", "00".repeat(20));
        assert!(destination.resolve().is_err());
        let mut ibc = base.ibc_storage.clone();
        ibc.absence_profile_id = 0;
        assert!(ibc.resolve().is_err());
        let mut ibc = base.ibc_storage.clone();
        ibc.max_client_id_bytes = 0;
        assert!(ibc.resolve().is_err());
        let mut settlement = base.settlement.clone();
        settlement.diamond_proxy_address = format!("0x{}", "00".repeat(20));
        assert!(settlement.resolve().is_err());

        let mut bootstrap = base.bootstrap.clone();
        bootstrap.sync_committee_size = 0;
        assert!(bootstrap.resolve().is_err());
        let mut bootstrap = base.bootstrap.clone();
        bootstrap.slots_per_epoch = 0;
        assert!(bootstrap.resolve().is_err());
        let mut bootstrap = base.bootstrap.clone();
        bootstrap.finalized_checkpoint_root = format!("0x{}", "00".repeat(32));
        assert!(bootstrap.resolve().is_err());
        let mut bootstrap = base.bootstrap;
        bootstrap.initial_trust_path = "relative.json".into();
        assert!(bootstrap.resolve().is_err());
    }

    #[test]
    fn environment_secrets_and_remaining_bounds_are_strict() {
        const TOKEN_ENV: &str = "PRIVIDIUM_TEST_COVERAGE_TOKEN";
        const KEY_ENV: &str = "PRIVIDIUM_TEST_COVERAGE_KEY";
        std::env::set_var(TOKEN_ENV, "a-secure-test-token-with-enough-bytes");
        std::env::set_var(KEY_ENV, format!("0x{}", "42".repeat(32)));
        assert_eq!(
            resolve_optional_token(Some(TOKEN_ENV), "token").unwrap(),
            Some("Bearer a-secure-test-token-with-enough-bytes".into())
        );
        assert_eq!(
            resolve_private_key(KEY_ENV, "key").unwrap(),
            format!("0x{}", "42".repeat(32))
        );
        assert!(resolve_token("lowercase", "token").is_err());
        assert!(resolve_token("PRIVIDIUM_TEST_MISSING_TOKEN", "token").is_err());
        std::env::set_var(TOKEN_ENV, "short");
        assert!(resolve_token(TOKEN_ENV, "token").is_err());
        std::env::set_var(KEY_ENV, "0x01");
        assert!(resolve_private_key(KEY_ENV, "key").is_err());

        assert_eq!(
            decode_merkle_prefix(&["0x00".into(), "0x0102".into()]).unwrap(),
            vec![vec![0], vec![1, 2]]
        );
        assert!(decode_merkle_prefix(&vec!["0x00".into(); 17]).is_err());
        assert!(validate_response_limit("limit", MAX_RESPONSE_BYTES + 1).is_err());
        assert!(validate_identifier("id", &"a".repeat(129)).is_err());
        assert!(validate_identifier("id", "line\nbreak").is_err());
        assert!(url_is_loopback(&Url::parse("http://[::1]").unwrap()));
        assert!(parse_url("url", "https://example.com/path").is_ok());

        let (base, _directory) = valid_config();
        for mutate in [
            |config: &mut Config| config.max_concurrent_requests = MAX_CONCURRENT_REQUESTS + 1,
            |config: &mut Config| config.max_queued_requests = MAX_QUEUED_REQUESTS + 1,
            |config: &mut Config| {
                config.max_concurrent_height_requests = MAX_CONCURRENT_REQUESTS + 1;
            },
            |config: &mut Config| config.request_timeout_seconds = MAX_TIMEOUT_SECONDS + 1,
        ] {
            let mut config = base.clone();
            mutate(&mut config);
            assert!(config.validate().is_err());
        }

        let mut registrar = base.destination.trust_update_registrar.clone();
        registrar.chain_id = 0;
        assert!(registrar.resolve().is_err());
        let mut registrar = base.destination.trust_update_registrar.clone();
        registrar.receipt_timeout_seconds = 0;
        assert!(registrar.resolve().is_err());
        let mut registrar = base.destination.trust_update_registrar.clone();
        registrar.receipt_poll_milliseconds = 1;
        assert!(registrar.resolve().is_err());
        let mut registrar = base.destination.trust_update_registrar;
        registrar.max_gas = 1;
        assert!(registrar.resolve().is_err());
    }
}
