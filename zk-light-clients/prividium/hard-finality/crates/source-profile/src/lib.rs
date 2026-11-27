// SPDX-License-Identifier: Apache-2.0

use prividium_crypto::keccak256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;

const CANONICAL_MAGIC: &[u8] = b"PRIVIDIUM_SOURCE_PROFILE_V1\0";
const MAX_TEXT_BYTES: usize = 256;
const MAX_LIST_ITEMS: usize = 128;
const SUPPORTED_HEADER_SCHEMAS: [&str; 2] = ["fulu-compatibility-v1", "synthetic-v1"];
const PINNED_ZKSYNC_OS_VERSION: &str = "v0.20.8";
const PINNED_ZKSYNC_OS_COMMIT: &str = "dbb5c03d4a94ceb1acea9f79242590f354660239";
const PINNED_NATIVE_TREE_PROFILE_ID: &str = "zksync-os-v0.20.8-native";
const PINNED_NATIVE_ROOT_BINDING_RULE_ID: &str = "zksync-os-v0.20.8-stored-batch-info-v1";
const PINNED_APPLICATION_ABSENCE_RULE: &str = "native-non-existing-only-v1";
const PINNED_ABSENCE_PROFILE_ID: u32 = 1;
const EUREKA_STORAGE_PROFILE_ID: &str = "cosmos-solidity-ibc-eureka-erc7201-v1";
const EUREKA_PATH_SHAPE_ID: &str = "ibc-eureka-v2-terminal-path-v1";
const EUREKA_COMMITMENTS_MAPPING_SLOT: [u8; 32] = [
    0x12, 0x60, 0x94, 0x44, 0x89, 0x27, 0x29, 0x88, 0xd9, 0xdf, 0x28, 0x51, 0x49, 0xb5, 0xaa, 0x1b,
    0x0f, 0x48, 0xf2, 0x13, 0x6d, 0x6f, 0x41, 0x61, 0x59, 0xf8, 0x40, 0xa3, 0xe0, 0x74, 0x76, 0x00,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceProfileV1 {
    pub profile_schema_version: u32,
    pub profile_name: String,
    pub consensus: ConsensusProfile,
    pub settlement: SettlementProfile,
    pub prividium_l2: PrividiumL2Profile,
    pub ibc: IbcProfile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsensusProfile {
    pub genesis_validators_root: String,
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub sync_committee_size: u64,
    pub fork_schedule: Vec<ForkScheduleEntry>,
    pub supported_light_client_header_schemas: Vec<String>,
    pub supported_execution_payload_header_schemas: Vec<String>,
    pub fork_specific_finality_gindices: Vec<ForkGindex>,
    pub fork_specific_next_committee_gindices: Vec<ForkGindex>,
    pub fork_specific_execution_gindices: Vec<ForkGindex>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkScheduleEntry {
    pub fork_id: String,
    pub activation_epoch: u64,
    pub fork_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkGindex {
    pub fork_id: String,
    pub generalized_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementProfile {
    pub diamond_proxy_address: String,
    pub diamond_source_commit: String,
    pub settlement_storage_profile_id: String,
    pub accepted_lifecycle_rule_id: String,
    pub native_root_binding_rule_id: String,
    /// Development/production profile parameter for
    /// `mapping(uint256 => bytes32) storedBatchHash`.
    pub stored_batch_hash_mapping_base_slot: String,
    /// Exact `ZKChainStorage.totalBatchesExecuted` slot in the pinned Diamond layout.
    pub total_batches_executed_slot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrividiumL2Profile {
    /// EIP-155 chain ID of the authenticated Prividium L2.
    pub chain_id: u64,
    pub zksync_os_version: String,
    pub zksync_os_commit: String,
    pub native_tree_profile_id: String,
    pub ibc_store_address: String,
    pub ibc_storage_profile_id: String,
    pub absence_profile_id: u32,
    /// Base slot of the profile's direct `mapping(bytes32 => bytes32)` IBC store.
    pub ibc_mapping_base_slot: String,
    pub max_client_id_bytes: u64,
    /// Exact application predicate layered over native-tree presence/absence.
    pub application_absence_rule: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IbcProfile {
    pub ibc_contracts_commit: String,
    pub supported_path_shape_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSourceProfileV1 {
    pub source: SourceProfileV1,
    pub genesis_validators_root: [u8; 32],
    pub diamond_proxy_address: [u8; 20],
    pub ibc_store_address: [u8; 20],
    pub stored_batch_hash_mapping_base_slot: [u8; 32],
    pub total_batches_executed_slot: [u8; 32],
    pub ibc_mapping_base_slot: [u8; 32],
    pub fork_versions: Vec<[u8; 4]>,
}

impl SourceProfileV1 {
    pub fn parse_json(input: &[u8]) -> Result<Self, ProfileError> {
        serde_json::from_slice(input).map_err(|error| ProfileError::Json(error.to_string()))
    }

    pub fn validate(self) -> Result<ValidatedSourceProfileV1, ProfileError> {
        if self.profile_schema_version != 1 {
            return Err(ProfileError::UnsupportedSchemaVersion(
                self.profile_schema_version,
            ));
        }
        validate_text("profileName", &self.profile_name)?;
        let consensus = &self.consensus;
        for (name, value) in [
            ("secondsPerSlot", consensus.seconds_per_slot),
            ("slotsPerEpoch", consensus.slots_per_epoch),
            (
                "epochsPerSyncCommitteePeriod",
                consensus.epochs_per_sync_committee_period,
            ),
            ("syncCommitteeSize", consensus.sync_committee_size),
        ] {
            if value == 0 {
                return Err(ProfileError::ZeroValue(name));
            }
        }
        usize::try_from(consensus.sync_committee_size)
            .map_err(|_| ProfileError::ValueDoesNotFitUsize("syncCommitteeSize"))?;

        validate_count("forkSchedule", consensus.fork_schedule.len())?;
        if consensus.fork_schedule.is_empty() {
            return Err(ProfileError::EmptyList("forkSchedule"));
        }
        let mut fork_ids = BTreeSet::new();
        let mut fork_versions = Vec::with_capacity(consensus.fork_schedule.len());
        let mut previous_epoch = None;
        for fork in &consensus.fork_schedule {
            validate_text("forkId", &fork.fork_id)?;
            if !fork_ids.insert(fork.fork_id.as_str()) {
                return Err(ProfileError::DuplicateForkId(fork.fork_id.clone()));
            }
            if let Some(previous) = previous_epoch {
                if fork.activation_epoch <= previous {
                    return Err(ProfileError::ForkScheduleNotStrictlyIncreasing);
                }
            }
            previous_epoch = Some(fork.activation_epoch);
            fork_versions.push(parse_hex::<4>("forkVersion", &fork.fork_version)?);
        }

        validate_sorted_unique_texts(
            "supportedLightClientHeaderSchemas",
            &consensus.supported_light_client_header_schemas,
        )?;
        validate_sorted_unique_texts(
            "supportedExecutionPayloadHeaderSchemas",
            &consensus.supported_execution_payload_header_schemas,
        )?;
        validate_implemented_header_schema(
            "supportedLightClientHeaderSchemas",
            &consensus.supported_light_client_header_schemas,
        )?;
        validate_implemented_header_schema(
            "supportedExecutionPayloadHeaderSchemas",
            &consensus.supported_execution_payload_header_schemas,
        )?;
        if consensus.supported_light_client_header_schemas
            != consensus.supported_execution_payload_header_schemas
        {
            return Err(ProfileError::HeaderSchemaMismatch);
        }
        validate_gindices(
            "forkSpecificFinalityGindices",
            &consensus.fork_specific_finality_gindices,
            &fork_ids,
        )?;
        validate_gindices(
            "forkSpecificNextCommitteeGindices",
            &consensus.fork_specific_next_committee_gindices,
            &fork_ids,
        )?;
        validate_gindices(
            "forkSpecificExecutionGindices",
            &consensus.fork_specific_execution_gindices,
            &fork_ids,
        )?;

        for (name, value) in [
            (
                "settlementStorageProfileId",
                self.settlement.settlement_storage_profile_id.as_str(),
            ),
            (
                "acceptedLifecycleRuleId",
                self.settlement.accepted_lifecycle_rule_id.as_str(),
            ),
            (
                "nativeRootBindingRuleId",
                self.settlement.native_root_binding_rule_id.as_str(),
            ),
            (
                "zksyncOsVersion",
                self.prividium_l2.zksync_os_version.as_str(),
            ),
            (
                "nativeTreeProfileId",
                self.prividium_l2.native_tree_profile_id.as_str(),
            ),
            (
                "ibcStorageProfileId",
                self.prividium_l2.ibc_storage_profile_id.as_str(),
            ),
            (
                "supportedPathShapeId",
                self.ibc.supported_path_shape_id.as_str(),
            ),
            (
                "applicationAbsenceRule",
                self.prividium_l2.application_absence_rule.as_str(),
            ),
        ] {
            validate_text(name, value)?;
        }
        validate_git_commit(
            "diamondSourceCommit",
            &self.settlement.diamond_source_commit,
        )?;
        validate_git_commit("zksyncOsCommit", &self.prividium_l2.zksync_os_commit)?;
        validate_git_commit("ibcContractsCommit", &self.ibc.ibc_contracts_commit)?;
        if self.prividium_l2.max_client_id_bytes == 0 {
            return Err(ProfileError::ZeroValue("maxClientIdBytes"));
        }
        if self.prividium_l2.chain_id == 0 {
            return Err(ProfileError::ZeroValue("prividiumL2.chainId"));
        }
        if self.prividium_l2.absence_profile_id == 0 {
            return Err(ProfileError::ZeroValue("absenceProfileId"));
        }
        validate_implemented_semantics(&self)?;

        Ok(ValidatedSourceProfileV1 {
            genesis_validators_root: parse_hex::<32>(
                "genesisValidatorsRoot",
                &consensus.genesis_validators_root,
            )?,
            diamond_proxy_address: parse_hex::<20>(
                "diamondProxyAddress",
                &self.settlement.diamond_proxy_address,
            )?,
            ibc_store_address: parse_hex::<20>(
                "ibcStoreAddress",
                &self.prividium_l2.ibc_store_address,
            )?,
            stored_batch_hash_mapping_base_slot: parse_hex::<32>(
                "storedBatchHashMappingBaseSlot",
                &self.settlement.stored_batch_hash_mapping_base_slot,
            )?,
            total_batches_executed_slot: parse_hex::<32>(
                "totalBatchesExecutedSlot",
                &self.settlement.total_batches_executed_slot,
            )?,
            ibc_mapping_base_slot: parse_hex::<32>(
                "ibcMappingBaseSlot",
                &self.prividium_l2.ibc_mapping_base_slot,
            )?,
            source: self,
            fork_versions,
        })
    }
}

impl ValidatedSourceProfileV1 {
    /// Canonical v1 encoding: a fixed magic prefix followed by ordered TLV
    /// fields. Each field is `u16_be(name_len) || name || u32_be(value_len) ||
    /// value`. Lists first encode a u32 count and then indexed fields in their
    /// validated order. Integers are fixed-width big endian.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.raw.extend_from_slice(CANONICAL_MAGIC);
        encoder.u32("profileSchemaVersion", self.source.profile_schema_version)?;
        encoder.text("profileName", &self.source.profile_name)?;
        encoder.fixed(
            "consensus.genesisValidatorsRoot",
            &self.genesis_validators_root,
        )?;
        encoder.u64("consensus.genesisTime", self.source.consensus.genesis_time)?;
        encoder.u64(
            "consensus.secondsPerSlot",
            self.source.consensus.seconds_per_slot,
        )?;
        encoder.u64(
            "consensus.slotsPerEpoch",
            self.source.consensus.slots_per_epoch,
        )?;
        encoder.u64(
            "consensus.epochsPerSyncCommitteePeriod",
            self.source.consensus.epochs_per_sync_committee_period,
        )?;
        encoder.u64(
            "consensus.syncCommitteeSize",
            self.source.consensus.sync_committee_size,
        )?;
        encoder.u32_len(
            "consensus.forkSchedule",
            self.source.consensus.fork_schedule.len(),
        )?;
        for (index, fork) in self.source.consensus.fork_schedule.iter().enumerate() {
            encoder.text(
                &indexed("consensus.forkSchedule", index, "forkId"),
                &fork.fork_id,
            )?;
            encoder.u64(
                &indexed("consensus.forkSchedule", index, "activationEpoch"),
                fork.activation_epoch,
            )?;
            encoder.fixed(
                &indexed("consensus.forkSchedule", index, "forkVersion"),
                &self.fork_versions[index],
            )?;
        }
        encoder.text_list(
            "consensus.supportedLightClientHeaderSchemas",
            &self.source.consensus.supported_light_client_header_schemas,
        )?;
        encoder.text_list(
            "consensus.supportedExecutionPayloadHeaderSchemas",
            &self
                .source
                .consensus
                .supported_execution_payload_header_schemas,
        )?;
        encoder.gindex_list(
            "consensus.forkSpecificFinalityGindices",
            &self.source.consensus.fork_specific_finality_gindices,
        )?;
        encoder.gindex_list(
            "consensus.forkSpecificNextCommitteeGindices",
            &self.source.consensus.fork_specific_next_committee_gindices,
        )?;
        encoder.gindex_list(
            "consensus.forkSpecificExecutionGindices",
            &self.source.consensus.fork_specific_execution_gindices,
        )?;
        encoder.fixed(
            "settlement.diamondProxyAddress",
            &self.diamond_proxy_address,
        )?;
        encoder.text(
            "settlement.diamondSourceCommit",
            &self.source.settlement.diamond_source_commit,
        )?;
        encoder.text(
            "settlement.settlementStorageProfileId",
            &self.source.settlement.settlement_storage_profile_id,
        )?;
        encoder.text(
            "settlement.acceptedLifecycleRuleId",
            &self.source.settlement.accepted_lifecycle_rule_id,
        )?;
        encoder.text(
            "settlement.nativeRootBindingRuleId",
            &self.source.settlement.native_root_binding_rule_id,
        )?;
        encoder.fixed(
            "settlement.storedBatchHashMappingBaseSlot",
            &self.stored_batch_hash_mapping_base_slot,
        )?;
        encoder.fixed(
            "settlement.totalBatchesExecutedSlot",
            &self.total_batches_executed_slot,
        )?;
        encoder.text(
            "prividiumL2.zksyncOsVersion",
            &self.source.prividium_l2.zksync_os_version,
        )?;
        encoder.u64("prividiumL2.chainId", self.source.prividium_l2.chain_id)?;
        encoder.text(
            "prividiumL2.zksyncOsCommit",
            &self.source.prividium_l2.zksync_os_commit,
        )?;
        encoder.text(
            "prividiumL2.nativeTreeProfileId",
            &self.source.prividium_l2.native_tree_profile_id,
        )?;
        encoder.fixed("prividiumL2.ibcStoreAddress", &self.ibc_store_address)?;
        encoder.text(
            "prividiumL2.ibcStorageProfileId",
            &self.source.prividium_l2.ibc_storage_profile_id,
        )?;
        encoder.u32(
            "prividiumL2.absenceProfileId",
            self.source.prividium_l2.absence_profile_id,
        )?;
        encoder.fixed(
            "prividiumL2.ibcMappingBaseSlot",
            &self.ibc_mapping_base_slot,
        )?;
        encoder.u64(
            "prividiumL2.maxClientIdBytes",
            self.source.prividium_l2.max_client_id_bytes,
        )?;
        encoder.text(
            "prividiumL2.applicationAbsenceRule",
            &self.source.prividium_l2.application_absence_rule,
        )?;
        encoder.text(
            "ibc.ibcContractsCommit",
            &self.source.ibc.ibc_contracts_commit,
        )?;
        encoder.text(
            "ibc.supportedPathShapeId",
            &self.source.ibc.supported_path_shape_id,
        )?;
        Ok(encoder.raw)
    }

    pub fn source_profile_id(&self) -> Result<[u8; 32], ProfileError> {
        self.canonical_bytes().map(|bytes| keccak256(&bytes))
    }

    pub fn render_rust_constants(&self) -> Result<String, ProfileError> {
        let profile_id = self.source_profile_id()?;
        let mut output = String::from("// @generated by prividium-source-profile; do not edit.\n");
        writeln!(
            output,
            "pub const SOURCE_PROFILE_ID: [u8; 32] = {profile_id:?};"
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = {:?};",
            self.genesis_validators_root
        )
        .map_err(|_| ProfileError::Render)?;
        for (name, value) in [
            ("SLOTS_PER_EPOCH", self.source.consensus.slots_per_epoch),
            (
                "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
                self.source.consensus.epochs_per_sync_committee_period,
            ),
        ] {
            writeln!(output, "pub const {name}: u64 = {value};")
                .map_err(|_| ProfileError::Render)?;
        }
        writeln!(
            output,
            "pub const SYNC_COMMITTEE_SIZE: usize = {};",
            self.source.consensus.sync_committee_size
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const FORK_SCHEDULE: [(&str, u64, [u8; 4]); {}] = [",
            self.source.consensus.fork_schedule.len()
        )
        .map_err(|_| ProfileError::Render)?;
        for (fork, version) in self
            .source
            .consensus
            .fork_schedule
            .iter()
            .zip(&self.fork_versions)
        {
            writeln!(
                output,
                "    ({:?}, {}, {version:?}),",
                fork.fork_id, fork.activation_epoch
            )
            .map_err(|_| ProfileError::Render)?;
        }
        output.push_str("];\n");
        render_gindices(
            &mut output,
            "FORK_SPECIFIC_FINALITY_GINDICES",
            &self.source.consensus.fork_specific_finality_gindices,
        )?;
        render_gindices(
            &mut output,
            "FORK_SPECIFIC_NEXT_COMMITTEE_GINDICES",
            &self.source.consensus.fork_specific_next_committee_gindices,
        )?;
        render_gindices(
            &mut output,
            "FORK_SPECIFIC_EXECUTION_GINDICES",
            &self.source.consensus.fork_specific_execution_gindices,
        )?;
        writeln!(
            output,
            "pub const DIAMOND_PROXY_ADDRESS: [u8; 20] = {:?};",
            self.diamond_proxy_address
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const PRIVIDIUM_L2_CHAIN_ID: u64 = {};",
            self.source.prividium_l2.chain_id
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const IBC_STORE_ADDRESS: [u8; 20] = {:?};",
            self.ibc_store_address
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const STORED_BATCH_HASH_MAPPING_BASE_SLOT: [u8; 32] = {:?};",
            self.stored_batch_hash_mapping_base_slot
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const TOTAL_BATCHES_EXECUTED_SLOT: [u8; 32] = {:?};",
            self.total_batches_executed_slot
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const IBC_MAPPING_BASE_SLOT: [u8; 32] = {:?};",
            self.ibc_mapping_base_slot
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const MAX_CLIENT_ID_BYTES: usize = {};",
            self.source.prividium_l2.max_client_id_bytes
        )
        .map_err(|_| ProfileError::Render)?;
        writeln!(
            output,
            "pub const ABSENCE_PROFILE_ID: u32 = {};",
            self.source.prividium_l2.absence_profile_id
        )
        .map_err(|_| ProfileError::Render)?;
        for (name, value) in [
            (
                "ACCEPTED_LIFECYCLE_RULE_ID",
                self.source.settlement.accepted_lifecycle_rule_id.as_str(),
            ),
            (
                "NATIVE_ROOT_BINDING_RULE_ID",
                self.source.settlement.native_root_binding_rule_id.as_str(),
            ),
            (
                "APPLICATION_ABSENCE_RULE",
                self.source.prividium_l2.application_absence_rule.as_str(),
            ),
        ] {
            writeln!(output, "pub const {name}: &str = {value:?};")
                .map_err(|_| ProfileError::Render)?;
        }
        Ok(output)
    }
}

fn render_gindices(
    output: &mut String,
    name: &str,
    values: &[ForkGindex],
) -> Result<(), ProfileError> {
    writeln!(
        output,
        "pub const {name}: [(&str, u64); {}] = [",
        values.len()
    )
    .map_err(|_| ProfileError::Render)?;
    for value in values {
        writeln!(
            output,
            "    ({:?}, {}),",
            value.fork_id, value.generalized_index
        )
        .map_err(|_| ProfileError::Render)?;
    }
    output.push_str("];\n");
    Ok(())
}

struct CanonicalEncoder {
    raw: Vec<u8>,
}

impl CanonicalEncoder {
    fn new() -> Self {
        Self { raw: Vec::new() }
    }

    fn field(&mut self, name: &str, value: &[u8]) -> Result<(), ProfileError> {
        let name_len = u16::try_from(name.len()).map_err(|_| ProfileError::CanonicalLength)?;
        let value_len = u32::try_from(value.len()).map_err(|_| ProfileError::CanonicalLength)?;
        self.raw.extend_from_slice(&name_len.to_be_bytes());
        self.raw.extend_from_slice(name.as_bytes());
        self.raw.extend_from_slice(&value_len.to_be_bytes());
        self.raw.extend_from_slice(value);
        Ok(())
    }

    fn fixed(&mut self, name: &str, value: &[u8]) -> Result<(), ProfileError> {
        self.field(name, value)
    }

    fn text(&mut self, name: &str, value: &str) -> Result<(), ProfileError> {
        self.field(name, value.as_bytes())
    }

    fn u32(&mut self, name: &str, value: u32) -> Result<(), ProfileError> {
        self.field(name, &value.to_be_bytes())
    }

    fn u64(&mut self, name: &str, value: u64) -> Result<(), ProfileError> {
        self.field(name, &value.to_be_bytes())
    }

    fn u32_len(&mut self, name: &str, value: usize) -> Result<(), ProfileError> {
        let value = u32::try_from(value).map_err(|_| ProfileError::CanonicalLength)?;
        self.u32(name, value)
    }

    fn text_list(&mut self, name: &str, values: &[String]) -> Result<(), ProfileError> {
        self.u32_len(name, values.len())?;
        for (index, value) in values.iter().enumerate() {
            self.text(&indexed(name, index, "value"), value)?;
        }
        Ok(())
    }

    fn gindex_list(&mut self, name: &str, values: &[ForkGindex]) -> Result<(), ProfileError> {
        self.u32_len(name, values.len())?;
        for (index, value) in values.iter().enumerate() {
            self.text(&indexed(name, index, "forkId"), &value.fork_id)?;
            self.u64(
                &indexed(name, index, "generalizedIndex"),
                value.generalized_index,
            )?;
        }
        Ok(())
    }
}

fn indexed(prefix: &str, index: usize, field: &str) -> String {
    format!("{prefix}[{index}].{field}")
}

fn validate_text(name: &'static str, value: &str) -> Result<(), ProfileError> {
    if value.is_empty() {
        return Err(ProfileError::EmptyText(name));
    }
    if value.len() > MAX_TEXT_BYTES || !value.is_ascii() || value.contains('\0') {
        return Err(ProfileError::InvalidText(name));
    }
    Ok(())
}

fn validate_count(name: &'static str, count: usize) -> Result<(), ProfileError> {
    if count > MAX_LIST_ITEMS {
        return Err(ProfileError::TooManyItems(name));
    }
    Ok(())
}

fn validate_sorted_unique_texts(name: &'static str, values: &[String]) -> Result<(), ProfileError> {
    validate_count(name, values.len())?;
    if values.is_empty() {
        return Err(ProfileError::EmptyList(name));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_text(name, value)?;
        if previous.is_some_and(|entry| entry >= value.as_str()) {
            return Err(ProfileError::ListNotStrictlySorted(name));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_implemented_header_schema(
    name: &'static str,
    values: &[String],
) -> Result<(), ProfileError> {
    if values.len() != 1 || !SUPPORTED_HEADER_SCHEMAS.contains(&values[0].as_str()) {
        return Err(ProfileError::UnsupportedHeaderSchema {
            field: name,
            values: values.to_vec(),
        });
    }
    Ok(())
}

fn validate_gindices(
    name: &'static str,
    values: &[ForkGindex],
    fork_ids: &BTreeSet<&str>,
) -> Result<(), ProfileError> {
    validate_count(name, values.len())?;
    if values.len() != fork_ids.len() {
        return Err(ProfileError::IncompleteForkMapping(name));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        if value.generalized_index <= 1 {
            return Err(ProfileError::InvalidGeneralizedIndex(name));
        }
        if !fork_ids.contains(value.fork_id.as_str()) {
            return Err(ProfileError::UnknownForkInMapping(value.fork_id.clone()));
        }
        if previous.is_some_and(|entry| entry >= value.fork_id.as_str()) {
            return Err(ProfileError::ListNotStrictlySorted(name));
        }
        previous = Some(&value.fork_id);
    }
    Ok(())
}

fn validate_git_commit(name: &'static str, value: &str) -> Result<(), ProfileError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProfileError::InvalidGitCommit(name));
    }
    Ok(())
}

fn validate_implemented_semantics(profile: &SourceProfileV1) -> Result<(), ProfileError> {
    for (field, actual, expected) in [
        (
            "zksyncOsVersion",
            profile.prividium_l2.zksync_os_version.as_str(),
            PINNED_ZKSYNC_OS_VERSION,
        ),
        (
            "zksyncOsCommit",
            profile.prividium_l2.zksync_os_commit.as_str(),
            PINNED_ZKSYNC_OS_COMMIT,
        ),
        (
            "nativeTreeProfileId",
            profile.prividium_l2.native_tree_profile_id.as_str(),
            PINNED_NATIVE_TREE_PROFILE_ID,
        ),
        (
            "nativeRootBindingRuleId",
            profile.settlement.native_root_binding_rule_id.as_str(),
            PINNED_NATIVE_ROOT_BINDING_RULE_ID,
        ),
        (
            "applicationAbsenceRule",
            profile.prividium_l2.application_absence_rule.as_str(),
            PINNED_APPLICATION_ABSENCE_RULE,
        ),
    ] {
        if actual != expected {
            return Err(ProfileError::UnsupportedProfileSelector {
                field,
                value: actual.to_owned(),
            });
        }
    }

    let settlement = &profile.settlement;
    let settlement_supported = matches!(
        (
            settlement.settlement_storage_profile_id.as_str(),
            settlement.accepted_lifecycle_rule_id.as_str(),
        ),
        ("synthetic-layout-v1", "synthetic-executed-v1")
            | (
                "era-contracts-zkos-v0.30.2-zk-chain-storage-v1",
                "zksync-v30.2-executed-batch-v1"
            )
    );
    if !settlement_supported {
        return Err(ProfileError::UnsupportedProfileCombination("settlement"));
    }

    let ibc_supported = matches!(
        (
            profile.prividium_l2.ibc_storage_profile_id.as_str(),
            profile.ibc.supported_path_shape_id.as_str(),
        ),
        ("synthetic-direct-mapping-v1", "synthetic-raw-bytes-v1")
            | (
                "local-direct-word-test-store-v1",
                "local-poc-terminal-path-v1"
            )
            | (EUREKA_STORAGE_PROFILE_ID, EUREKA_PATH_SHAPE_ID)
    );
    if !ibc_supported {
        return Err(ProfileError::UnsupportedProfileCombination("ibc"));
    }
    if profile.prividium_l2.ibc_storage_profile_id == EUREKA_STORAGE_PROFILE_ID
        && parse_hex::<32>(
            "ibcMappingBaseSlot",
            &profile.prividium_l2.ibc_mapping_base_slot,
        )? != EUREKA_COMMITMENTS_MAPPING_SLOT
    {
        return Err(ProfileError::UnsupportedProfileSelector {
            field: "ibcMappingBaseSlot",
            value: profile.prividium_l2.ibc_mapping_base_slot.clone(),
        });
    }

    if profile.prividium_l2.absence_profile_id != PINNED_ABSENCE_PROFILE_ID {
        return Err(ProfileError::UnsupportedAbsenceProfile(
            profile.prividium_l2.absence_profile_id,
        ));
    }
    Ok(())
}

fn parse_hex<const N: usize>(name: &'static str, value: &str) -> Result<[u8; N], ProfileError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(ProfileError::MissingHexPrefix(name))?;
    let expected = N.checked_mul(2).ok_or(ProfileError::CanonicalLength)?;
    if hex.len() != expected {
        return Err(ProfileError::WrongHexLength(name));
    }
    let mut result = [0_u8; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = core::str::from_utf8(pair).map_err(|_| ProfileError::InvalidHex(name))?;
        result[index] = u8::from_str_radix(pair, 16).map_err(|_| ProfileError::InvalidHex(name))?;
    }
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    Json(String),
    UnsupportedSchemaVersion(u32),
    EmptyText(&'static str),
    InvalidText(&'static str),
    ZeroValue(&'static str),
    ValueDoesNotFitUsize(&'static str),
    EmptyList(&'static str),
    TooManyItems(&'static str),
    ListNotStrictlySorted(&'static str),
    DuplicateForkId(String),
    ForkScheduleNotStrictlyIncreasing,
    InvalidGeneralizedIndex(&'static str),
    UnknownForkInMapping(String),
    IncompleteForkMapping(&'static str),
    UnsupportedHeaderSchema {
        field: &'static str,
        values: Vec<String>,
    },
    HeaderSchemaMismatch,
    InvalidGitCommit(&'static str),
    UnsupportedProfileSelector {
        field: &'static str,
        value: String,
    },
    UnsupportedProfileCombination(&'static str),
    UnsupportedAbsenceProfile(u32),
    MissingHexPrefix(&'static str),
    WrongHexLength(&'static str),
    InvalidHex(&'static str),
    CanonicalLength,
    Render,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> SourceProfileV1 {
        SourceProfileV1 {
            profile_schema_version: 1,
            profile_name: "synthetic-local".into(),
            consensus: ConsensusProfile {
                genesis_validators_root: format!("0x{}", "11".repeat(32)),
                genesis_time: 1_700_000_000,
                seconds_per_slot: 12,
                slots_per_epoch: 32,
                epochs_per_sync_committee_period: 256,
                sync_committee_size: 8,
                fork_schedule: vec![ForkScheduleEntry {
                    fork_id: "synthetic-v1".into(),
                    activation_epoch: 0,
                    fork_version: "0x01020304".into(),
                }],
                supported_light_client_header_schemas: vec!["synthetic-v1".into()],
                supported_execution_payload_header_schemas: vec!["synthetic-v1".into()],
                fork_specific_finality_gindices: vec![ForkGindex {
                    fork_id: "synthetic-v1".into(),
                    generalized_index: 105,
                }],
                fork_specific_next_committee_gindices: vec![ForkGindex {
                    fork_id: "synthetic-v1".into(),
                    generalized_index: 55,
                }],
                fork_specific_execution_gindices: vec![ForkGindex {
                    fork_id: "synthetic-v1".into(),
                    generalized_index: 25,
                }],
            },
            settlement: SettlementProfile {
                diamond_proxy_address: format!("0x{}", "22".repeat(20)),
                diamond_source_commit: "33".repeat(20),
                settlement_storage_profile_id: "synthetic-layout-v1".into(),
                accepted_lifecycle_rule_id: "synthetic-executed-v1".into(),
                native_root_binding_rule_id: "zksync-os-v0.20.8-stored-batch-info-v1".into(),
                stored_batch_hash_mapping_base_slot: format!("0x{}", "00".repeat(32)),
                total_batches_executed_slot: format!("0x{}", "00".repeat(31) + "10"),
            },
            prividium_l2: PrividiumL2Profile {
                chain_id: 6_565,
                zksync_os_version: "v0.20.8".into(),
                zksync_os_commit: "dbb5c03d4a94ceb1acea9f79242590f354660239".into(),
                native_tree_profile_id: "zksync-os-v0.20.8-native".into(),
                ibc_store_address: format!("0x{}", "44".repeat(20)),
                ibc_storage_profile_id: "synthetic-direct-mapping-v1".into(),
                absence_profile_id: 1,
                ibc_mapping_base_slot: format!("0x{}", "01".repeat(32)),
                max_client_id_bytes: 128,
                application_absence_rule: "native-non-existing-only-v1".into(),
            },
            ibc: IbcProfile {
                ibc_contracts_commit: "55".repeat(20),
                supported_path_shape_id: "synthetic-raw-bytes-v1".into(),
            },
        }
    }

    #[test]
    fn canonical_bytes_and_id_are_deterministic_across_json_formatting() -> Result<(), ProfileError>
    {
        let compact = serde_json::to_vec(&profile()).unwrap_or_default();
        let pretty = serde_json::to_vec_pretty(&profile()).unwrap_or_default();
        let first = SourceProfileV1::parse_json(&compact)?.validate()?;
        let second = SourceProfileV1::parse_json(&pretty)?.validate()?;
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.source_profile_id(), second.source_profile_id());
        Ok(())
    }

    #[test]
    fn security_field_mutation_changes_profile_id() -> Result<(), ProfileError> {
        let original = profile().validate()?;
        let original_id = original.source_profile_id()?;
        let mut changed = profile();
        changed.prividium_l2.max_client_id_bytes -= 1;
        let changed_id = changed.validate()?.source_profile_id()?;
        assert_ne!(original_id, changed_id);
        let mut changed_chain = profile();
        changed_chain.prividium_l2.chain_id += 1;
        assert_ne!(original_id, changed_chain.validate()?.source_profile_id()?);
        let mut changed_execution_slot = profile();
        changed_execution_slot
            .settlement
            .total_batches_executed_slot = format!("0x{}", "00".repeat(31) + "12");
        assert_ne!(
            original_id,
            changed_execution_slot.validate()?.source_profile_id()?
        );
        Ok(())
    }

    #[test]
    fn unknown_fields_and_incomplete_fork_maps_fail_closed() {
        let mut json = serde_json::to_value(profile()).unwrap_or_default();
        json["unexpected"] = serde_json::Value::Bool(true);
        assert!(
            SourceProfileV1::parse_json(&serde_json::to_vec(&json).unwrap_or_default()).is_err()
        );

        let mut incomplete = profile();
        incomplete
            .consensus
            .fork_specific_execution_gindices
            .clear();
        assert_eq!(
            incomplete.validate(),
            Err(ProfileError::IncompleteForkMapping(
                "forkSpecificExecutionGindices"
            ))
        );
    }

    #[test]
    fn unknown_next_fork_and_zero_gindex_fail_closed() {
        let mut unknown = profile();
        unknown.consensus.fork_specific_finality_gindices[0].fork_id = "other".into();
        assert_eq!(
            unknown.validate(),
            Err(ProfileError::UnknownForkInMapping("other".into()))
        );

        let mut zero = profile();
        zero.consensus.fork_specific_finality_gindices[0].generalized_index = 0;
        assert_eq!(
            zero.validate(),
            Err(ProfileError::InvalidGeneralizedIndex(
                "forkSpecificFinalityGindices"
            ))
        );
    }

    #[test]
    fn unknown_or_mismatched_header_schemas_fail_closed() {
        let mut unknown = profile();
        unknown.consensus.supported_execution_payload_header_schemas = vec!["future-v2".into()];
        assert!(matches!(
            unknown.validate(),
            Err(ProfileError::UnsupportedHeaderSchema {
                field: "supportedExecutionPayloadHeaderSchemas",
                ..
            })
        ));

        let mut mismatched = profile();
        mismatched
            .consensus
            .supported_execution_payload_header_schemas = vec!["fulu-compatibility-v1".into()];
        assert_eq!(
            mismatched.validate(),
            Err(ProfileError::HeaderSchemaMismatch)
        );
    }

    #[test]
    fn unsupported_implementation_selectors_fail_closed() {
        let mut connected = profile();
        connected.settlement.settlement_storage_profile_id =
            "era-contracts-zkos-v0.30.2-zk-chain-storage-v1".into();
        connected.settlement.accepted_lifecycle_rule_id = "zksync-v30.2-executed-batch-v1".into();
        connected.prividium_l2.ibc_storage_profile_id = "local-direct-word-test-store-v1".into();
        connected.ibc.supported_path_shape_id = "local-poc-terminal-path-v1".into();
        assert!(connected.validate().is_ok());

        let mut production = profile();
        production.prividium_l2.ibc_storage_profile_id = EUREKA_STORAGE_PROFILE_ID.into();
        production.ibc.supported_path_shape_id = EUREKA_PATH_SHAPE_ID.into();
        production.prividium_l2.ibc_mapping_base_slot =
            "0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600".into();
        assert!(production.clone().validate().is_ok());

        let mut wrong_production_path = production.clone();
        wrong_production_path.ibc.supported_path_shape_id = "local-poc-terminal-path-v1".into();
        assert_eq!(
            wrong_production_path.validate(),
            Err(ProfileError::UnsupportedProfileCombination("ibc"))
        );

        production.prividium_l2.ibc_mapping_base_slot = format!("0x{}", "00".repeat(32));
        assert!(matches!(
            production.validate(),
            Err(ProfileError::UnsupportedProfileSelector {
                field: "ibcMappingBaseSlot",
                ..
            })
        ));

        let mut wrong_version = profile();
        wrong_version.prividium_l2.zksync_os_version = "v0.20.9".into();
        assert!(matches!(
            wrong_version.validate(),
            Err(ProfileError::UnsupportedProfileSelector {
                field: "zksyncOsVersion",
                ..
            })
        ));

        let mut mixed_settlement = profile();
        mixed_settlement.settlement.accepted_lifecycle_rule_id =
            "zksync-v30.2-stored-batch-hash-equality-v1".into();
        assert_eq!(
            mixed_settlement.validate(),
            Err(ProfileError::UnsupportedProfileCombination("settlement"))
        );

        let mut mixed_ibc = profile();
        mixed_ibc.ibc.supported_path_shape_id = "local-poc-terminal-path-v1".into();
        assert_eq!(
            mixed_ibc.validate(),
            Err(ProfileError::UnsupportedProfileCombination("ibc"))
        );

        let mut wrong_absence = profile();
        wrong_absence.prividium_l2.absence_profile_id = 2;
        assert_eq!(
            wrong_absence.validate(),
            Err(ProfileError::UnsupportedAbsenceProfile(2))
        );
    }

    #[test]
    fn generated_constants_include_runtime_security_dispatch() -> Result<(), ProfileError> {
        let validated = profile().validate()?;
        let rendered = validated.render_rust_constants()?;
        for required in [
            "SOURCE_PROFILE_ID",
            "SYNC_COMMITTEE_SIZE: usize",
            "FORK_SCHEDULE",
            "FORK_SPECIFIC_FINALITY_GINDICES",
            "FORK_SPECIFIC_NEXT_COMMITTEE_GINDICES",
            "FORK_SPECIFIC_EXECUTION_GINDICES",
            "ACCEPTED_LIFECYCLE_RULE_ID",
            "TOTAL_BATCHES_EXECUTED_SLOT",
            "NATIVE_ROOT_BINDING_RULE_ID",
            "APPLICATION_ABSENCE_RULE",
            "ABSENCE_PROFILE_ID",
        ] {
            assert!(rendered.contains(required), "missing {required}");
        }
        Ok(())
    }
}
