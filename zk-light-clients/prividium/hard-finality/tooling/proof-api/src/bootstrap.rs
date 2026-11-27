// SPDX-License-Identifier: Apache-2.0

use crate::{config::ResolvedBootstrap, http::read_response_bounded, EngineError};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;

const MAX_INITIAL_TRUST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum BootstrapMaterial {
    Lighthouse { response: serde_json::Value },
    InitialTrust { artifact: InitialTrustArtifact },
}
impl BootstrapMaterial {
    pub fn current_sync_committee(&self) -> Result<SyncCommittee, EngineError> {
        match self {
            Self::InitialTrust { artifact } => Ok(artifact.current_sync_committee.clone()),
            Self::Lighthouse { response } => {
                let value = response
                    .pointer("/data/current_sync_committee")
                    .cloned()
                    .ok_or_else(|| {
                        EngineError::InvalidRequest(
                            "Lighthouse bootstrap lacks current sync committee".into(),
                        )
                    })?;
                serde_json::from_value(value).map_err(|error| {
                    EngineError::InvalidRequest(format!(
                        "invalid Lighthouse current sync committee: {error}"
                    ))
                })
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitialTrustArtifact {
    pub purpose: String,
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_header_root: String,
    pub current_sync_committee_root: String,
    pub next_sync_committee_root: String,
    pub next_sync_committee_known: bool,
    pub source_profile_id: String,
    pub current_sync_committee: SyncCommittee,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncCommittee {
    pub pubkeys: Vec<String>,
    pub aggregate_pubkey: String,
}

#[derive(Deserialize)]
struct BootstrapEnvelope {
    version: String,
    data: BootstrapData,
}

#[derive(Deserialize)]
struct BootstrapData {
    header: BootstrapHeader,
    current_sync_committee: SyncCommittee,
}

#[derive(Deserialize)]
struct BootstrapHeader {
    beacon: BeaconHeader,
}

#[derive(Deserialize)]
struct BeaconHeader {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
    body_root: String,
}

pub struct BootstrapResolver {
    config: ResolvedBootstrap,
    client: HttpClient,
}

impl BootstrapResolver {
    pub fn new(
        config: ResolvedBootstrap,
        timeout: std::time::Duration,
    ) -> Result<Self, EngineError> {
        let client = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| EngineError::Internal(format!("build Beacon HTTP client: {error}")))?;
        Ok(Self { config, client })
    }

    /// Resolves bootstrap material once at startup.
    ///
    /// Only an explicit HTTP 404 activates the pinned artifact fallback.
    pub fn resolve(&self) -> Result<BootstrapMaterial, EngineError> {
        let path = format!(
            "/eth/v1/beacon/light_client/bootstrap/{}",
            self.config.finalized_checkpoint_root
        );
        let url = self
            .config
            .url
            .join(&path)
            .map_err(|error| EngineError::Internal(format!("Beacon URL: {error}")))?;
        let mut request = self.client.get(url).header("Accept", "application/json");
        if let Some(authorization) = &self.config.authorization {
            request = request.header("Authorization", authorization);
        }
        let response = request
            .send()
            .map_err(|error| EngineError::Unavailable(format!("Beacon bootstrap: {error}")))?;
        let status = response.status();
        let body = read_response_bounded(response, self.config.max_response_bytes)
            .map_err(|error| EngineError::Unavailable(error.to_string()))?;
        self.resolve_response(status, &body)
    }

    fn resolve_response(
        &self,
        status: reqwest::StatusCode,
        body: &[u8],
    ) -> Result<BootstrapMaterial, EngineError> {
        if status == reqwest::StatusCode::NOT_FOUND {
            return self.load_initial_trust();
        }
        if !status.is_success() {
            return Err(EngineError::Unavailable(format!(
                "Beacon bootstrap returned HTTP {}",
                status.as_u16()
            )));
        }
        validate_lighthouse_bootstrap(body, &self.config)?;
        let response = strict_json(body, "Lighthouse bootstrap")?;
        Ok(BootstrapMaterial::Lighthouse { response })
    }

    fn load_initial_trust(&self) -> Result<BootstrapMaterial, EngineError> {
        let metadata = fs::metadata(&self.config.initial_trust_path).map_err(|error| {
            EngineError::Unavailable(format!(
                "inspect initial trust artifact {}: {error}",
                self.config.initial_trust_path.display()
            ))
        })?;
        if metadata.len() > MAX_INITIAL_TRUST_BYTES {
            return Err(EngineError::InvalidRequest(
                "initial trust artifact exceeds 16 MiB".into(),
            ));
        }
        let body = fs::read(&self.config.initial_trust_path).map_err(|error| {
            EngineError::Unavailable(format!(
                "read initial trust artifact {}: {error}",
                self.config.initial_trust_path.display()
            ))
        })?;
        let digest = hex::encode(Sha256::digest(&body));
        if digest != self.config.initial_trust_sha256 {
            return Err(EngineError::InvalidRequest(
                "initial trust artifact SHA-256 mismatch".into(),
            ));
        }
        let artifact: InitialTrustArtifact = strict_json(&body, "initial trust artifact")?;
        validate_initial_trust(&artifact, &self.config)?;
        Ok(BootstrapMaterial::InitialTrust { artifact })
    }
}

fn validate_lighthouse_bootstrap(
    body: &[u8],
    config: &ResolvedBootstrap,
) -> Result<(), EngineError> {
    build_initial_trust_artifact(
        body,
        &config.finalized_checkpoint_root,
        &config.source_profile_id,
        config.sync_committee_size,
    )?;
    Ok(())
}

/// Converts one Lighthouse light-client bootstrap response into the pinned
/// initial-trust artifact used by the hard-finality contract and Proof API.
///
/// The conversion applies the same strict fork, checkpoint-root,
/// committee-size and BLS-key validation as the live bootstrap resolver.
pub fn build_initial_trust_artifact(
    body: &[u8],
    finalized_checkpoint_root: &str,
    source_profile_id: &str,
    sync_committee_size: usize,
) -> Result<InitialTrustArtifact, EngineError> {
    let envelope: BootstrapEnvelope = strict_json(body, "Lighthouse bootstrap")?;
    if envelope.version != "fulu" {
        return Err(EngineError::InvalidRequest(format!(
            "unsupported Beacon bootstrap fork {}",
            envelope.version
        )));
    }
    let root = beacon_header_root(&envelope.data.header.beacon)?;
    let expected_root = decode_fixed::<32>("finalized checkpoint root", finalized_checkpoint_root)?;
    if root != expected_root {
        return Err(EngineError::InvalidRequest(
            "Lighthouse bootstrap header does not match configured checkpoint root".into(),
        ));
    }
    let source_profile_id_bytes = decode_fixed::<32>("sourceProfileId", source_profile_id)?;
    if source_profile_id_bytes == [0_u8; 32] {
        return Err(EngineError::InvalidRequest(
            "sourceProfileId must be nonzero".into(),
        ));
    }
    if envelope.data.current_sync_committee.pubkeys.len() != sync_committee_size {
        return Err(EngineError::InvalidRequest(format!(
            "Lighthouse bootstrap committee has {} keys; expected {}",
            envelope.data.current_sync_committee.pubkeys.len(),
            sync_committee_size
        )));
    }
    for public_key in &envelope.data.current_sync_committee.pubkeys {
        decode_fixed::<48>("sync committee public key", public_key)?;
    }
    decode_fixed::<48>(
        "sync committee aggregate public key",
        &envelope.data.current_sync_committee.aggregate_pubkey,
    )?;
    let committee_root = sync_committee_root(&envelope.data.current_sync_committee)?;
    let slot = parse_decimal_u64("beacon slot", &envelope.data.header.beacon.slot)?;
    if slot == 0 {
        return Err(EngineError::InvalidRequest(
            "finalized Beacon slot must be nonzero".into(),
        ));
    }

    Ok(InitialTrustArtifact {
        purpose: "reviewed production initial trust anchor".into(),
        finalized_beacon_slot: slot,
        finalized_beacon_header_root: format!("0x{}", hex::encode(root)),
        current_sync_committee_root: format!("0x{}", hex::encode(committee_root)),
        next_sync_committee_root: format!("0x{}", "00".repeat(32)),
        next_sync_committee_known: false,
        source_profile_id: format!("0x{}", hex::encode(source_profile_id_bytes)),
        current_sync_committee: envelope.data.current_sync_committee,
    })
}

/// Strictly validates an initial-trust artifact before it is used as a
/// production contract-deployment input.
pub fn validate_initial_trust_artifact(
    body: &[u8],
    source_profile_id: &str,
    sync_committee_size: usize,
) -> Result<InitialTrustArtifact, EngineError> {
    let artifact: InitialTrustArtifact = strict_json(body, "initial trust artifact")?;
    if artifact.purpose != "reviewed production initial trust anchor" {
        return Err(EngineError::InvalidRequest(
            "deployment initial trust must be a reviewed production trust anchor".into(),
        ));
    }
    if artifact.finalized_beacon_slot == 0 {
        return Err(EngineError::InvalidRequest(
            "initial trust finalized Beacon slot must be nonzero".into(),
        ));
    }
    let finalized_root = decode_fixed::<32>(
        "finalizedBeaconHeaderRoot",
        &artifact.finalized_beacon_header_root,
    )?;
    let current_root = decode_fixed::<32>(
        "currentSyncCommitteeRoot",
        &artifact.current_sync_committee_root,
    )?;
    if finalized_root == [0_u8; 32] || current_root == [0_u8; 32] {
        return Err(EngineError::InvalidRequest(
            "initial trust finalized and current committee roots must be nonzero".into(),
        ));
    }
    let next_root =
        decode_fixed::<32>("nextSyncCommitteeRoot", &artifact.next_sync_committee_root)?;
    let expected_profile = decode_fixed::<32>("sourceProfileId", source_profile_id)?;
    if expected_profile == [0_u8; 32]
        || decode_fixed::<32>("artifact sourceProfileId", &artifact.source_profile_id)?
            != expected_profile
    {
        return Err(EngineError::InvalidRequest(
            "initial trust SourceProfile ID does not match deployment profile".into(),
        ));
    }
    if artifact.current_sync_committee.pubkeys.len() != sync_committee_size {
        return Err(EngineError::InvalidRequest(format!(
            "initial trust committee has {} keys; expected {}",
            artifact.current_sync_committee.pubkeys.len(),
            sync_committee_size
        )));
    }
    for public_key in &artifact.current_sync_committee.pubkeys {
        decode_fixed::<48>("sync committee public key", public_key)?;
    }
    decode_fixed::<48>(
        "sync committee aggregate public key",
        &artifact.current_sync_committee.aggregate_pubkey,
    )?;
    if sync_committee_root(&artifact.current_sync_committee)? != current_root {
        return Err(EngineError::InvalidRequest(
            "initial trust current committee does not match its declared root".into(),
        ));
    }
    if (!artifact.next_sync_committee_known && next_root != [0_u8; 32])
        || (artifact.next_sync_committee_known && next_root == [0_u8; 32])
    {
        return Err(EngineError::InvalidRequest(
            "initial trust next committee flag and root are inconsistent".into(),
        ));
    }
    Ok(artifact)
}

fn validate_initial_trust(
    artifact: &InitialTrustArtifact,
    config: &ResolvedBootstrap,
) -> Result<(), EngineError> {
    if artifact.purpose != "reviewed production initial trust anchor"
        && artifact.purpose != "demo-only initial trust anchor"
    {
        return Err(EngineError::InvalidRequest(
            "initial trust artifact purpose must identify a reviewed production or demo trust anchor"
                .into(),
        ));
    }
    if artifact.finalized_beacon_slot == 0 {
        return Err(EngineError::InvalidRequest(
            "initial trust finalized Beacon slot must be nonzero".into(),
        ));
    }
    if artifact.finalized_beacon_header_root != config.finalized_checkpoint_root {
        return Err(EngineError::InvalidRequest(
            "initial trust root does not match configured finalized checkpoint".into(),
        ));
    }
    let finalized_root = decode_fixed::<32>(
        "finalizedBeaconHeaderRoot",
        &artifact.finalized_beacon_header_root,
    )?;
    let current_root = decode_fixed::<32>(
        "currentSyncCommitteeRoot",
        &artifact.current_sync_committee_root,
    )?;
    if finalized_root == [0; 32] || current_root == [0; 32] {
        return Err(EngineError::InvalidRequest(
            "initial trust finalized and current committee roots must be nonzero".into(),
        ));
    }
    let next_root =
        decode_fixed::<32>("nextSyncCommitteeRoot", &artifact.next_sync_committee_root)?;
    decode_fixed::<32>("sourceProfileId", &artifact.source_profile_id)?;
    if artifact.source_profile_id != config.source_profile_id {
        return Err(EngineError::InvalidRequest(
            "initial trust SourceProfile ID does not match configuration".into(),
        ));
    }
    if artifact.current_sync_committee.pubkeys.len() != config.sync_committee_size {
        return Err(EngineError::InvalidRequest(format!(
            "initial trust committee has {} keys; expected {}",
            artifact.current_sync_committee.pubkeys.len(),
            config.sync_committee_size
        )));
    }
    for public_key in &artifact.current_sync_committee.pubkeys {
        decode_fixed::<48>("sync committee public key", public_key)?;
    }
    decode_fixed::<48>(
        "sync committee aggregate public key",
        &artifact.current_sync_committee.aggregate_pubkey,
    )?;
    let computed_committee_root = sync_committee_root(&artifact.current_sync_committee)?;
    if computed_committee_root
        != decode_fixed::<32>(
            "currentSyncCommitteeRoot",
            &artifact.current_sync_committee_root,
        )?
    {
        return Err(EngineError::InvalidRequest(
            "initial trust current committee does not match its declared root".into(),
        ));
    }
    if !artifact.next_sync_committee_known && next_root != [0_u8; 32] {
        return Err(EngineError::InvalidRequest(
            "unknown next committee must use the zero root".into(),
        ));
    }
    if artifact.next_sync_committee_known && next_root == [0_u8; 32] {
        return Err(EngineError::InvalidRequest(
            "known next committee must use a nonzero root".into(),
        ));
    }
    Ok(())
}

pub(crate) fn sync_committee_root(committee: &SyncCommittee) -> Result<[u8; 32], EngineError> {
    let public_key_roots = committee
        .pubkeys
        .iter()
        .map(|value| public_key_root(value))
        .collect::<Result<Vec<_>, _>>()?;
    let pubkeys_root = merkleize(public_key_roots)?;
    let aggregate_root = public_key_root(&committee.aggregate_pubkey)?;
    Ok(hash_pair(pubkeys_root, aggregate_root))
}

fn public_key_root(value: &str) -> Result<[u8; 32], EngineError> {
    let bytes = decode_fixed::<48>("sync committee public key", value)?;
    let mut first = [0_u8; 32];
    first.copy_from_slice(&bytes[..32]);
    let mut second = [0_u8; 32];
    second[..16].copy_from_slice(&bytes[32..]);
    Ok(hash_pair(first, second))
}

fn merkleize(mut leaves: Vec<[u8; 32]>) -> Result<[u8; 32], EngineError> {
    if leaves.is_empty() {
        return Err(EngineError::InvalidRequest(
            "sync committee must not be empty".into(),
        ));
    }
    leaves.resize(leaves.len().next_power_of_two(), [0_u8; 32]);
    while leaves.len() > 1 {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    Ok(leaves[0])
}

fn beacon_header_root(header: &BeaconHeader) -> Result<[u8; 32], EngineError> {
    let leaves = [
        uint64_root(parse_decimal_u64("beacon slot", &header.slot)?),
        uint64_root(parse_decimal_u64(
            "beacon proposer index",
            &header.proposer_index,
        )?),
        decode_fixed::<32>("beacon parent root", &header.parent_root)?,
        decode_fixed::<32>("beacon state root", &header.state_root)?,
        decode_fixed::<32>("beacon body root", &header.body_root)?,
        [0_u8; 32],
        [0_u8; 32],
        [0_u8; 32],
    ];
    let level_one = [
        hash_pair(leaves[0], leaves[1]),
        hash_pair(leaves[2], leaves[3]),
        hash_pair(leaves[4], leaves[5]),
        hash_pair(leaves[6], leaves[7]),
    ];
    let level_two = [
        hash_pair(level_one[0], level_one[1]),
        hash_pair(level_one[2], level_one[3]),
    ];
    Ok(hash_pair(level_two[0], level_two[1]))
}

fn uint64_root(value: u64) -> [u8; 32] {
    let mut root = [0_u8; 32];
    root[..8].copy_from_slice(&value.to_le_bytes());
    root
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn parse_decimal_u64(field: &str, value: &str) -> Result<u64, EngineError> {
    value
        .parse()
        .map_err(|_| EngineError::InvalidRequest(format!("{field} is not a decimal u64")))
}

fn decode_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], EngineError> {
    let hex_value = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::InvalidRequest(format!("{field} lacks 0x prefix")))?;
    let bytes = hex::decode(hex_value)
        .map_err(|_| EngineError::InvalidRequest(format!("{field} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| EngineError::InvalidRequest(format!("{field} must be {N} bytes")))
}

fn strict_json<T: for<'de> Deserialize<'de>>(body: &[u8], label: &str) -> Result<T, EngineError> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = T::deserialize(&mut decoder)
        .map_err(|error| EngineError::InvalidRequest(format!("invalid {label}: {error}")))?;
    decoder.end().map_err(|error| {
        EngineError::InvalidRequest(format!("trailing data in {label}: {error}"))
    })?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn header() -> BeaconHeader {
        BeaconHeader {
            slot: "1".into(),
            proposer_index: "2".into(),
            parent_root: format!("0x{}", "11".repeat(32)),
            state_root: format!("0x{}", "22".repeat(32)),
            body_root: format!("0x{}", "33".repeat(32)),
        }
    }

    #[test]
    fn beacon_header_root_is_sensitive_to_slot() {
        let first = header();
        let mut second = header();
        second.slot = "2".into();
        assert_ne!(beacon_header_root(&first), beacon_header_root(&second));
    }

    #[test]
    fn fixed_hex_rejects_wrong_length() {
        assert!(decode_fixed::<32>("root", "0x12").is_err());
        assert!(decode_fixed::<32>("root", &format!("0x{}", "12".repeat(32))).is_ok());
    }

    fn fallback_resolver() -> (BootstrapResolver, std::path::PathBuf) {
        static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "prividium-initial-trust-{}-{}.json",
            std::process::id(),
            NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let root = format!("0x{}", "11".repeat(32));
        let zero_root = format!("0x{}", "00".repeat(32));
        let public_key = format!("0x{}", "00".repeat(48));
        let committee = SyncCommittee {
            pubkeys: vec![public_key.clone()],
            aggregate_pubkey: public_key.clone(),
        };
        let committee_root = format!(
            "0x{}",
            hex::encode(sync_committee_root(&committee).unwrap_or_default())
        );
        let artifact = serde_json::json!({
            "purpose": "demo-only initial trust anchor",
            "finalizedBeaconSlot": 1,
            "finalizedBeaconHeaderRoot": root,
            "currentSyncCommitteeRoot": committee_root,
            "nextSyncCommitteeRoot": zero_root,
            "nextSyncCommitteeKnown": false,
            "sourceProfileId": root,
            "currentSyncCommittee": {
                "pubkeys": [public_key],
                "aggregatePubkey": public_key,
            }
        });
        let bytes = serde_json::to_vec(&artifact).unwrap_or_default();
        assert!(fs::write(&path, &bytes).is_ok());
        let config = ResolvedBootstrap {
            url: url::Url::parse("http://127.0.0.1/").unwrap_or_else(|_| unreachable!()),
            authorization: None,
            finalized_checkpoint_root: root.clone(),
            source_profile_id: root,
            source_profile_id_bytes: [0x11_u8; 32],
            initial_trust_path: path.clone(),
            initial_trust_sha256: hex::encode(Sha256::digest(&bytes)),
            sync_committee_size: 1,
            slots_per_epoch: 32,
            epochs_per_sync_committee_period: 256,
            max_response_bytes: 1024,
        };
        let resolver = BootstrapResolver::new(config, std::time::Duration::from_secs(1))
            .unwrap_or_else(|_| unreachable!());
        (resolver, path)
    }

    #[test]
    fn only_not_found_uses_pinned_initial_trust() {
        let (resolver, path) = fallback_resolver();
        let fallback = resolver.resolve_response(reqwest::StatusCode::NOT_FOUND, b"ignored");
        assert!(matches!(
            fallback,
            Ok(BootstrapMaterial::InitialTrust { .. })
        ));
        let server_error =
            resolver.resolve_response(reqwest::StatusCode::INTERNAL_SERVER_ERROR, b"ignored");
        assert!(matches!(server_error, Err(EngineError::Unavailable(_))));
        assert!(fs::remove_file(path).is_ok());
    }

    #[test]
    fn lighthouse_bootstrap_is_bound_to_checkpoint_and_committee() {
        let (mut resolver, path) = fallback_resolver();
        let header = header();
        resolver.config.finalized_checkpoint_root =
            format!("0x{}", hex::encode(beacon_header_root(&header).unwrap()));
        let public_key = format!("0x{}", "12".repeat(48));
        let body = serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": {
                "header": {"beacon": {
                    "slot": header.slot,
                    "proposer_index": header.proposer_index,
                    "parent_root": header.parent_root,
                    "state_root": header.state_root,
                    "body_root": header.body_root
                }},
                "current_sync_committee": {
                    "pubkeys": [public_key.clone()],
                    "aggregatePubkey": public_key
                }
            }
        }))
        .unwrap();
        let material = resolver
            .resolve_response(reqwest::StatusCode::OK, &body)
            .unwrap();
        assert_eq!(material.current_sync_committee().unwrap().pubkeys.len(), 1);

        let artifact = build_initial_trust_artifact(
            &body,
            &resolver.config.finalized_checkpoint_root,
            &resolver.config.source_profile_id,
            resolver.config.sync_committee_size,
        )
        .unwrap();
        assert_eq!(artifact.finalized_beacon_slot, 1);
        assert_eq!(
            artifact.finalized_beacon_header_root,
            resolver.config.finalized_checkpoint_root
        );
        assert_eq!(
            artifact.source_profile_id,
            resolver.config.source_profile_id
        );
        assert_eq!(artifact.current_sync_committee.pubkeys.len(), 1);
        assert!(!artifact.next_sync_committee_known);
        let artifact_body = serde_json::to_vec(&artifact).unwrap();
        assert!(validate_initial_trust_artifact(
            &artifact_body,
            &resolver.config.source_profile_id,
            resolver.config.sync_committee_size,
        )
        .is_ok());
        let mut wrong_artifact = artifact;
        wrong_artifact.current_sync_committee_root = format!("0x{}", "99".repeat(32));
        assert!(validate_initial_trust_artifact(
            &serde_json::to_vec(&wrong_artifact).unwrap(),
            &resolver.config.source_profile_id,
            resolver.config.sync_committee_size,
        )
        .is_err());

        let mut wrong_fork: Value = serde_json::from_slice(&body).unwrap();
        wrong_fork["version"] = serde_json::json!("deneb");
        assert!(validate_lighthouse_bootstrap(
            &serde_json::to_vec(&wrong_fork).unwrap(),
            &resolver.config
        )
        .is_err());
        assert!(strict_json::<Value>(b"{} trailing", "value").is_err());
        assert!(parse_decimal_u64("slot", "bad").is_err());
        assert!(merkleize(vec![]).is_err());
        assert!(fs::remove_file(path).is_ok());
    }

    #[test]
    fn initial_trust_validation_rejects_policy_and_root_mismatches() {
        let (resolver, path) = fallback_resolver();
        let material = resolver.load_initial_trust().unwrap();
        let BootstrapMaterial::InitialTrust { artifact } = material else {
            unreachable!()
        };
        assert_eq!(artifact.current_sync_committee.pubkeys.len(), 1);

        let mut wrong = artifact.clone();
        wrong.purpose = "unreviewed".into();
        assert!(validate_initial_trust(&wrong, &resolver.config).is_err());
        let mut wrong = artifact.clone();
        wrong.finalized_beacon_slot = 0;
        assert!(validate_initial_trust(&wrong, &resolver.config).is_err());
        let mut wrong = artifact.clone();
        wrong.source_profile_id = format!("0x{}", "99".repeat(32));
        assert!(validate_initial_trust(&wrong, &resolver.config).is_err());
        let mut wrong = artifact;
        wrong.next_sync_committee_known = true;
        assert!(validate_initial_trust(&wrong, &resolver.config).is_err());
        assert!(fs::remove_file(path).is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn deployment_artifact_validation_rejects_each_invalid_trust_binding() {
        let (mut resolver, path) = fallback_resolver();
        let header = header();
        resolver.config.finalized_checkpoint_root =
            format!("0x{}", hex::encode(beacon_header_root(&header).unwrap()));
        let public_key = format!("0x{}", "12".repeat(48));
        let body = serde_json::to_vec(&serde_json::json!({
            "version": "fulu",
            "data": {
                "header": {"beacon": {
                    "slot": header.slot,
                    "proposer_index": header.proposer_index,
                    "parent_root": header.parent_root,
                    "state_root": header.state_root,
                    "body_root": header.body_root
                }},
                "current_sync_committee": {
                    "pubkeys": [public_key.clone()],
                    "aggregatePubkey": public_key
                }
            }
        }))
        .unwrap();
        let valid = build_initial_trust_artifact(
            &body,
            &resolver.config.finalized_checkpoint_root,
            &resolver.config.source_profile_id,
            1,
        )
        .unwrap();
        let validate = |artifact: &InitialTrustArtifact| {
            validate_initial_trust_artifact(
                &serde_json::to_vec(artifact).unwrap(),
                &resolver.config.source_profile_id,
                1,
            )
        };

        let mut changed = valid.clone();
        changed.purpose = "demo-only initial trust anchor".into();
        assert!(validate(&changed).is_err());
        let mut changed = valid.clone();
        changed.finalized_beacon_slot = 0;
        assert!(validate(&changed).is_err());
        for field in ["finalized", "current"] {
            let mut changed = valid.clone();
            if field == "finalized" {
                changed.finalized_beacon_header_root = format!("0x{}", "00".repeat(32));
            } else {
                changed.current_sync_committee_root = format!("0x{}", "00".repeat(32));
            }
            assert!(validate(&changed).is_err());
        }
        let mut changed = valid.clone();
        changed.source_profile_id = format!("0x{}", "99".repeat(32));
        assert!(validate(&changed).is_err());
        let mut changed = valid.clone();
        changed.current_sync_committee.pubkeys.clear();
        assert!(validate(&changed).is_err());
        let mut changed = valid.clone();
        changed.current_sync_committee.pubkeys[0] = "0x01".into();
        assert!(validate(&changed).is_err());
        let mut changed = valid.clone();
        changed.current_sync_committee.aggregate_pubkey = "0x01".into();
        assert!(validate(&changed).is_err());
        for (known, root) in [(false, "11"), (true, "00")] {
            let mut changed = valid.clone();
            changed.next_sync_committee_known = known;
            changed.next_sync_committee_root = format!("0x{}", root.repeat(32));
            assert!(validate(&changed).is_err());
        }

        assert!(build_initial_trust_artifact(
            &body,
            &format!("0x{}", "99".repeat(32)),
            &resolver.config.source_profile_id,
            1,
        )
        .is_err());
        assert!(build_initial_trust_artifact(
            &body,
            &resolver.config.finalized_checkpoint_root,
            &format!("0x{}", "00".repeat(32)),
            1,
        )
        .is_err());
        assert!(build_initial_trust_artifact(
            &body,
            &resolver.config.finalized_checkpoint_root,
            &resolver.config.source_profile_id,
            2,
        )
        .is_err());
        let mut zero_slot: Value = serde_json::from_slice(&body).unwrap();
        zero_slot["data"]["header"]["beacon"]["slot"] = serde_json::json!("0");
        let zero_slot = serde_json::to_vec(&zero_slot).unwrap();
        assert!(build_initial_trust_artifact(
            &zero_slot,
            &format!(
                "0x{}",
                hex::encode(
                    beacon_header_root(&BeaconHeader {
                        slot: "0".into(),
                        ..header
                    })
                    .unwrap()
                )
            ),
            &resolver.config.source_profile_id,
            1,
        )
        .is_err());
        assert!(fs::remove_file(path).is_ok());
    }

    #[test]
    fn pinned_trust_loading_checks_files_and_digests() {
        let (mut resolver, path) = fallback_resolver();
        resolver.config.initial_trust_sha256 = "00".repeat(32);
        assert!(resolver.load_initial_trust().is_err());
        resolver.config.initial_trust_path = path.with_extension("missing");
        assert!(resolver.load_initial_trust().is_err());
        assert!(fs::remove_file(path).is_ok());
    }
}
