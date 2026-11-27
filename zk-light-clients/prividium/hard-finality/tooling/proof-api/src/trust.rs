// SPDX-License-Identifier: Apache-2.0

use crate::{
    bootstrap::{sync_committee_root, BootstrapMaterial, SyncCommittee},
    config::ResolvedBootstrap,
    destination::TrustSnapshot,
    http::read_response_bounded,
    EngineError,
};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustUpdateEvidence {
    pub start_period: u64,
    pub signing_sync_committee: SyncCommittee,
    pub update: Value,
}

pub trait TrustEvidenceSource: Send + Sync + 'static {
    fn collect(&self, previous: &TrustSnapshot) -> Result<TrustUpdateEvidence, EngineError>;
    fn signing_committee(
        &self,
        trust: &TrustSnapshot,
        signature_slot: u64,
    ) -> Result<SyncCommittee, EngineError>;
}

#[cfg(any(feature = "sp1", test))]
pub(crate) fn validate_settlement_attested_header(
    trust: &TrustSnapshot,
    attested_slot: u64,
    attested_root: [u8; 32],
) -> Result<(), EngineError> {
    let previous = prividium_types::ConsensusTrustState {
        finalized_beacon_slot: trust.state.finalized_beacon_slot,
        finalized_beacon_header_root: trust.state.finalized_beacon_header_root,
        current_sync_committee_root: trust.state.current_sync_committee_root,
        next_sync_committee_root: trust.state.next_sync_committee_root,
        next_sync_committee_known: trust.state.next_sync_committee_known,
    };
    prividium_consensus::validate_attested_header_against_trust(
        &previous,
        attested_slot,
        attested_root,
    )
    .map_err(|error| {
        EngineError::InvalidRequest(format!(
            "Beacon optimistic header conflicts with destination finalized trust: {error:?}"
        ))
    })
}

#[derive(Clone)]
pub struct BeaconTrustUpdateCollector {
    config: ResolvedBootstrap,
    client: HttpClient,
    committees: Arc<Mutex<BTreeMap<[u8; 32], SyncCommittee>>>,
}

impl BeaconTrustUpdateCollector {
    pub fn new(
        config: ResolvedBootstrap,
        timeout: std::time::Duration,
        bootstrap: &BootstrapMaterial,
    ) -> Result<Self, EngineError> {
        let committee = bootstrap.current_sync_committee()?;
        validate_committee(&committee, config.sync_committee_size)?;
        let root = sync_committee_root(&committee)?;
        let client = HttpClient::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| EngineError::Internal(format!("build Beacon HTTP client: {error}")))?;
        Ok(Self {
            config,
            client,
            committees: Arc::new(Mutex::new(BTreeMap::from([(root, committee)]))),
        })
    }

    fn slots_per_period(&self) -> Result<u64, EngineError> {
        self.config
            .slots_per_epoch
            .checked_mul(self.config.epochs_per_sync_committee_period)
            .ok_or_else(|| EngineError::Internal("sync committee period size overflow".into()))
    }

    fn fetch_update(&self, start_period: u64) -> Result<Value, EngineError> {
        let mut url = self
            .config
            .url
            .join("/eth/v1/beacon/light_client/updates")
            .map_err(|error| EngineError::Internal(format!("Beacon URL: {error}")))?;
        url.query_pairs_mut()
            .append_pair("start_period", &start_period.to_string())
            .append_pair("count", "1");
        let mut request = self.client.get(url).header("Accept", "application/json");
        if let Some(authorization) = &self.config.authorization {
            request = request.header("Authorization", authorization);
        }
        let response = request
            .send()
            .map_err(|error| EngineError::Unavailable(format!("Beacon update: {error}")))?;
        let status = response.status();
        let body = read_response_bounded(response, self.config.max_response_bytes)
            .map_err(|error| EngineError::Unavailable(error.to_string()))?;
        if !status.is_success() {
            return Err(EngineError::Unavailable(format!(
                "Beacon update returned HTTP {}",
                status.as_u16()
            )));
        }
        let mut decoder = serde_json::Deserializer::from_slice(&body);
        let updates = Vec::<Value>::deserialize(&mut decoder)
            .map_err(|error| EngineError::Unavailable(format!("invalid Beacon update: {error}")))?;
        decoder.end().map_err(|error| {
            EngineError::Unavailable(format!("trailing Beacon update data: {error}"))
        })?;
        if updates.len() != 1 {
            return Err(EngineError::Unavailable(format!(
                "Beacon update returned {} entries; expected exactly one",
                updates.len()
            )));
        }
        updates
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::Unavailable("Beacon update is empty".into()))
    }
    fn cache_next_committee(&self, update: &Value) -> Result<(), EngineError> {
        let committee: SyncCommittee = serde_json::from_value(
            update
                .pointer("/data/next_sync_committee")
                .cloned()
                .ok_or_else(|| {
                    EngineError::Unavailable("Beacon update lacks next sync committee".into())
                })?,
        )
        .map_err(|error| {
            EngineError::Unavailable(format!("invalid next sync committee: {error}"))
        })?;
        validate_committee(&committee, self.config.sync_committee_size)?;
        let root = sync_committee_root(&committee)?;
        self.committees
            .lock()
            .map_err(|_| EngineError::Internal("sync committee cache is poisoned".into()))?
            .insert(root, committee);
        Ok(())
    }

    fn cached_committee(&self, root: [u8; 32]) -> Result<Option<SyncCommittee>, EngineError> {
        Ok(self
            .committees
            .lock()
            .map_err(|_| EngineError::Internal("sync committee cache is poisoned".into()))?
            .get(&root)
            .cloned())
    }
}

impl TrustEvidenceSource for BeaconTrustUpdateCollector {
    fn collect(&self, previous: &TrustSnapshot) -> Result<TrustUpdateEvidence, EngineError> {
        let slots_per_period = self.slots_per_period()?;
        let start_period = previous.state.finalized_beacon_slot / slots_per_period;
        let update = self.fetch_update(start_period)?;
        validate_update_shape(&update, self.config.sync_committee_size)?;

        let version = text_at(&update, "/version", "update version")?;
        if version != "fulu" {
            return Err(EngineError::Unavailable(format!(
                "unsupported Beacon update fork {version}"
            )));
        }
        let signature_slot = decimal_at(&update, "/data/signature_slot", "signature slot")?;
        let attested_slot = decimal_at(
            &update,
            "/data/attested_header/beacon/slot",
            "attested slot",
        )?;
        let finalized_slot = decimal_at(
            &update,
            "/data/finalized_header/beacon/slot",
            "finalized slot",
        )?;
        if signature_slot <= attested_slot
            || attested_slot < finalized_slot
            || finalized_slot < previous.state.finalized_beacon_slot
        {
            return Err(EngineError::Unavailable(
                "Beacon update does not form a monotonic finalized transition".into(),
            ));
        }

        let signature_period = signature_slot / slots_per_period;
        let expected_root = if signature_period == start_period {
            previous.state.current_sync_committee_root
        } else if signature_period == start_period.saturating_add(1)
            && previous.state.next_sync_committee_known
        {
            previous.state.next_sync_committee_root
        } else {
            return Err(EngineError::Unavailable(
                "Beacon update signature period is not reachable from destination trust".into(),
            ));
        };

        self.cache_next_committee(&update)?;
        let mut signing_sync_committee = self.cached_committee(expected_root)?;
        if signing_sync_committee.is_none() && start_period > 0 {
            let preceding_update = self.fetch_update(start_period - 1)?;
            validate_update_shape(&preceding_update, self.config.sync_committee_size)?;
            if text_at(&preceding_update, "/version", "preceding update version")? != "fulu" {
                return Err(EngineError::Unavailable(
                    "preceding Beacon update is not Fulu".into(),
                ));
            }
            self.cache_next_committee(&preceding_update)?;
            signing_sync_committee = self.cached_committee(expected_root)?;
        }
        let signing_sync_committee = signing_sync_committee.ok_or_else(|| {
            EngineError::Unavailable(
                "full signing sync committee is unavailable for destination trust".into(),
            )
        })?;

        Ok(TrustUpdateEvidence {
            start_period,
            signing_sync_committee,
            update,
        })
    }

    fn signing_committee(
        &self,
        trust: &TrustSnapshot,
        signature_slot: u64,
    ) -> Result<SyncCommittee, EngineError> {
        let slots_per_period = self.slots_per_period()?;
        let trusted_period = trust.state.finalized_beacon_slot / slots_per_period;
        let signature_period = signature_slot / slots_per_period;
        let expected_root = if signature_period == trusted_period {
            trust.state.current_sync_committee_root
        } else if signature_period == trusted_period.saturating_add(1)
            && trust.state.next_sync_committee_known
        {
            trust.state.next_sync_committee_root
        } else {
            return Err(EngineError::Unavailable(
                "Settlement signature period is not reachable from destination trust".into(),
            ));
        };
        if let Some(committee) = self.cached_committee(expected_root)? {
            return Ok(committee);
        }
        if trusted_period > 0 {
            let preceding_update = self.fetch_update(trusted_period - 1)?;
            validate_update_shape(&preceding_update, self.config.sync_committee_size)?;
            if text_at(&preceding_update, "/version", "preceding update version")? != "fulu" {
                return Err(EngineError::Unavailable(
                    "preceding Beacon update is not Fulu".into(),
                ));
            }
            self.cache_next_committee(&preceding_update)?;
        }
        self.cached_committee(expected_root)?.ok_or_else(|| {
            EngineError::Unavailable("full Settlement signing sync committee is unavailable".into())
        })
    }
}

fn validate_update_shape(update: &Value, committee_size: usize) -> Result<(), EngineError> {
    require_hex_at(
        update,
        "/data/sync_aggregate/sync_committee_signature",
        "sync committee signature",
        96,
    )?;
    let bits = decode_hex(
        "sync committee bits",
        text_at(
            update,
            "/data/sync_aggregate/sync_committee_bits",
            "sync committee bits",
        )?,
    )?;
    let expected_bytes = committee_size.div_ceil(8);
    if bits.len() != expected_bytes {
        return Err(EngineError::Unavailable(format!(
            "sync committee bitfield has {} bytes; expected {expected_bytes}",
            bits.len()
        )));
    }
    let participants: usize = bits.iter().map(|byte| byte.count_ones() as usize).sum();
    for index in committee_size..(bits.len() * 8) {
        if bits[index / 8] & (1 << (index % 8)) != 0 {
            return Err(EngineError::Unavailable(
                "sync committee bitfield has nonzero padding bits".into(),
            ));
        }
    }
    if participants == 0 || participants.saturating_mul(3) < committee_size.saturating_mul(2) {
        return Err(EngineError::Unavailable(
            "sync committee participation is below two thirds".into(),
        ));
    }
    require_branch(update, "/data/finality_branch", "finality branch", 7)?;
    require_branch(
        update,
        "/data/next_sync_committee_branch",
        "next sync committee branch",
        6,
    )
}

fn validate_committee(committee: &SyncCommittee, expected_size: usize) -> Result<(), EngineError> {
    if committee.pubkeys.len() != expected_size {
        return Err(EngineError::Unavailable(format!(
            "sync committee has {} keys; expected {expected_size}",
            committee.pubkeys.len()
        )));
    }
    for public_key in &committee.pubkeys {
        let _ = decode_hex_exact("sync committee public key", public_key, 48)?;
    }
    let _ = decode_hex_exact(
        "sync committee aggregate public key",
        &committee.aggregate_pubkey,
        48,
    )?;
    Ok(())
}

fn require_branch(
    value: &Value,
    pointer: &str,
    field: &str,
    expected_length: usize,
) -> Result<(), EngineError> {
    let branch = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} is missing")))?;
    if branch.len() != expected_length {
        return Err(EngineError::Unavailable(format!(
            "{field} has {} nodes; expected {expected_length}",
            branch.len()
        )));
    }
    for node in branch {
        let node = node
            .as_str()
            .ok_or_else(|| EngineError::Unavailable(format!("{field} node is not text")))?;
        let _ = decode_hex_exact(field, node, 32)?;
    }
    Ok(())
}

fn require_hex_at(
    value: &Value,
    pointer: &str,
    field: &str,
    bytes: usize,
) -> Result<(), EngineError> {
    let _ = decode_hex_exact(field, text_at(value, pointer, field)?, bytes)?;
    Ok(())
}

fn decimal_at(value: &Value, pointer: &str, field: &str) -> Result<u64, EngineError> {
    text_at(value, pointer, field)?
        .parse()
        .map_err(|_| EngineError::Unavailable(format!("{field} is not a decimal u64")))
}

fn text_at<'a>(value: &'a Value, pointer: &str, field: &str) -> Result<&'a str, EngineError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| EngineError::Unavailable(format!("{field} is missing")))
}

fn decode_hex_exact(field: &str, value: &str, bytes: usize) -> Result<Vec<u8>, EngineError> {
    let decoded = decode_hex(field, value)?;
    if decoded.len() != bytes {
        return Err(EngineError::Unavailable(format!(
            "{field} must be exactly {bytes} bytes"
        )));
    }
    Ok(decoded)
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, EngineError> {
    let body = value
        .strip_prefix("0x")
        .ok_or_else(|| EngineError::Unavailable(format!("{field} lacks 0x prefix")))?;
    hex::decode(body).map_err(|_| EngineError::Unavailable(format!("{field} is not valid hex")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::destination::ConsensusTrustState;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    fn committee(byte: u8) -> SyncCommittee {
        SyncCommittee {
            pubkeys: (0..8)
                .map(|index| format!("0x{}", hex::encode([byte + index; 48])))
                .collect(),
            aggregate_pubkey: format!("0x{}", hex::encode([byte; 48])),
        }
    }

    fn update(next: &SyncCommittee) -> Value {
        json!({
            "version": "fulu",
            "data": {
                "signature_slot": "70",
                "attested_header": {"beacon": {"slot": "69"}},
                "finalized_header": {"beacon": {"slot": "68"}},
                "sync_aggregate": {
                    "sync_committee_signature": format!("0x{}", "11".repeat(96)),
                    "sync_committee_bits": "0xff"
                },
                "finality_branch": vec![format!("0x{}", "22".repeat(32)); 7],
                "next_sync_committee": next,
                "next_sync_committee_branch": vec![format!("0x{}", "33".repeat(32)); 6]
            }
        })
    }

    fn serve(value: Value) -> url::Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains("start_period=1&count=1"));
            let body = json!([value]).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        url::Url::parse(&format!("http://{address}/")).unwrap()
    }

    fn serve_raw(status: &str, body: String, authorization: Option<&str>) -> url::Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let authorization = authorization.map(str::to_owned);
        let status = status.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            if let Some(authorization) = authorization {
                assert!(request.to_ascii_lowercase().contains(&format!(
                    "authorization: {}",
                    authorization.to_ascii_lowercase()
                )));
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        url::Url::parse(&format!("http://{address}/")).unwrap()
    }

    fn collector(url: url::Url, current: SyncCommittee) -> BeaconTrustUpdateCollector {
        let current_root = sync_committee_root(&current).unwrap();
        BeaconTrustUpdateCollector {
            config: ResolvedBootstrap {
                source_profile_id_bytes: [1; 32],
                url,
                authorization: None,
                finalized_checkpoint_root: format!("0x{}", "11".repeat(32)),
                source_profile_id: format!("0x{}", "12".repeat(32)),
                initial_trust_path: "/tmp/trust.json".into(),
                initial_trust_sha256: "13".repeat(32),
                sync_committee_size: 8,
                slots_per_epoch: 8,
                epochs_per_sync_committee_period: 8,
                max_response_bytes: 64 * 1024,
            },
            client: HttpClient::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            committees: Arc::new(Mutex::new(BTreeMap::from([(current_root, current)]))),
        }
    }

    #[test]
    fn collector_authenticates_monotonic_fulu_update() {
        let current = committee(1);
        let next = committee(20);
        let current_root = sync_committee_root(&current).unwrap();
        let collector = BeaconTrustUpdateCollector {
            config: ResolvedBootstrap {
                source_profile_id_bytes: [1; 32],
                url: serve(update(&next)),
                authorization: None,
                finalized_checkpoint_root: format!("0x{}", "11".repeat(32)),
                source_profile_id: format!("0x{}", "12".repeat(32)),
                initial_trust_path: "/tmp/trust.json".into(),
                initial_trust_sha256: "13".repeat(32),
                sync_committee_size: 8,
                slots_per_epoch: 8,
                epochs_per_sync_committee_period: 8,
                max_response_bytes: 64 * 1024,
            },
            client: HttpClient::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            committees: Arc::new(Mutex::new(BTreeMap::from([(
                current_root,
                current.clone(),
            )]))),
        };
        let previous = TrustSnapshot {
            block_number: 1,
            digest: [9; 32],
            state: ConsensusTrustState {
                finalized_beacon_slot: 64,
                finalized_beacon_header_root: [2; 32],
                current_sync_committee_root: current_root,
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: false,
            },
        };
        let evidence = collector.collect(&previous).unwrap();
        assert_eq!(evidence.start_period, 1);
        assert_eq!(evidence.signing_sync_committee.pubkeys, current.pubkeys);
        assert!(collector
            .cached_committee(sync_committee_root(&next).unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn update_shape_committee_and_scalar_decoders_are_strict() {
        let next = committee(20);
        let valid = update(&next);
        assert!(validate_update_shape(&valid, 8).is_ok());
        assert!(validate_committee(&next, 8).is_ok());
        assert_eq!(decimal_at(&json!({"n":"42"}), "/n", "n").unwrap(), 42);
        assert_eq!(text_at(&json!({"v":"ok"}), "/v", "v").unwrap(), "ok");
        assert_eq!(decode_hex_exact("x", "0x0102", 2).unwrap(), vec![1, 2]);

        let mut no_participants = valid.clone();
        no_participants["data"]["sync_aggregate"]["sync_committee_bits"] = json!("0x00");
        assert!(validate_update_shape(&no_participants, 8).is_err());
        let mut short_branch = valid.clone();
        short_branch["data"]["finality_branch"] = json!([]);
        assert!(validate_update_shape(&short_branch, 8).is_err());
        let mut wrong_bits = valid;
        wrong_bits["data"]["sync_aggregate"]["sync_committee_bits"] = json!("0xffff");
        assert!(validate_update_shape(&wrong_bits, 8).is_err());
        assert!(validate_committee(&committee(1), 9).is_err());
        assert!(decode_hex("x", "01").is_err());
        assert!(decode_hex("x", "0xzz").is_err());
        assert!(decode_hex_exact("x", "0x01", 2).is_err());
        assert!(decimal_at(&json!({"n":"bad"}), "/n", "n").is_err());
        assert!(text_at(&json!({}), "/v", "v").is_err());
    }

    #[test]
    fn collector_initialization_pins_bootstrap_committee_and_period() {
        let initial = committee(1);
        let bootstrap = BootstrapMaterial::Lighthouse {
            response: json!({"data":{"current_sync_committee":{
                "pubkeys": initial.pubkeys,
                "aggregatePubkey": initial.aggregate_pubkey
            }}}),
        };
        let collector = BeaconTrustUpdateCollector::new(
            ResolvedBootstrap {
                source_profile_id_bytes: [1; 32],
                url: url::Url::parse("http://127.0.0.1:1/").unwrap(),
                authorization: Some("Bearer token".into()),
                finalized_checkpoint_root: format!("0x{}", "11".repeat(32)),
                source_profile_id: format!("0x{}", "12".repeat(32)),
                initial_trust_path: "/tmp/trust.json".into(),
                initial_trust_sha256: "13".repeat(32),
                sync_committee_size: 8,
                slots_per_epoch: 8,
                epochs_per_sync_committee_period: 8,
                max_response_bytes: 1024,
            },
            Duration::from_secs(1),
            &bootstrap,
        )
        .unwrap();
        assert_eq!(collector.slots_per_period(), Ok(64));
        assert_eq!(collector.committees.lock().unwrap().len(), 1);
    }

    #[test]
    fn signing_committee_selection_is_period_bound() {
        let current = committee(1);
        let current_root = sync_committee_root(&current).unwrap();
        let collector = collector(
            url::Url::parse("http://127.0.0.1:1/").unwrap(),
            current.clone(),
        );
        let trust = TrustSnapshot {
            block_number: 1,
            digest: [9; 32],
            state: ConsensusTrustState {
                finalized_beacon_slot: 64,
                finalized_beacon_header_root: [2; 32],
                current_sync_committee_root: current_root,
                next_sync_committee_root: [3; 32],
                next_sync_committee_known: true,
            },
        };
        assert_eq!(
            collector.signing_committee(&trust, 70).unwrap().pubkeys,
            current.pubkeys
        );
        assert!(collector.signing_committee(&trust, 192).is_err());
    }

    #[test]
    fn settlement_attested_header_respects_finalized_trust() {
        let trust = TrustSnapshot {
            block_number: 1,
            digest: [9; 32],
            state: ConsensusTrustState {
                finalized_beacon_slot: 64,
                finalized_beacon_header_root: [2; 32],
                current_sync_committee_root: [3; 32],
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: false,
            },
        };
        assert!(validate_settlement_attested_header(&trust, 63, [2; 32]).is_err());
        assert!(validate_settlement_attested_header(&trust, 64, [4; 32]).is_err());
        assert!(validate_settlement_attested_header(&trust, 64, [2; 32]).is_ok());
        assert!(validate_settlement_attested_header(&trust, 65, [4; 32]).is_ok());
    }

    #[test]
    fn update_fetch_and_transition_errors_are_explicit() {
        let current = committee(1);
        let next = committee(20);
        let mut wrong_fork = update(&next);
        wrong_fork["version"] = json!("deneb");
        let previous = TrustSnapshot {
            block_number: 1,
            digest: [9; 32],
            state: ConsensusTrustState {
                finalized_beacon_slot: 64,
                finalized_beacon_header_root: [2; 32],
                current_sync_committee_root: sync_committee_root(&current).unwrap(),
                next_sync_committee_root: [0; 32],
                next_sync_committee_known: false,
            },
        };
        assert!(collector(serve(wrong_fork), current.clone())
            .collect(&previous)
            .is_err());

        let mut nonmonotonic = update(&next);
        nonmonotonic["data"]["finalized_header"]["beacon"]["slot"] = json!("63");
        assert!(collector(serve(nonmonotonic), current.clone())
            .collect(&previous)
            .is_err());

        let mut unreachable = update(&next);
        unreachable["data"]["signature_slot"] = json!("192");
        unreachable["data"]["attested_header"]["beacon"]["slot"] = json!("191");
        unreachable["data"]["finalized_header"]["beacon"]["slot"] = json!("190");
        assert!(collector(serve(unreachable), current.clone())
            .collect(&previous)
            .is_err());

        let url = serve_raw(
            "500 Internal Server Error",
            "{}".into(),
            Some("Bearer test"),
        );
        let mut authenticated_collector = collector(url, current.clone());
        authenticated_collector.config.authorization = Some("Bearer test".into());
        assert!(authenticated_collector.fetch_update(1).is_err());

        let url = serve_raw("200 OK", "[]".into(), None);
        assert!(collector(url, current.clone()).fetch_update(1).is_err());
        let url = serve_raw("200 OK", "not-json".into(), None);
        assert!(collector(url, current.clone()).fetch_update(1).is_err());
        let url = serve_raw("200 OK", "[{}] trailing".into(), None);
        assert!(collector(url, current).fetch_update(1).is_err());
    }

    #[test]
    fn shape_validation_rejects_padding_and_malformed_branches() {
        let next = committee(20);
        let mut padded = update(&next);
        padded["data"]["sync_aggregate"]["sync_committee_bits"] = json!("0xff");
        assert!(validate_update_shape(&padded, 7).is_err());

        let mut node_not_text = update(&next);
        node_not_text["data"]["finality_branch"][0] = json!(1);
        assert!(validate_update_shape(&node_not_text, 8).is_err());
        let mut node_wrong_size = update(&next);
        node_wrong_size["data"]["finality_branch"][0] = json!("0x01");
        assert!(validate_update_shape(&node_wrong_size, 8).is_err());
        let mut no_signature = update(&next);
        no_signature["data"]["sync_aggregate"]
            .as_object_mut()
            .unwrap()
            .remove("sync_committee_signature");
        assert!(validate_update_shape(&no_signature, 8).is_err());

        let mut bad_committee = committee(1);
        bad_committee.pubkeys[0] = "0x01".into();
        assert!(validate_committee(&bad_committee, 8).is_err());
        let mut bad_committee = committee(1);
        bad_committee.aggregate_pubkey = "0x01".into();
        assert!(validate_committee(&bad_committee, 8).is_err());
    }
}
