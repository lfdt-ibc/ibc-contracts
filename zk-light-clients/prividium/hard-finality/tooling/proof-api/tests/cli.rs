// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{fs, process::Command};

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn beacon_root() -> [u8; 32] {
    let mut slot = [0_u8; 32];
    slot[..8].copy_from_slice(&1_u64.to_le_bytes());
    let mut proposer = [0_u8; 32];
    proposer[..8].copy_from_slice(&2_u64.to_le_bytes());
    let leaves = [
        slot, proposer, [0x11; 32], [0x22; 32], [0x33; 32], [0; 32], [0; 32], [0; 32],
    ];
    let first = [
        hash_pair(leaves[0], leaves[1]),
        hash_pair(leaves[2], leaves[3]),
        hash_pair(leaves[4], leaves[5]),
        hash_pair(leaves[6], leaves[7]),
    ];
    hash_pair(hash_pair(first[0], first[1]), hash_pair(first[2], first[3]))
}

#[test]
fn bootstrap_and_validation_clis_process_one_reviewed_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let bootstrap_path = directory.path().join("bootstrap.json");
    let artifact_path = directory.path().join("initial-trust.json");
    let public_key = format!("0x{}", "12".repeat(48));
    fs::write(
        &bootstrap_path,
        serde_json::to_vec(&json!({
            "version": "fulu",
            "data": {
                "header": {"beacon": {
                    "slot": "1",
                    "proposer_index": "2",
                    "parent_root": format!("0x{}", "11".repeat(32)),
                    "state_root": format!("0x{}", "22".repeat(32)),
                    "body_root": format!("0x{}", "33".repeat(32))
                }},
                "current_sync_committee": {
                    "pubkeys": [public_key.clone()],
                    "aggregatePubkey": public_key
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let profile = format!("0x{}", "44".repeat(32));
    let output = Command::new(env!("CARGO_BIN_EXE_bootstrap-artifact"))
        .args([
            bootstrap_path.to_str().unwrap(),
            &format!("0x{}", hex::encode(beacon_root())),
            &profile,
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::write(&artifact_path, output.stdout).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_validate-initial-trust"))
        .args([artifact_path.to_str().unwrap(), &profile, "1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "initial trust artifact is valid\n"
    );
}

#[test]
fn bootstrap_and_validation_clis_reject_invalid_arguments() {
    for binary in [
        env!("CARGO_BIN_EXE_bootstrap-artifact"),
        env!("CARGO_BIN_EXE_validate-initial-trust"),
    ] {
        assert!(!Command::new(binary).status().unwrap().success());
    }

    let directory = tempfile::tempdir().unwrap();
    assert!(!Command::new(env!("CARGO_BIN_EXE_bootstrap-artifact"))
        .args([
            directory.path().to_str().unwrap(),
            &format!("0x{}", "11".repeat(32)),
            &format!("0x{}", "22".repeat(32)),
            "0",
        ])
        .status()
        .unwrap()
        .success());
    assert!(!Command::new(env!("CARGO_BIN_EXE_validate-initial-trust"))
        .args([
            directory.path().to_str().unwrap(),
            &format!("0x{}", "22".repeat(32)),
            "0",
            "extra",
        ])
        .status()
        .unwrap()
        .success());
}
