// SPDX-License-Identifier: Apache-2.0

use prividium_proof_api::bootstrap::validate_initial_trust_artifact;
use std::{env, fs, path::PathBuf};

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("prividium-validate-initial-trust: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let input = arguments.next().map(PathBuf::from).ok_or(
        "usage: prividium-validate-initial-trust INITIAL_TRUST.json SOURCE_PROFILE_ID SYNC_COMMITTEE_SIZE",
    )?;
    let source_profile_id = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("SourceProfile ID is required and must be UTF-8")?;
    let committee_size = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("sync committee size is required")?
        .parse::<usize>()?;
    if arguments.next().is_some() {
        return Err("too many arguments".into());
    }
    if committee_size == 0 {
        return Err("sync committee size must be nonzero".into());
    }

    let metadata = fs::metadata(&input)?;
    if !metadata.is_file() {
        return Err("initial trust input must be a regular file".into());
    }
    if metadata.len() > MAX_ARTIFACT_BYTES {
        return Err("initial trust artifact exceeds 16 MiB".into());
    }
    let body = fs::read(&input)?;
    validate_initial_trust_artifact(&body, &source_profile_id, committee_size)?;
    println!("initial trust artifact is valid");
    Ok(())
}
