// SPDX-License-Identifier: Apache-2.0

use prividium_proof_api::bootstrap::build_initial_trust_artifact;
use std::{env, fs, io::Write as _, path::PathBuf};

const MAX_BOOTSTRAP_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("prividium-bootstrap-artifact: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let input = arguments.next().map(PathBuf::from).ok_or(
        "usage: prividium-bootstrap-artifact BOOTSTRAP.json CHECKPOINT_ROOT SOURCE_PROFILE_ID SYNC_COMMITTEE_SIZE",
    )?;
    let checkpoint_root = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("checkpoint root is required and must be UTF-8")?;
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
        return Err("bootstrap input must be a regular file".into());
    }
    if metadata.len() > MAX_BOOTSTRAP_BYTES {
        return Err("Lighthouse bootstrap response exceeds 16 MiB".into());
    }
    let body = fs::read(&input)?;
    let artifact =
        build_initial_trust_artifact(&body, &checkpoint_root, &source_profile_id, committee_size)?;

    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &artifact)?;
    output.write_all(b"\n")?;
    Ok(())
}
