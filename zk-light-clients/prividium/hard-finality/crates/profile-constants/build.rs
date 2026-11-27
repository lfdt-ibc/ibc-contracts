// SPDX-License-Identifier: Apache-2.0

use prividium_source_profile::SourceProfileV1;
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PRIVIDIUM_SOURCE_PROFILE");
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| std::io::Error::other("CARGO_MANIFEST_DIR is missing"))?,
    );
    let workspace = manifest.join("../..");
    let supplied = env::var_os("PRIVIDIUM_SOURCE_PROFILE").ok_or_else(|| {
        std::io::Error::other(
            "PRIVIDIUM_SOURCE_PROFILE is required; select the synthetic profile explicitly for local tests and a reviewed production profile for release builds",
        )
    })?;
    let supplied = PathBuf::from(supplied);
    let profile_path = if supplied.is_absolute() {
        supplied
    } else {
        workspace.join(supplied)
    };
    let profile_path = profile_path.canonicalize().map_err(|error| {
        std::io::Error::other(format!(
            "cannot resolve source profile {}: {error}",
            profile_path.display()
        ))
    })?;
    println!("cargo:rerun-if-changed={}", profile_path.display());

    let bytes = fs::read(&profile_path)?;
    let profile = SourceProfileV1::parse_json(&bytes)
        .and_then(SourceProfileV1::validate)
        .map_err(|error| {
            std::io::Error::other(format!(
                "invalid source profile {}: {error:?}",
                profile_path.display()
            ))
        })?;
    let generated = profile.render_rust_constants().map_err(|error| {
        std::io::Error::other(format!("failed to render source profile: {error:?}"))
    })?;
    let out = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| std::io::Error::other("OUT_DIR is missing"))?,
    )
    .join("source_profile.rs");
    fs::write(out, generated)?;
    Ok(())
}
