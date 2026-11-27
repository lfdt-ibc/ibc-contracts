// SPDX-License-Identifier: Apache-2.0

use prividium_source_profile::SourceProfileV1;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("profilec: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let _program = args.next();
    let input = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: profilec INPUT.json OUTPUT.rs".to_owned())?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: profilec INPUT.json OUTPUT.rs".to_owned())?;
    if args.next().is_some() {
        return Err("usage: profilec INPUT.json OUTPUT.rs".to_owned());
    }
    let raw = fs::read(&input).map_err(|error| format!("read {}: {error}", input.display()))?;
    let profile = SourceProfileV1::parse_json(&raw)
        .and_then(SourceProfileV1::validate)
        .map_err(|error| format!("invalid profile: {error:?}"))?;
    let rendered = profile
        .render_rust_constants()
        .map_err(|error| format!("render constants: {error:?}"))?;
    fs::write(&output, rendered).map_err(|error| format!("write {}: {error}", output.display()))?;
    let profile_id = profile
        .source_profile_id()
        .map_err(|error| format!("hash profile: {error:?}"))?;
    println!("SOURCE_PROFILE_ID=0x{}", hex(&profile_id));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
