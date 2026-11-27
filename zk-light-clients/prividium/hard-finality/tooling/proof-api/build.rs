// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/prover.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/prover.proto"], &["proto"])?;
    if std::env::var_os("CARGO_FEATURE_SP1").is_some() {
        configure_sp1_programs()?;
    }
    Ok(())
}

fn configure_sp1_programs() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PRIVIDIUM_SP1_ELF_DIR");
    let programs = [
        "prividium-trust-update-program",
        "prividium-settlement-update-program",
        "prividium-membership-program",
        "prividium-non-membership-program",
    ];
    let configured = std::env::var_os("PRIVIDIUM_SP1_ELF_DIR").ok_or_else(|| {
        std::io::Error::other("PRIVIDIUM_SP1_ELF_DIR is required for the combined Proof API build")
    })?;
    let elf_directory = std::path::PathBuf::from(configured).canonicalize()?;
    for binary in programs {
        let requested = elf_directory.join(binary);
        let path = requested.canonicalize().map_err(|error| {
            std::io::Error::other(format!(
                "required reviewed SP1 ELF {} is unavailable: {error}",
                requested.display()
            ))
        })?;
        if !path.is_file() {
            return Err(std::io::Error::other(format!(
                "required reviewed SP1 ELF is not a file: {}",
                path.display()
            ))
            .into());
        }
        let bytes = std::fs::read(&path)?;
        if !bytes.starts_with(b"\x7fELF") {
            return Err(std::io::Error::other(format!(
                "required reviewed SP1 program is not an ELF file: {}",
                path.display()
            ))
            .into());
        }
        println!("cargo:rerun-if-changed={}", path.display());
        println!("cargo:rustc-env=SP1_ELF_{binary}={}", path.display());
    }
    Ok(())
}
