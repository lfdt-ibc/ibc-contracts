// SPDX-License-Identifier: Apache-2.0

use blake2::{Blake2s256, Digest as _};
use std::{env, fmt::Write as _, fs, path::PathBuf};

const HASH_BYTES: usize = 32;
const TREE_DEPTH: usize = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    // H(0) is the protocol's all-zero leaf. Higher empty subtrees satisfy
    // H(d + 1) = BLAKE2s(H(d) || H(d)). Generate source constants on the
    // build host so the zkVM does not recompute 65 invariant hashes per proof.
    let mut hashes = [[0_u8; HASH_BYTES]; TREE_DEPTH + 1];
    hashes[0] = Blake2s256::digest([0_u8; 72]).into();
    for depth in 1..=TREE_DEPTH {
        let mut preimage = [0_u8; HASH_BYTES * 2];
        preimage[..HASH_BYTES].copy_from_slice(&hashes[depth - 1]);
        preimage[HASH_BYTES..].copy_from_slice(&hashes[depth - 1]);
        hashes[depth] = Blake2s256::digest(preimage).into();
    }

    let mut generated = String::from(
        "pub(crate) const EMPTY_SUBTREE_HASHES: [Hash; TREE_DEPTH as usize + 1] = [\n",
    );
    for hash in hashes {
        generated.push_str("    [");
        for (index, byte) in hash.iter().enumerate() {
            if index != 0 {
                generated.push_str(", ");
            }
            write!(generated, "0x{byte:02x}")?;
        }
        generated.push_str("],\n");
    }
    generated.push_str("];\n");

    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?)
        .join("empty_subtree_hashes.rs");
    fs::write(output, generated)?;
    Ok(())
}
