// SPDX-License-Identifier: Apache-2.0

#![no_std]

use blake2::{Blake2s256, Digest as _};
use sha2::Sha256;
use sha3::Keccak256;

pub type Hash32 = [u8; 32];

#[must_use]
pub fn sha256(bytes: &[u8]) -> Hash32 {
    Sha256::digest(bytes).into()
}

#[must_use]
pub fn sha256_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[must_use]
pub fn keccak256(bytes: &[u8]) -> Hash32 {
    Keccak256::digest(bytes).into()
}

#[must_use]
pub fn blake2s(bytes: &[u8]) -> Hash32 {
    Blake2s256::digest(bytes).into()
}

#[must_use]
pub fn blake2s_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Blake2s256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_empty_input_vectors() {
        assert_eq!(
            sha256(b""),
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            keccak256(b""),
            hex32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            blake2s(b""),
            hex32("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    #[test]
    fn pair_helpers_are_unambiguous_concatenation() {
        let left = [0x11; 32];
        let right = [0x22; 32];
        let mut joined = [0_u8; 64];
        joined[..32].copy_from_slice(&left);
        joined[32..].copy_from_slice(&right);
        assert_eq!(sha256_pair(&left, &right), sha256(&joined));
        assert_eq!(blake2s_pair(&left, &right), blake2s(&joined));
    }

    fn hex32(value: &str) -> Hash32 {
        let mut out = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = core::str::from_utf8(chunk).unwrap_or_default();
            out[index] = u8::from_str_radix(text, 16).unwrap_or_default();
        }
        out
    }
}
