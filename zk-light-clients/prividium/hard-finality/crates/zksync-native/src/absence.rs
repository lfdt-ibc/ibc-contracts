// SPDX-License-Identifier: Apache-2.0

use crate::{error::ProofError, proof::NativeProofBatch, Address, Hash};

/// Verifies source-defined native-tree absence for one address/slot/root.
///
/// This deliberately does not decide whether native absence, an existing
/// zero-valued word, or another state means application-level IBC absence.
pub fn verify_native_absence(
    proof: &NativeProofBatch,
    queried_address: &Address,
    queried_slot: &Hash,
    expected_root: &Hash,
) -> Result<(), ProofError> {
    match proof.verify_single_against_root(queried_address, queried_slot, expected_root)? {
        None => Ok(()),
        Some(_) => Err(ProofError::ExpectedNativeAbsence),
    }
}

/// Equivalent to [`verify_native_absence`], using a flat key that the caller
/// has already derived from `queried_address` and `queried_slot`.
pub fn verify_native_absence_with_flat_key(
    proof: &NativeProofBatch,
    queried_address: &Address,
    queried_slot: &Hash,
    queried_flat_key: &Hash,
    expected_root: &Hash,
) -> Result<(), ProofError> {
    match proof.verify_single_with_flat_key_against_root(
        queried_address,
        queried_slot,
        queried_flat_key,
        expected_root,
    )? {
        None => Ok(()),
        Some(_) => Err(ProofError::ExpectedNativeAbsence),
    }
}
