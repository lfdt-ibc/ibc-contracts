// SPDX-License-Identifier: Apache-2.0

use crate::Hash;

#[inline]
pub fn hash_branch(left: &Hash, right: &Hash) -> Hash {
    prividium_crypto::blake2s_pair(left, right)
}
