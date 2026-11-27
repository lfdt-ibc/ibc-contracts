// SPDX-License-Identifier: Apache-2.0

#![no_std]

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
};
use prividium_types::{BlsPublicKey, BlsSignature, Hash32};
use sha2::Sha256;

/// Ethereum's proof-of-possession minimal-public-key ciphersuite DST.
pub const ETHEREUM_BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlsError {
    NoParticipants,
    InvalidPublicKeyEncoding { position: usize },
    PublicKeyAtInfinity { position: usize },
    AggregatePublicKeyAtInfinity,
    InvalidSignatureEncoding,
    SignatureAtInfinity,
    InvalidSignature,
}

/// Allocation-free aggregate verification. The index is used only for
/// precise malformed-key errors and may be the original committee position.
/// `from_compressed` performs canonical field decoding, on-curve validation,
/// and subgroup validation. Identity points are then rejected explicitly.
pub fn fast_aggregate_verify_indexed<'a, I>(
    participant_public_keys: I,
    signing_root: Hash32,
    signature: &BlsSignature,
) -> Result<(), BlsError>
where
    I: IntoIterator<Item = (usize, &'a BlsPublicKey)>,
{
    let mut aggregate = G1Projective::identity();
    let mut participant_count = 0_usize;
    for (position, encoded) in participant_public_keys {
        let point = Option::<G1Affine>::from(G1Affine::from_compressed(&encoded.0))
            .ok_or(BlsError::InvalidPublicKeyEncoding { position })?;
        if bool::from(point.is_identity()) {
            return Err(BlsError::PublicKeyAtInfinity { position });
        }
        aggregate += point;
        participant_count += 1;
    }
    if participant_count == 0 {
        return Err(BlsError::NoParticipants);
    }
    let aggregate = G1Affine::from(aggregate);
    if bool::from(aggregate.is_identity()) {
        return Err(BlsError::AggregatePublicKeyAtInfinity);
    }

    let signature = Option::<G2Affine>::from(G2Affine::from_compressed(&signature.0))
        .ok_or(BlsError::InvalidSignatureEncoding)?;
    if bool::from(signature.is_identity()) {
        return Err(BlsError::SignatureAtInfinity);
    }
    let message = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
        [signing_root],
        ETHEREUM_BLS_DST,
    );
    let prepared_message = G2Prepared::from(G2Affine::from(message));
    let prepared_signature = G2Prepared::from(signature);
    let negative_generator = G1Affine::from(-G1Projective::generator());
    let product = multi_miller_loop(&[
        (&aggregate, &prepared_message),
        (&negative_generator, &prepared_signature),
    ])
    .final_exponentiation();
    if product != Gt::identity() {
        return Err(BlsError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex::decode(value).unwrap_or_default();
        bytes.try_into().unwrap_or([0; N])
    }

    fn official_vector() -> ([BlsPublicKey; 3], Hash32, BlsSignature) {
        // consensus-spec-tests bc5c1a7f, eth_fast_aggregate_verify_valid_2.
        let keys = [
            decode("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a").into(),
            decode("b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81").into(),
            decode("b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f").into(),
        ];
        let signature = decode("9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930").into();
        (keys, [0xab; 32], signature)
    }

    #[test]
    fn official_fast_aggregate_verify_vector() {
        let (keys, message, signature) = official_vector();
        assert_eq!(
            fast_aggregate_verify_indexed(keys.iter().enumerate(), message, &signature),
            Ok(())
        );
    }

    #[test]
    fn malformed_identity_and_mutations_fail_closed() {
        let (keys, mut message, signature) = official_vector();
        message[0] ^= 1;
        assert_eq!(
            fast_aggregate_verify_indexed(keys.iter().enumerate(), message, &signature),
            Err(BlsError::InvalidSignature)
        );

        let identity: BlsPublicKey = {
            let mut p = [0; 48];
            p[0] = 0xc0;
            p
        }
        .into();
        assert_eq!(
            fast_aggregate_verify_indexed([identity].iter().enumerate(), message, &signature),
            Err(BlsError::PublicKeyAtInfinity { position: 0 })
        );
        let invalid: BlsPublicKey = [0; 48].into();
        assert_eq!(
            fast_aggregate_verify_indexed([invalid].iter().enumerate(), message, &signature),
            Err(BlsError::InvalidPublicKeyEncoding { position: 0 })
        );
    }
}
