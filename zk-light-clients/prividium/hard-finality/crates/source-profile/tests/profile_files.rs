// SPDX-License-Identifier: Apache-2.0

use prividium_source_profile::SourceProfileV1;

const EXAMPLE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../profiles/example.synthetic.json"
));
const TARGET_EVIDENCE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../profiles/target-deployment-addresses.evidence.json"
));

#[test]
fn synthetic_profile_has_stable_reviewable_id() {
    let result = SourceProfileV1::parse_json(EXAMPLE)
        .and_then(SourceProfileV1::validate)
        .and_then(|profile| profile.source_profile_id());
    assert_eq!(
        result,
        Ok([
            0x49, 0x1a, 0x35, 0xca, 0x3c, 0x50, 0xa1, 0xb8, 0x01, 0x2a, 0xd4, 0x63, 0x2b, 0xa4,
            0xc7, 0x93, 0x60, 0x10, 0xfe, 0x79, 0x26, 0xe1, 0x7a, 0x4c, 0x9c, 0x15, 0xfd, 0xd5,
            0x47, 0x84, 0x55, 0xfe,
        ])
    );
}

#[test]
fn partial_target_evidence_cannot_be_compiled_as_a_profile() {
    assert!(SourceProfileV1::parse_json(TARGET_EVIDENCE).is_err());
}
