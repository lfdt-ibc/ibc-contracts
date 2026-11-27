# Release

A release binds one reviewed source revision, one SourceProfile, one pinned
toolchain, four guest ELFs, four VKeys, and one destination deployment.
Builds fail when `PRIVIDIUM_SOURCE_PROFILE` is missing, so a release cannot
silently inherit the checked-in synthetic test profile.

## Checklist

- [ ] Working tree and dependency revisions are clean and recorded.
- [ ] Production SourceProfile and evidence are reviewed.
- [ ] Synthetic inputs are absent from production configuration.
- [ ] Rust formatting, checks, tests, and clippy pass.
- [ ] Standalone Proof API formatting, tests, clippy, and release build pass.
- [ ] Foundry formatting and tests pass.
- [ ] All four guests build reproducibly.
- [ ] Four ELF hashes and four distinct VKeys are recorded.
- [ ] Every program executes and verifies with the real SP1 verifier.
- [ ] Constructor inputs and deployed getters match the manifest.
- [ ] Router registration and counterparty settings are verified.
- [ ] Forward, acknowledgement, and timeout E2E paths pass.
- [ ] Relayer height mapping is cryptographically defined.
- [ ] No credential, proof, ELF, or machine-specific output is committed.

## Generate artifacts

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/source-profile.production.json"
./scripts/reproducible-guests.sh "$PRIVIDIUM_SOURCE_PROFILE"

mkdir -p target/deployment-artifacts
./scripts/generate-vkeys.sh \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json

jq -e 'length == 4' target/deployment-artifacts/program-vkeys.json
sha256sum "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json

./scripts/release-workflow.sh all \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json \
  release/manifest.json
```

Record SourceProfile ID separately from its checksum. Record SP1 SDK and
circuit versions, verifier hash, container digest, source commit, and dirty
status.

The manifest must identify:

- source commit and clean/dirty status;
- SourceProfile path, checksum, and SourceProfile ID;
- pinned host and guest toolchains;
- SP1 circuit and verifier identities;
- each program name, ELF hash, and VKey; and
- generation command and timestamp.

Do not copy keys from an earlier branch, profile, or deployment. The release
workflow rejects a dirty tree by default and revalidates the profile ID, ELF
hashes, four distinct VKeys, SP1 and dependency pins, and canonical contract
ABI and bytecode hashes before accepting the manifest.

## Contract deployment evidence

Retain chain IDs, Router and counterparty configuration, deployment and
registration transactions, gateway route, bootstrap state, SourceProfile ID,
IBC store, absence profile, four VKeys, and all readback results.

Record gateway owner/governance and route freeze status. Read values back from
the deployed contract; do not rely only on deployment arguments or receipts.

## Proof and E2E evidence

For each program retain witness hash, public values, proof hash, VKey, source
heights, cycles, proving time, local verification, and destination transaction.
Mark cold and warm runs separately.

For performance tests also retain settlement readiness, witness construction,
queue wait, proof time, verification, relayer submission, mining latency,
throughput, CPU, memory, and GPU samples. Keep large evidence under ignored
`target/test-evidence/` or an artifact store.

## Release blockers

Do not release when:

- profile, ELF, VKey, verifier, Router, IBC store, or bootstrap identity differs
  between service, manifest, and contract;
- documentation and code describe different programs or public values;
- a security-critical validation exists only on the host;
- exact-height evidence is unavailable and collection falls back to latest;
- the L2-block-to-batch mapping required by the relayer is unauthenticated;
- the production deployment binds the client to a deployer EOA instead of the
  Router;
- verifier-route governance is unknown or unacceptable;
- malformed or trailing public values are accepted;
- proof queues or caches are unbounded;
- only mock verification has been tested;
- Trust or Settlement cannot be proven from the deployed bootstrap;
- forward receive works but acknowledgement return was not tested; or
- timeout testing did not generate and submit the actual Non-Membership proof.
