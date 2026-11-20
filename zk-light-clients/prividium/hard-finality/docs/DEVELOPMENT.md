# Development

This guide covers local work on the four SP1 programs, shared verification
crates, standalone Proof API, and Solidity light client.

Read [architecture.md](architecture.md) and [spec.md](spec.md) before changing
proof semantics or public values.

## Toolchain

Install and verify the pinned SP1 release:

```bash
sp1up --version v6.7.0
./scripts/check-sp1-toolchain.sh
```

Install the pinned Solidity dependency:

```bash
./scripts/install-contract-deps.sh
```

Do not silently upgrade SP1, Rust, Solidity, a SourceProfile, or verifier
contracts. Any of them can change an ELF and its VKey.

## Repository boundaries

| Path | Purpose |
| --- | --- |
| `crates/program-logic` | Shared verification statements used by native tests and guests |
| `crates/types`, `crates/public-values` | Witness types and strict Solidity ABI codecs |
| `crates/consensus`, `crates/bls`, `crates/ssz` | Ethereum sync-committee and SSZ verification |
| `crates/ethereum-mpt`, `crates/settlement` | L1 account/storage and settlement authentication |
| `crates/zksync-native`, `crates/zksync-rpc` | Native-tree verification and RPC wire types |
| `crates/ibc-storage` | Logical path, Solidity slot, and native-key derivation |
| `crates/source-profile`, `crates/profile-constants` | Profile validation and generated guest constants |
| `programs/*` | Thin SP1 entrypoints for the four statements |
| `tooling/proof-api` | Standalone gRPC service with local witness construction and direct SP1 network proving |
| `contracts/src` | Destination light client and public-value decoding |
| `contracts/test` | Mock-verifier lifecycle and negative tests |
| `contracts/script` | E2E deployment and real-proof submission helpers |
| `scripts` | Reproducible builds, VKeys, dependency setup, and evidence capture |

Keep security-critical rules in shared code invoked by both native validation
and the guest. Do not rely on host-only checks for proof soundness.

## Fast development loop

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings

cd contracts
forge fmt --check
forge test -vvv
cd ..
```

The Foundry suite uses a mock verifier. It tests contract decoding, VKey
routing, state transitions, request binding, and negative cases without
generating Groth16 proofs.

## SourceProfile

The SourceProfile pins the Beacon configuration, settlement contract and
layout, ZKsync native-proof rules, IBC store, path grammar, and absence rule.

Compile and inspect the development profile:

```bash
cargo run --locked --offline \
  -p prividium-source-profile --bin profilec -- \
  profiles/example.synthetic.json \
  target/generated-source-profile.rs
```

`profiles/example.synthetic.json` is not production configuration. A real
deployment requires an independently reviewed profile built from exact chain
and contract evidence. Follow [`SOURCE_PROFILE.md`](SOURCE_PROFILE.md) for the
field definitions, supported production values, and collection commands.

## Build the four guests

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
./scripts/build-sp1.sh
./scripts/hash-guests.sh
```

Outputs:

```text
target/elf-compilation/riscv64im-succinct-zkvm-elf/release/
  prividium-trust-update-program
  prividium-settlement-update-program
  prividium-membership-program
  prividium-non-membership-program
```

Generate the manifest:

```bash
mkdir -p target/deployment-artifacts
./scripts/generate-vkeys.sh \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json
jq . target/deployment-artifacts/program-vkeys.json
```

For a release candidate:

```bash
./scripts/reproducible-guests.sh "$PRIVIDIUM_SOURCE_PROFILE"
```

The reproducibility check requires a clean committed tree and a tracked
profile.

## Proof API

The Proof API is excluded from the parent workspace because it is a standalone
service with its own lockfile, toolchain file, Dockerfile, protobuf build, and
release lifecycle.

```bash
cd tooling/proof-api
cargo fmt --all -- --check
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --all-targets --locked
PRIVIDIUM_SP1_ELF_DIR="$PWD/../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release" \
  cargo build --release --locked --features sp1
```

Prepare local configuration without committing credentials:

```bash
cp config.example.json config.json
cp initial-trust.example.json /secure/path/initial-trust.json
chmod 600 config.json /secure/path/initial-trust.json
```

Replace every placeholder. Set the bootstrap file digest in configuration and
provide endpoint tokens through the environment variables named by the
configuration. Then start the service:

```bash
./target/release/prividium-proof-api --config config.json
```

The release binary embeds all four reviewed ELFs. It constructs witnesses,
submits them through the SP1 SDK, verifies the Groth16 proofs locally, and
checks public outputs before serving the relayer. The complete RPC, SP1,
bootstrap, and security requirements are in
[`../tooling/proof-api/README.md`](../tooling/proof-api/README.md).

Never submit an artifact whose profile, public values, program version, ELF
hash, or VKey differs from the deployment manifest.

## Changing protocol logic

1. Update the detailed specification.
2. Update shared types and verification logic.
3. Keep native validation and guest execution on the same implementation.
4. Update public-value encoding and Solidity decoding together.
5. Add positive, negative, boundary, and mutation tests.
6. Rebuild affected ELFs and regenerate VKeys.
7. Run the contract lifecycle and at least one real SP1 execution.
8. Record the new release identities.

## Common failures

| Failure | Likely cause |
| --- | --- |
| SourceProfile mismatch | Host, guest ELF, manifest, or contract uses another profile |
| Wrong VKey | ELF and deployment manifest came from different builds |
| Current trust digest mismatch | Trust or Settlement witness was built from stale destination state |
| Committee period rejected | Stored current/next committee cannot authenticate the selected signature |
| Unknown batch | Membership or Non-Membership was submitted before Settlement |
| Conflicting accepted batch | Another root or timestamp is already stored for the batch |
| Wrong path/value/request digest | Relayer request differs from the proof public values |
| Native absence rejected | The key exists, including an existing zero value |
| `cargo prove` revision mismatch | Installed SP1 CLI differs from `sp1-container.env` |
| Foundry import failure | Pinned `sp1-contracts` checkout or submodules are missing |
| Reproducibility mismatch | Source, profile bytes, lockfile, flags, or toolchain differs |
| Host builds fail in SP1 SDK FFI | Use `generate-vkeys.sh`, which derives VKeys directly from ELFs |

See [`../scripts/README.md`](../scripts/README.md) for every repository
script, its inputs, and outputs.
