# Prividium SP1 settlement-backed IBC light client

This repository implements a four-program SP1 light client for proving IBC
state from a Prividium/ZKsync OS chain on a destination EVM chain.

```text
Ethereum consensus trust
        |
        v
ZKsync settlement state and native root
        |
        v
IBC Membership or Non-Membership
```

Trust Update advances the Ethereum consensus trust stored by the destination
contract. Settlement Update uses that trust to authenticate a ZKsync L1 batch
and native state root. Membership and Non-Membership prove application state
against a root already accepted by Settlement Update.

## Programs

| Program | Purpose |
| --- | --- |
| `trust-update` | Advances the finalized Beacon header and trusted sync-committee roots |
| `settlement-update` | Authenticates an L1 batch, ZKsync native root, and source timestamp |
| `membership` | Proves that an expected IBC value exists under an accepted native root |
| `non-membership` | Proves that a supported IBC path is absent under an accepted native root |

The four programs have separate ELFs and VKeys. They must all be built from
the same source revision, SP1 toolchain, and SourceProfile.

## Documentation

| Task | Document |
| --- | --- |
| Understand the components and trust flow | [`docs/architecture.md`](docs/architecture.md) |
| Review protocol statements and bindings | [`docs/spec.md`](docs/spec.md) |
| Prepare and review a production SourceProfile | [`docs/SOURCE_PROFILE.md`](docs/SOURCE_PROFILE.md) |
| Set up the toolchain and build artifacts | [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) |
| Run Rust, Foundry, SP1, and E2E tests | [`docs/TESTING.md`](docs/TESTING.md) |
| Prepare and deploy the verifier and light client | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |
| Deploy the settlement-backed hard-finality Proof API | [`tooling/proof-api/docs/DEPLOYMENT.md`](tooling/proof-api/docs/DEPLOYMENT.md) |
| Connect the Proof API, relayer, Router, and source RPCs | [`docs/INTEGRATION.md`](docs/INTEGRATION.md) |
| Produce and review a release | [`docs/RELEASE.md`](docs/RELEASE.md) |

For a new deployment, read them in this order:

```text
Architecture -> Specification -> SourceProfile -> Development -> Testing
             -> Deployment -> Integration -> Release
```

## Quick validation

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings

./scripts/install-contract-deps.sh
cd contracts
forge fmt --check
forge test -vvv
cd ../tooling/proof-api
cargo fmt --all -- --check
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --all-targets --locked
PRIVIDIUM_SP1_ELF_DIR="$PWD/../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release" \
  cargo build --release --locked --features sp1
```

## Build ELFs and VKeys

Every Rust and guest build requires an explicit SourceProfile. The checked-in
synthetic profile is only for local development and tests.

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
./scripts/build-sp1.sh

mkdir -p target/deployment-artifacts
./scripts/generate-vkeys.sh \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json
```

The manifest contains the ELF hash and VKey for all four programs. Changing
guest code, the SourceProfile, the lockfile, or the SP1 toolchain requires new
ELFs and VKeys.

## Security model

Trust Update is the only route that changes finalized Beacon trust or committee
roots. Settlement Update authenticates one ZKsync batch against the current
trust digest without changing that trust. It verifies the batch's stored hash
and proves that the batch number is not above the authenticated
`totalBatchesExecuted` counter from the same L1 state. One Membership proof can authenticate
up to 64 packet or acknowledgement claims against that batch root.
Non-Membership remains one proof per absence claim. Neither route is usable
until the corresponding Settlement state has been accepted.

The contract additionally binds schema and program versions, SourceProfile ID,
the dedicated VKey, IBC store, logical path, storage derivation, request
digest, and expected value or absence profile. Identical Settlement replays are
no-ops; conflicting roots or timestamps for an accepted batch are rejected.

Settlement uses an optimistic Beacon header authenticated by a trusted sync
committee. It must not be described as Ethereum-finalized state. Trust Update
provides the separate finalized-consensus maintenance path.

## Prerequisites

Install Docker, Foundry, Rust `1.97.1`, and the SP1 `6.7.0` CLI before building
the release. Verify the SP1 installation with:

```bash
sp1up --version v6.7.0
./scripts/check-sp1-toolchain.sh
```

The deployment host also needs access to the source L2 RPC, L1 execution RPC,
Beacon API, destination RPC, and SP1 network gateway. Keep RPC tokens, the SP1
network key, and the destination trust-update signer key outside the repository.

| Component | Pinned value |
| --- | --- |
| Host Rust | `1.97.1` |
| SP1 SDK and build tools | `6.7.0` |
| SP1 release revision | `cd7850de24cd611683a961a8dcb64c94f7876b7a` |
| SP1 guest Rust | `rustc 1.94.0-dev` |
| SP1 circuit/verifier | `v6.1.0` |
| Groth16 verifier hash | `0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696` |
| Solidity | `0.8.28` |
| `sp1-contracts` | `v6.1.1`, commit `d3629729c3216eb51bd4859d027a8eb729399fa4` |

`rust-toolchain.toml`, `Cargo.lock`, `scripts/sp1-container.env`, and the
dependency installer are authoritative. Do not silently replace pinned inputs.

## Production Proof API

`tooling/proof-api` exposes the standard remote-prover gRPC interface. It
is the complete proving service for this deployment. It collects source
evidence, constructs witnesses, runs the four reviewed ELFs through the SP1
network gateway, verifies every returned Groth16 proof locally, validates the
public outputs, and returns contract proof data to the relayer. There is no
separate proof-backend process or backend HTTP API.

At startup the service derives the VKey for every embedded ELF and compares all
four values with the destination configuration. It refuses to listen if an ELF,
VKey, SourceProfile, Router client, verifier, or storage binding is wrong. For
Membership requests, it makes one multi-slot `zks_getProof` request, generates
one shared SP1 proof for up to 64 claims, places that proof in the first
packet's FULL envelope, and returns CACHED Merkle-branch envelopes for the
remaining packets in request order.

Build the four ELFs first. For a host deployment, the checked-in launcher
validates the release artifacts, generates the hard-finality configuration,
builds the service with the `sp1` feature, and starts it:

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/source-production.json"
./scripts/build-sp1.sh

install -d -m 700 /etc/prividium-l1-proof-api
install -m 600 tooling/proof-api/config/operator.env.example \
  /etc/prividium-l1-proof-api/operator.env
${EDITOR:-vi} /etc/prividium-l1-proof-api/operator.env
tooling/proof-api/scripts/start-proof-api.sh \
  /etc/prividium-l1-proof-api/operator.env
```

Put the API token, RPC tokens, SP1 network key and trust-update signer key in the
protected operator environment file. The launcher exports only the variables
named by the generated configuration. The trust-update signer must be
authorized for `updateClient` on the destination Router. The service uses that
permission only to advance consensus trust when a committee gap cannot fit in
the normal `StateProof` response. Membership proofs require no separate signer
or registration transaction.

The Docker Compose deployment receives the reviewed ELF directory and
SourceProfile as named build contexts and runs the same launcher inside the
container. Complete host and container commands are in
[`tooling/proof-api/docs/DEPLOYMENT.md`](tooling/proof-api/docs/DEPLOYMENT.md).

`maxAutomaticTrustUpdates` limits each in-memory catch-up group and the number
of Trust Updates that may accompany the final Settlement response. If trust is
further behind, the service submits and confirms the earlier Trust Updates as
individual Router transactions, then returns the last Trust Updates and
Settlement in the normal `StateProof` response. It is not a lifetime limit.

## Solidity light client

The destination contract stores consensus trust, accepted Settlement states,
and registered Membership batch roots. It verifies one Membership SP1 proof at
registration and verifies compact per-packet Merkle branches during Router
callbacks. Non-Membership continues to verify its SP1 proof directly.
Both callbacks return the authenticated source timestamp stored by Settlement.

Install the pinned contract dependency, prepare the four VKeys and coherent
Beacon bootstrap, then deploy the light client on the destination chain:

```bash
./scripts/install-contract-deps.sh
export BEACON_API_URL='https://beacon.example'
./scripts/capture-beacon-bootstrap.sh \
  source-profile.production.json \
  release/initial-trust.json

export PRIVATE_KEY='0x...'
export DESTINATION_RPC_URL='https://destination.example'
export DESTINATION_CHAIN_ID='1337'
export IBC_ROUTER='0x...'
export SP1_VERIFIER_GATEWAY='0x...'
export CONFIRM_DEPLOYMENT='YES'
./scripts/deploy-light-client.sh \
  source-profile.production.json \
  release/initial-trust.json \
  target/deployment-artifacts/program-vkeys.json
```

The deployment wrapper uses the real ICS26 Router and an existing reviewed SP1
verifier gateway. It validates the SourceProfile, initial trust, ELF hashes,
VKeys, destination chain, Router code and verifier route before broadcasting.
Read every deployed value back before governance registers or migrates the
Router client. The complete scripted and manual procedures are documented in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Integration boundary

A full deployment needs the included Proof API with SP1 network access, an IBC
relayer, source RPC access, and destination Router registration. The Proof API
is the single proving-service process; the SP1 network gateway is its remote
proving transport, not another application backend.

Settlement public values authenticate both the batch-end L2 block `B_end` and
L1 batch number `K`. The contract stores `K -> (B_end, root, timestamp)`.
The relayer may retain the packet event block as `proofHeight`; the contract
requires that height not be newer than `B_end`. Membership batch registration
and Non-Membership both bind their proven root to the root accepted for `K`.

## Production boundary

Do not deploy the synthetic profile. A production release must freeze and
review the real Beacon configuration, settlement contract and storage layout,
ZKsync OS version, native proof format, IBC store, path grammar, absence rule,
destination Router, verifier gateway, bootstrap trust state, four ELF hashes,
and four VKeys.

Production validation and release gates are defined in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) and
[`docs/RELEASE.md`](docs/RELEASE.md).
