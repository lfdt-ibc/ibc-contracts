# Scripts

Run scripts from the repository root. They fail on missing inputs and do not
store credentials. Production profiles, keys, tokens, witnesses, ELFs, proofs,
and deployment output must remain outside source control.

## Build and release scripts

| Script | Purpose | Main output |
| --- | --- | --- |
| `check-sp1-toolchain.sh` | Verifies the pinned `cargo prove` revision and Succinct Rust compiler | Toolchain versions on stdout |
| `build-sp1.sh` | Builds all four guests in the pinned SP1 container | Four ELFs under `target/elf-compilation/.../release/` |
| `hash-guests.sh` | Prints SHA-256 for the four existing ELFs | Four digest lines |
| `generate-vkeys.sh` | Rebuilds the guests, derives each VKey directly from its ELF, and writes a reviewed manifest | JSON containing four ELF hashes and VKeys |
| `reproducible-guests.sh` | Builds the same clean commit twice and compares all four ELF hashes | Pass/fail plus four hashes |
| `install-contract-deps.sh` | Installs and verifies the pinned `sp1-contracts` checkout and submodules | Verified dependency checkout |
| `test-workflow.sh` | Runs the unified formatting, lint, unit, contract, and Router E2E validation workflow | Pass/fail test evidence |
| `coverage.sh` | Generates separate core Rust, Proof API, and Solidity coverage reports | Reports under `target/coverage/` |
| `release-workflow.sh` | Generates and revalidates a four-program release manifest against current artifacts and pins | `release/manifest.json` by default |
| `capture-beacon-bootstrap.sh` | Captures a finalized Beacon checkpoint and converts it to the validated hard-finality initial-trust artifact | Raw Beacon responses, `initial-trust.json`, and checksum |
| `deploy-light-client.sh` | Validates the reviewed profile, initial trust, ELFs, VKeys, destination Router, and verifier route, then deploys the hard-finality client | Foundry deployment receipt and client address |
| `sp1-container.env` | Pins the SP1 container digest, release revision, circuit version, and verifier hash | Sourced by build scripts |

### Build all guests

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
./scripts/build-sp1.sh
```

The selected profile must be inside the repository because the build creates an
isolated source snapshot. The script copies the reviewed profile into the
snapshot's deterministic profile location before building:

```text
prividium-trust-update-program
prividium-settlement-update-program
prividium-membership-program
prividium-non-membership-program
```

`PRIVIDIUM_SOURCE_PROFILE` is required. Select the checked-in synthetic profile
explicitly for local development, and select the reviewed production profile
when generating release ELFs and VKeys. There is no implicit profile fallback.

### Generate VKeys

```bash
mkdir -p target/deployment-artifacts
./scripts/generate-vkeys.sh \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json
```

The script first rebuilds all guests. It then runs `cargo prove vkey --elf`
for each ELF, requires exactly one canonical 32-byte VKey per program, requires
all four keys to be distinct, and records the selected SourceProfile ID beside
every ELF hash and VKey. Deployment and release scripts reject a manifest whose
SourceProfile ID differs from the selected profile.

### Check reproducibility

```bash
./scripts/reproducible-guests.sh "$PRIVIDIUM_SOURCE_PROFILE"
```

The profile must be tracked and the working tree must be clean. The script uses
two independent archives of the committed revision. A mismatch is a release
blocker.

### Run the unified validation workflow

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
IBC_CONTRACTS_DIR=/path/to/pinned/ibc-contracts \
  ./scripts/test-workflow.sh all
```

Use `fast` when the external Router checkout is unavailable. Individual
actions are `check`, `rust`, `proof-api`, `contracts`, and `router-e2e`.

### Generate coverage

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
./scripts/coverage.sh all
```

LCOV and text summaries are written separately for the core workspace, Proof
API, and Solidity contracts. Set `HTML=1` to add Rust HTML reports.

### Generate and validate release metadata

After reproducibly building the four ELFs and generating the reviewed VKey
manifest:

```bash
./scripts/release-workflow.sh all \
  source-profile.production.json \
  target/deployment-artifacts/program-vkeys.json \
  release/manifest.json
```

The workflow rejects dirty source trees by default and binds the Git revision,
SourceProfile, four ELFs and VKeys, SP1 pins, `sp1-contracts` revision, and
canonical contract ABI and bytecode hashes.

## Evidence collection scripts

| Script | Purpose |
| --- | --- |
| `collect-zksync-v0208.sh` | Captures one batch response and one `zks_getProof` response from a v0.20.8-compatible node |
| `generate-connected-e2e-profile.sh` | Builds a local-development SourceProfile from captured Beacon genesis/spec data, an explicit IBC store, and the reviewed IBC-contracts commit |

Capture one native proof:

```bash
export RPC_BEARER_TOKEN="..."  # omit when the endpoint does not require it
./scripts/collect-zksync-v0208.sh \
  https://source.example/rpc \
  12345 \
  0x1111111111111111111111111111111111111111 \
  0x2222222222222222222222222222222222222222222222222222222222222222 \
  target/test-evidence/native-proof
```

Arguments are RPC URL, decimal L2 block, account address, storage slot, and a
new output directory. The script refuses to overwrite captures.

Generate a connected local profile:

```bash
./scripts/generate-connected-e2e-profile.sh \
  beacon-genesis.raw.json \
  beacon-spec.raw.json \
  0x1111111111111111111111111111111111111111 \
  0123456789abcdef0123456789abcdef01234567 \
  target/test-evidence/source-profile.json
```

This helper deliberately pins local settlement addresses and storage rules. Its
output is not a production profile.

## Capture the production Beacon bootstrap

```bash
export BEACON_API_URL='https://beacon.example'
export BEACON_API_TOKEN='replace-if-required'

./scripts/capture-beacon-bootstrap.sh \
  source-profile.production.json \
  release/initial-trust.json
```

The token is optional. The script validates the Beacon genesis, consensus
timing, finalized checkpoint, committee size, committee root, and SourceProfile
ID before writing the artifact. Review the raw responses with the source-chain
operator. The manual equivalent is documented in
[`../docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).

## Deploy the production light client

```bash
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

The wrapper deploys through
`contracts/script/DeployHardFinalityClient.s.sol`. It uses the existing Router
and verifier gateway. Router registration or migration is performed separately
through the destination governance process. See
[`../docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) for the complete scripted and
manual procedures.

## Exit behavior

Scripts use strict shell mode and return nonzero on validation failure. Do not
pipe their output through commands that hide the exit status. Review generated
JSON and checksums before using them as deployment input.
