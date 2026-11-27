# Deployment

This guide prepares the Beacon trust state and deploys the four-circuit
settlement-backed hard-finality light client. It provides a guarded script path and the equivalent
manual commands. Router registration or migration remains a separate
destination-governance operation.

## Automated and manual boundaries

Repository scripts automate deterministic guest builds, VKey extraction,
Beacon bootstrap capture, contract-input validation, and deployment. Selection
of the production SourceProfile, Beacon endpoint, Router, gateway governance,
client ID, counterparty, signer custody, and migration transaction requires
deployment review.

Do not infer production values from the synthetic profile or E2E scripts.

## Prerequisites

- reviewed source commit and clean working tree;
- Docker and the pinned SP1 CLI/toolchain;
- Foundry with Solidity 0.8.28 support;
- destination RPC and funded/authorized deployment signer;
- destination ICS26 Router and governance procedure;
- reviewed SP1 v6.1.0 Groth16 gateway route;
- production SourceProfile;
- coherent Beacon bootstrap evidence; and
- reproducible four-ELF/four-VKey manifest.

Prepare and validate the production SourceProfile by following
[`SOURCE_PROFILE.md`](SOURCE_PROFILE.md) before generating ELFs or capturing
the Beacon bootstrap.

## Artifact bundle

Prepare:

- repository commit;
- production SourceProfile, SHA-256, and SourceProfile ID;
- four ELFs, hashes, and VKeys;
- initial finalized Beacon slot and header root;
- current and next sync-committee roots and known flag;
- IBC store address and absence-profile ID;
- destination ICS26 Router address; and
- reviewed SP1 verifier gateway and route.

Generate the program manifest:

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/source-profile.production.json"
mkdir -p target/deployment-artifacts
./scripts/generate-vkeys.sh \
  "$PRIVIDIUM_SOURCE_PROFILE" \
  target/deployment-artifacts/program-vkeys.json
```

## Bootstrap state

The initial trust fields must come from one coherent finalized Beacon
bootstrap capture:

```text
finalizedBeaconSlot
finalizedBeaconHeaderRoot
currentSyncCommitteeRoot
nextSyncCommitteeRoot
nextSyncCommitteeKnown
```

Retain the raw response and checksum. Confirm that its consensus configuration
matches the SourceProfile used to build the four ELFs.

The bootstrap includes the complete current committee preimage required by
the first Trust or Settlement witness. If the next committee is unknown, use a
zero next root and `nextSyncCommitteeKnown=false`. Do not claim a next
committee is known unless it is authenticated by the bootstrap or a valid
Trust Update.

### Capture with the script

Set the Beacon endpoint and pass the reviewed production SourceProfile:

```bash
export BEACON_API_URL='https://beacon.example'
export BEACON_API_TOKEN='replace-if-required'

mkdir -p release
./scripts/capture-beacon-bootstrap.sh \
  source-profile.production.json \
  release/initial-trust.json
```

Omit `BEACON_API_TOKEN` when the endpoint does not require authentication. The
script verifies the Beacon genesis and consensus timing against the
SourceProfile, fetches the finalized header and matching light-client
bootstrap, recomputes the Beacon header root and current sync-committee root,
and binds the result to the compiled SourceProfile ID. It writes:

```text
release/beacon-genesis.raw.json
release/beacon-spec.raw.json
release/bootstrap-header.raw.json
release/bootstrap.raw.json
release/initial-trust.json
release/initial-trust-sha256.txt
```

Review the finalized checkpoint and committee with the source-chain operator
before approving the artifact for deployment.

### Capture manually

The following commands perform the same capture without the shell wrapper:

```bash
export BEACON_API_URL='https://beacon.example'
export SOURCE_PROFILE_FILE="$PWD/source-profile.production.json"
export RELEASE_DIR="$PWD/release"

install -d -m 755 "$RELEASE_DIR"
BEACON_API_URL="${BEACON_API_URL%/}"

curl --fail-with-body --silent --show-error \
  --header 'Accept: application/json' \
  "$BEACON_API_URL/eth/v1/beacon/genesis" \
  --output "$RELEASE_DIR/beacon-genesis.raw.json"

curl --fail-with-body --silent --show-error \
  --header 'Accept: application/json' \
  "$BEACON_API_URL/eth/v1/config/spec" \
  --output "$RELEASE_DIR/beacon-spec.raw.json"

jq -e --slurpfile profile "$SOURCE_PROFILE_FILE" '
  ((.data.genesis_validators_root | ascii_downcase)
    == ($profile[0].consensus.genesisValidatorsRoot | ascii_downcase))
  and ((.data.genesis_time | tonumber) == $profile[0].consensus.genesisTime)
' "$RELEASE_DIR/beacon-genesis.raw.json" >/dev/null

jq -e --slurpfile profile "$SOURCE_PROFILE_FILE" '
  ((.data.SECONDS_PER_SLOT | tonumber) == $profile[0].consensus.secondsPerSlot)
  and ((.data.SLOTS_PER_EPOCH | tonumber) == $profile[0].consensus.slotsPerEpoch)
  and ((.data.EPOCHS_PER_SYNC_COMMITTEE_PERIOD | tonumber)
       == $profile[0].consensus.epochsPerSyncCommitteePeriod)
  and ((.data.SYNC_COMMITTEE_SIZE | tonumber)
       == $profile[0].consensus.syncCommitteeSize)
  and any($profile[0].consensus.supportedLightClientHeaderSchemas[]; . == "fulu")
' "$RELEASE_DIR/beacon-spec.raw.json" >/dev/null

curl --fail-with-body --silent --show-error \
  --header 'Accept: application/json' \
  "$BEACON_API_URL/eth/v1/beacon/headers/finalized" \
  --output "$RELEASE_DIR/bootstrap-header.raw.json"

TRUSTED_BEACON_ROOT="$(
  jq -er '.data.root' "$RELEASE_DIR/bootstrap-header.raw.json"
)"

curl --fail-with-body --silent --show-error \
  --header 'Accept: application/json' \
  "$BEACON_API_URL/eth/v1/beacon/light_client/bootstrap/$TRUSTED_BEACON_ROOT" \
  --output "$RELEASE_DIR/bootstrap.raw.json"

PROFILE_OUTPUT="$(
  cargo run --quiet --locked --offline \
    -p prividium-source-profile --bin profilec -- \
    "$SOURCE_PROFILE_FILE" "$RELEASE_DIR/generated-source-profile.rs"
)"
SOURCE_PROFILE_ID="${PROFILE_OUTPUT#SOURCE_PROFILE_ID=}"
SYNC_COMMITTEE_SIZE="$(
  jq -er '.consensus.syncCommitteeSize' "$SOURCE_PROFILE_FILE"
)"

PRIVIDIUM_SOURCE_PROFILE="$SOURCE_PROFILE_FILE" \
cargo run --quiet --locked --offline \
  --manifest-path tooling/proof-api/Cargo.toml \
  --bin prividium-bootstrap-artifact -- \
  "$RELEASE_DIR/bootstrap.raw.json" \
  "${TRUSTED_BEACON_ROOT,,}" \
  "$SOURCE_PROFILE_ID" \
  "$SYNC_COMMITTEE_SIZE" \
  >"$RELEASE_DIR/initial-trust.json"

(
  cd "$RELEASE_DIR"
  sha256sum initial-trust.json >initial-trust-sha256.txt
)
```

For an authenticated Beacon endpoint, add its reviewed authorization header to
all four `curl` commands. The `prividium-bootstrap-artifact` command is required;
manually copying committee roots into JSON does not perform the cryptographic
root and SourceProfile checks.

## Contract dependencies

```bash
./scripts/install-contract-deps.sh
```

## Configuration reference

| Field | Format | Purpose |
| --- | --- | --- |
| `PRIVATE_KEY` | 32-byte secret | Production deployment signer; custody must follow destination policy |
| `DESTINATION_RPC_URL` | URL | Destination JSON-RPC endpoint |
| `DESTINATION_CHAIN_ID` | decimal integer | Expected destination chain ID checked before deployment |
| `SOURCE_PROFILE_ID` | bytes32 | Hash of the reviewed SourceProfile |
| `INITIAL_FINALIZED_SLOT` | decimal u64 | Trusted finalized Beacon slot |
| `INITIAL_FINALIZED_ROOT` | bytes32 | SSZ root of the trusted finalized header |
| `INITIAL_CURRENT_COMMITTEE_ROOT` | bytes32 | Trusted current sync-committee root |
| `INITIAL_NEXT_COMMITTEE_ROOT` | bytes32 | Trusted next root, or zero when unknown |
| `INITIAL_NEXT_COMMITTEE_KNOWN` | boolean | Whether the next root is authenticated |
| `TRUST_UPDATE_VKEY` | bytes32 | Trust Update program VKey |
| `SETTLEMENT_UPDATE_VKEY` | bytes32 | Settlement Update program VKey |
| `MEMBERSHIP_VKEY` | bytes32 | Membership program VKey |
| `NON_MEMBERSHIP_VKEY` | bytes32 | Non-Membership program VKey |
| `ABSENCE_PROFILE_ID` | u32 | Must match the profile and Non-Membership statement |
| `IBC_STORE_ADDRESS` | address | Source IBC storage contract/proxy pinned by the profile |
| `IBC_ROUTER` | address | Destination Router authorized to call the client; required by production deployment |
| `SP1_VERIFIER_GATEWAY` | address | Reviewed gateway containing the expected Groth16 route |

Keep the deployment key outside source control and shell history. Production
custody and signing must follow the destination-chain policy.

## Verifier and gateway

The expected SP1 v6.1.0 Groth16 verifier hash is:

```text
0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696
```

The proof selector is its leading four bytes, `0x4388a21c`. Verify the
gateway route on chain. Record the concrete verifier address, gateway owner,
route freeze status, and any governance delay. A mutable owner-controlled route
is part of the light client's trust model.

## Deploy the light client

The production deployment uses
`contracts/script/DeployHardFinalityClient.s.sol`. It deploys only the light
client. The Router and SP1 verifier gateway must already exist on the
destination chain.

### Deploy with the script

The wrapper derives the SourceProfile ID, source IBC store, absence profile,
initial trust, and four VKeys from the reviewed artifacts. It also verifies the
four local ELF hashes, destination chain ID, Router bytecode, gateway bytecode,
and Groth16 verifier route before broadcasting.

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

By default, the wrapper verifies ELFs under
`target/elf-compilation/riscv64im-succinct-zkvm-elf/release`. Set
`PRIVIDIUM_ELF_DIR` only when the reviewed ELF bundle is stored elsewhere.

### Deploy manually

For a manual deployment, export the same values explicitly and invoke the same
production Foundry script:

```bash
export SOURCE_PROFILE_FILE="$PWD/source-profile.production.json"
export INITIAL_TRUST_FILE="$PWD/release/initial-trust.json"
export PROGRAM_VKEYS_FILE="$PWD/target/deployment-artifacts/program-vkeys.json"

PROFILE_OUTPUT="$(
  cargo run --quiet --locked --offline \
    -p prividium-source-profile --bin profilec -- \
    "$SOURCE_PROFILE_FILE" /tmp/prividium-source-profile.rs
)"
export SOURCE_PROFILE_ID="${PROFILE_OUTPUT#SOURCE_PROFILE_ID=}"

SYNC_COMMITTEE_SIZE="$(
  jq -er '.consensus.syncCommitteeSize' "$SOURCE_PROFILE_FILE"
)"
PRIVIDIUM_SOURCE_PROFILE="$SOURCE_PROFILE_FILE" \
cargo run --quiet --locked --offline \
  --manifest-path tooling/proof-api/Cargo.toml \
  --bin prividium-validate-initial-trust -- \
  "$INITIAL_TRUST_FILE" \
  "$SOURCE_PROFILE_ID" \
  "$SYNC_COMMITTEE_SIZE"

export INITIAL_FINALIZED_SLOT="$(jq -er '.finalizedBeaconSlot' "$INITIAL_TRUST_FILE")"
export INITIAL_FINALIZED_ROOT="$(jq -er '.finalizedBeaconHeaderRoot' "$INITIAL_TRUST_FILE")"
export INITIAL_CURRENT_COMMITTEE_ROOT="$(jq -er '.currentSyncCommitteeRoot' "$INITIAL_TRUST_FILE")"
export INITIAL_NEXT_COMMITTEE_ROOT="$(jq -er '.nextSyncCommitteeRoot' "$INITIAL_TRUST_FILE")"
export INITIAL_NEXT_COMMITTEE_KNOWN="$(jq -er '.nextSyncCommitteeKnown' "$INITIAL_TRUST_FILE")"
export IBC_STORE_ADDRESS="$(jq -er '.prividiumL2.ibcStoreAddress' "$SOURCE_PROFILE_FILE")"
export ABSENCE_PROFILE_ID="$(jq -er '.prividiumL2.absenceProfileId' "$SOURCE_PROFILE_FILE")"
export TRUST_UPDATE_VKEY="$(jq -er '.["trust-update"].programVKey' "$PROGRAM_VKEYS_FILE")"
export SETTLEMENT_UPDATE_VKEY="$(jq -er '.["settlement-update"].programVKey' "$PROGRAM_VKEYS_FILE")"
export MEMBERSHIP_VKEY="$(jq -er '.membership.programVKey' "$PROGRAM_VKEYS_FILE")"
export NON_MEMBERSHIP_VKEY="$(jq -er '.["non-membership"].programVKey' "$PROGRAM_VKEYS_FILE")"

export PRIVATE_KEY='0x...'
export DESTINATION_RPC_URL='https://destination.example'
export DESTINATION_CHAIN_ID='1337'
export IBC_ROUTER='0x...'
export SP1_VERIFIER_GATEWAY='0x...'

cd contracts
forge script script/DeployHardFinalityClient.s.sol:DeployHardFinalityClient \
  --rpc-url "$DESTINATION_RPC_URL" \
  --broadcast \
  -vvvv
```

The manual route still executes the Foundry script's on-chain chain-ID,
Router, gateway-route, verifier-hash, and post-deployment readback checks. The
operator must separately compare the SourceProfile, initial-trust artifact,
VKey manifest, and ELF hashes before running it.

## Deployment order

1. Confirm destination chain ID and Router address.
2. Confirm the SP1 gateway, verifier hash, and route policy.
3. Confirm SourceProfile ID, IBC store, absence profile, and four VKeys.
4. Confirm initial trust against the bootstrap evidence.
5. Deploy the client with the actual ICS26 Router as `IBC_ROUTER`.
6. Read every immutable and trust-state field back from chain.
7. Register or migrate the Router client through governance.
8. Confirm `Router.getClient(clientId)` returns the deployed client.
9. Confirm Router counterparty client and prefix.
10. Start the Proof API only after its identity matches the deployed client.
    Follow the host or Docker Compose procedure in
    [`../tooling/proof-api/docs/DEPLOYMENT.md`](../tooling/proof-api/docs/DEPLOYMENT.md).

## E2E helper scope

`DeploySettlementE2E.s.sol` passes the deployer address as the Router and
deploys a fresh gateway. It remains a local E2E helper. Production deployments
use `DeployHardFinalityClient.s.sol` through either method above.

The production script connects to the supplied Router and verifier gateway and
checks the expected `0x4388a21c` Groth16 route. Gateway ownership and route
freeze policy remain part of destination governance.

For local E2E only, the helper may be invoked after setting every required
field:

```bash
cd contracts
forge script script/DeploySettlementE2E.s.sol:DeploySettlementE2E \
  --rpc-url "$DESTINATION_RPC_URL" \
  --broadcast -vvvv
```

This command deploys a fresh gateway and binds the broadcaster as Router. It is
not the production command.

## Readback

Compare `SOURCE_PROFILE_ID`, all four VKeys, `IBC_STORE`,
`ABSENCE_PROFILE_ID`, `SP1_VERIFIER`, `IBC_ROUTER`, and the complete
consensus trust state with the release manifest.

A successful deployment receipt is not sufficient evidence.

After governance registration, also verify the Router's client lookup,
counterparty client ID and prefix, and authorization path. Submit a read-only
invalid proof before traffic migration and confirm it fails without changing
trust or accepted batches.
