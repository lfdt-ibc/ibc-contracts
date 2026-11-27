# SourceProfile guide

The SourceProfile describes the source system that this settlement-backed hard-finality light
client is allowed to prove. It binds the SP1 programs to one Beacon network,
one ZKsync settlement deployment, one Prividium L2, and one IBC storage
layout.

The SourceProfile contains public deployment data. It must not contain RPC
URLs, access tokens, private keys, or prover credentials.

All four SP1 programs, the light client, and the Proof API must use the same
reviewed SourceProfile. Changing any field changes the `SOURCE_PROFILE_ID` and
requires new ELFs, new VKeys, and a new light-client deployment.

## Start a production profile

[`profiles/example.synthetic.json`](../profiles/example.synthetic.json) shows
the required JSON structure. Its addresses, hashes, storage slots, fork
values, and committee size belong to a local synthetic test and are not
production values.

Copy the structure into a separate production file:

```bash
install -m 644 profiles/example.synthetic.json profiles/source-production.json
${EDITOR:-vi} profiles/source-production.json
export SOURCE_PROFILE_FILE="$PWD/profiles/source-production.json"
```

Collect the values from the source-chain owners and the reviewed deployment
records. The sections below explain each field and where it comes from.

## Profile identity

| Field | Meaning | Value source |
| --- | --- | --- |
| `profileSchemaVersion` | SourceProfile JSON schema version | Use `1` for this implementation. |
| `profileName` | Human-readable name for the source deployment | Choose a stable name that identifies the network and release, such as `bb-prividium-v0208-production`. |

The profile name is only a label. Security comes from the complete profile and
its derived `SOURCE_PROFILE_ID`.

## Consensus fields

The `consensus` section describes the Beacon network used to authenticate L1
state.

Set the Beacon endpoint and save its genesis and chain specification:

```bash
export BEACON_API_URL='https://beacon.example'
export RELEASE_DIR="$PWD/release/source-profile-evidence"

install -d -m 755 "$RELEASE_DIR"
BEACON_API_URL="${BEACON_API_URL%/}"

curl --fail-with-body --silent --show-error \
  "$BEACON_API_URL/eth/v1/beacon/genesis" \
  -o "$RELEASE_DIR/beacon-genesis.json"

curl --fail-with-body --silent --show-error \
  "$BEACON_API_URL/eth/v1/config/spec" \
  -o "$RELEASE_DIR/beacon-spec.json"
```

For an authenticated endpoint, add the approved authorization header to both
requests.

Read the directly reported values:

```bash
jq '{
  genesisValidatorsRoot: .data.genesis_validators_root,
  genesisTime: (.data.genesis_time | tonumber)
}' "$RELEASE_DIR/beacon-genesis.json"

jq '{
  secondsPerSlot: (.data.SECONDS_PER_SLOT | tonumber),
  slotsPerEpoch: (.data.SLOTS_PER_EPOCH | tonumber),
  epochsPerSyncCommitteePeriod:
    (.data.EPOCHS_PER_SYNC_COMMITTEE_PERIOD | tonumber),
  syncCommitteeSize: (.data.SYNC_COMMITTEE_SIZE | tonumber),
  fuluForkEpoch: (.data.FULU_FORK_EPOCH | tonumber),
  fuluForkVersion: .data.FULU_FORK_VERSION
}' "$RELEASE_DIR/beacon-spec.json"
```

| Field | Meaning | How to obtain it |
| --- | --- | --- |
| `genesisValidatorsRoot` | Identifies the Beacon network | `.data.genesis_validators_root` from `/eth/v1/beacon/genesis`. |
| `genesisTime` | Beacon genesis timestamp | `.data.genesis_time` from `/eth/v1/beacon/genesis`. |
| `secondsPerSlot` | Duration of one Beacon slot | `SECONDS_PER_SLOT` from `/eth/v1/config/spec`. |
| `slotsPerEpoch` | Slots in one Beacon epoch | `SLOTS_PER_EPOCH` from `/eth/v1/config/spec`. |
| `epochsPerSyncCommitteePeriod` | Epochs covered by one sync committee | `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` from `/eth/v1/config/spec`. |
| `syncCommitteeSize` | Number of public keys in a sync committee | `SYNC_COMMITTEE_SIZE` from `/eth/v1/config/spec`. |
| `forkSchedule` | Fork name, activation epoch, and four-byte fork version | Read the corresponding `*_FORK_EPOCH` and `*_FORK_VERSION` values from `/eth/v1/config/spec`. Order entries by activation epoch. |
| `supportedLightClientHeaderSchemas` | Beacon light-client header format implemented by the guest | Use the schema supported by this release. The current production implementation supports `fulu-compatibility-v1`. |
| `supportedExecutionPayloadHeaderSchemas` | Execution payload header format implemented by the guest | Must match `supportedLightClientHeaderSchemas`. The current production implementation supports `fulu-compatibility-v1`. |
| `forkSpecificFinalityGindices` | SSZ path to `finalized_checkpoint.root` for each listed fork | Obtain from the reviewed BeaconState SSZ schema. For the supported Fulu-compatible schema, the reviewed value is `169`. |
| `forkSpecificNextCommitteeGindices` | SSZ path to `next_sync_committee` for each listed fork | Obtain from the reviewed BeaconState SSZ schema. For the supported Fulu-compatible schema, the reviewed value is `87`. |
| `forkSpecificExecutionGindices` | SSZ path to `execution_payload` in the Beacon block body | Obtain from the reviewed BeaconBlockBody SSZ schema. For the supported Fulu-compatible schema, the reviewed value is `25`. |

The Beacon API reports network and fork parameters, but it does not provide
authoritative generalized indices. Review the generalized indices against the
consensus SSZ types used by the deployed Beacon release. Each fork in
`forkSchedule` needs one entry in all three generalized-index lists.
Keep `forkSchedule` in activation-epoch order and sort each generalized-index
list by `forkId`, as required by the profile validator.

Adding a fork or header schema that this repository does not implement
requires a code change and a new release. A JSON-only change is not enough.

## Settlement fields

The `settlement` section identifies the ZKsync settlement Diamond and the
exact storage layout authenticated by the Settlement Update program.

| Field | Meaning | How to obtain it |
| --- | --- | --- |
| `diamondProxyAddress` | ZKsync settlement Diamond proxy on L1 | Use the proxy address from the reviewed settlement deployment record. Confirm code exists with `cast code`. |
| `diamondSourceCommit` | Exact settlement-contract source revision | Run `git rev-parse HEAD` in the reviewed settlement-contract checkout used for deployment, or read it from the signed deployment record. |
| `settlementStorageProfileId` | Identifier for the supported Diamond storage layout | For the supported production v0.30.2 layout, use `era-contracts-zkos-v0.30.2-zk-chain-storage-v1`. |
| `acceptedLifecycleRuleId` | Lifecycle stage the circuit authenticates | For the supported executed-batch rule, use `zksync-v30.2-executed-batch-v1`. |
| `nativeRootBindingRuleId` | Rule used to recompute and bind `StoredBatchInfo` | Use `zksync-os-v0.20.8-stored-batch-info-v1`. |
| `storedBatchHashMappingBaseSlot` | Base slot of `storedBatchHashes` in the Diamond storage layout | Obtain from the compiler storage layout for the exact `diamondSourceCommit`. For the supported v0.30.2 layout, the reviewed slot is `0x0e`, encoded as 32 bytes. |
| `totalBatchesExecutedSlot` | Slot of the `totalBatchesExecuted` counter | Obtain from the same compiler storage layout. For the supported v0.30.2 layout, the reviewed slot is `0x0b`, encoded as 32 bytes. |

Confirm the deployed Diamond and source revision:

```bash
export L1_RPC_URL='https://l1-execution.example'
export DIAMOND_PROXY_ADDRESS='0x...'
export SETTLEMENT_SOURCE_DIR='/absolute/path/to/reviewed-settlement-source'

cast code "$DIAMOND_PROXY_ADDRESS" --rpc-url "$L1_RPC_URL"
git -C "$SETTLEMENT_SOURCE_DIR" rev-parse HEAD
```

`cast code` must return deployed bytecode rather than `0x`.

Storage slot numbers cannot be discovered safely from ordinary RPC reads.
Obtain them from the compiler storage layout generated from the exact source
commit used by the deployed Diamond. Record the layout file with the release.
If the deployed layout differs from the supported v0.30.2 layout, this
implementation needs a reviewed code and profile update before deployment.

Encode a small slot number as a 32-byte value with:

```bash
printf '0x%064x\n' 14 # storedBatchHashes: 0x0e
printf '0x%064x\n' 11 # totalBatchesExecuted: 0x0b
```

## Prividium L2 fields

The `prividiumL2` section identifies the source L2 and the IBC state layout
proved by Membership and Non-Membership.

| Field | Meaning | How to obtain it |
| --- | --- | --- |
| `chainId` | EIP-155 chain ID of the source Prividium L2 | Run `cast chain-id --rpc-url "$SOURCE_L2_RPC_URL"`. |
| `zksyncOsVersion` | Supported ZKsync OS release | This implementation is pinned to `v0.20.8`. Confirm it with the source-chain release record. |
| `zksyncOsCommit` | Exact ZKsync OS source revision | This implementation is pinned to `dbb5c03d4a94ceb1acea9f79242590f354660239`. Confirm it with the source-chain release record. |
| `nativeTreeProfileId` | Native-tree proof format implemented by the guest | Use `zksync-os-v0.20.8-native`. |
| `ibcStoreAddress` | Source Router or storage proxy holding IBC commitments | Use the proxy address from the IBC deployment record. If a current compatible light client exists, read `IBC_STORE()` from it. |
| `ibcStorageProfileId` | Storage-layout rule for IBC commitments | For the supported production Eureka store, use `cosmos-solidity-ibc-eureka-erc7201-v1`. |
| `absenceProfileId` | Non-Membership absence rule identifier | Use `1` for the currently implemented native non-existing proof rule. |
| `ibcMappingBaseSlot` | Base slot or ERC-7201 location of the IBC commitments mapping | For the supported Eureka profile, use `0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600`. |
| `maxClientIdBytes` | Maximum supported IBC client ID length | Use `128` for this implementation. |
| `applicationAbsenceRule` | Application-level rule layered over native absence | Use `native-non-existing-only-v1`. |

Query the source chain and confirm the IBC store contains code:

```bash
export SOURCE_L2_RPC_URL='https://source-l2.example'
export IBC_STORE_ADDRESS='0x...'

cast chain-id --rpc-url "$SOURCE_L2_RPC_URL"
cast code "$IBC_STORE_ADDRESS" --rpc-url "$SOURCE_L2_RPC_URL"
```

When an existing destination light client already represents the same source
deployment, its configured IBC store can be read with:

```bash
export DESTINATION_RPC_URL='https://destination.example'
export CURRENT_LIGHT_CLIENT='0x...'

cast call "$CURRENT_LIGHT_CLIENT" \
  'IBC_STORE()(address)' \
  --rpc-url "$DESTINATION_RPC_URL"
```

Use the source Router or storage proxy address, not its implementation
contract. Confirm the address against the source deployment record before
adding it to the profile.

## IBC fields

| Field | Meaning | How to obtain it |
| --- | --- | --- |
| `ibcContractsCommit` | Exact IBC contracts source revision used by the source deployment | Run `git rev-parse HEAD` in the reviewed IBC contracts checkout, or read it from the signed deployment record. |
| `supportedPathShapeId` | IBC path encoding implemented by the guests | For the supported production Eureka contracts, use `ibc-eureka-v2-terminal-path-v1`. |

Confirm the IBC source revision with:

```bash
export IBC_CONTRACTS_SOURCE_DIR='/absolute/path/to/reviewed-ibc-contracts'
git -C "$IBC_CONTRACTS_SOURCE_DIR" rev-parse HEAD
```

The commit must be the source revision used to deploy `ibcStoreAddress`, not
simply the latest repository commit.

## Validate and approve the profile

Format and inspect the completed JSON:

```bash
jq . "$SOURCE_PROFILE_FILE"
```

Run the repository validator and derive the `SOURCE_PROFILE_ID`:

```bash
install -d -m 755 target release

PROFILE_OUTPUT="$(
  cargo run --quiet --locked --offline \
    -p prividium-source-profile --bin profilec -- \
    "$SOURCE_PROFILE_FILE" \
    target/generated-source-profile.rs
)"

export SOURCE_PROFILE_ID="${PROFILE_OUTPUT#SOURCE_PROFILE_ID=}"
printf 'SOURCE_PROFILE_ID=%s\n' "$SOURCE_PROFILE_ID"
```

Record a checksum of the exact reviewed file:

```bash
sha256sum "$SOURCE_PROFILE_FILE" | awk '{print $1}' \
  >release/source-profile.sha256
cat release/source-profile.sha256
```

Review the following before approval:

- the Beacon genesis and spec responses match the `consensus` section;
- every address is a proxy or contract address from the correct deployment;
- the settlement and IBC commits match the deployed contracts;
- storage slots come from the compiler layout for those exact commits;
- all selectors and rule identifiers are supported by this repository; and
- the profile contains no secrets or authenticated URLs.

After approval, use this exact file for:

1. `scripts/generate-vkeys.sh`;
2. `scripts/capture-beacon-bootstrap.sh`;
3. `scripts/deploy-light-client.sh`; and
4. the Proof API build and runtime configuration.

The checksum and `SOURCE_PROFILE_ID` must remain the same in all four steps.
