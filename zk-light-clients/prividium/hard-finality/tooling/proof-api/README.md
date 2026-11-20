# Prividium Proof API

Rust relayer-facing Proof API and chain-data host for the Prividium SP1 light client.

## Scope

The Proof API is the single relayer-facing proving service for this branch. It
collects and validates source-chain evidence, reads destination trust state,
constructs witnesses for the four reviewed programs, submits those programs to
the SP1 network gateway, verifies the returned Groth16 proofs locally, and
returns the Solidity ABI proof envelope to the relayer.

The four ELFs are embedded in the release binary. The service derives their
VKeys during startup and compares them with the configured destination client.
It does not call a separate HTTP proof backend and does not require another
application service for witness encoding or circuit selection.

The service exposes `ibc.v2.prover.ProverService` over gRPC:

- `LatestProvableHeight`
- `StateProof` for Settlement Update, with automatic Trust Update bundling when required
- `PacketProofs` for membership, acknowledgement, and receipt absence

`TrustUpdateProof` is also available as an optional administrative operation.
The relayer does not need to call it because `StateProof` performs required
trust catch-up automatically.

## Deployment guide

Use [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the complete host and Docker
Compose procedures. The recommended production path is the checked-in Compose
file and `scripts/start-proof-api.sh`. The launcher verifies the reviewed
SourceProfile, initial trust artifact, VKey manifest, and all four ELF hashes
before it writes the runtime JSON and starts the service.

The launcher starts only this Proof API. The source RPCs, Beacon API,
destination Router, SP1 network gateway and workers, and relayer must already
be available.

## Build and run manually

Build the four guests from the repository root. Use the same reviewed
SourceProfile that will be deployed with the light client.

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/source-production.json"
./scripts/build-sp1.sh
export PRIVIDIUM_SP1_ELF_DIR="$PWD/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"

cargo build --manifest-path tooling/proof-api/Cargo.toml \
  --release --locked --features sp1

export PRIVIDIUM_PROOF_API_TOKEN='replace-with-at-least-32-bytes'
export PRIVIDIUM_SP1_NETWORK_PRIVATE_KEY='replace-with-the-network-key'
export PRIVIDIUM_L2_RPC_TOKEN='replace-with-at-least-32-bytes'
export PRIVIDIUM_L1_RPC_TOKEN='replace-with-at-least-32-bytes'
export PRIVIDIUM_DESTINATION_RPC_TOKEN='replace-with-at-least-32-bytes'
export PRIVIDIUM_BEACON_TOKEN='replace-with-at-least-32-bytes'
export PRIVIDIUM_TRUST_UPDATE_REGISTRAR_PRIVATE_KEY='replace-with-the-destination-key'

cp tooling/proof-api/config.example.json tooling/proof-api/config.json
cp tooling/proof-api/initial-trust.example.json /etc/prividium/initial-trust.json
sha256sum /etc/prividium/initial-trust.json
# Put the digest in bootstrap.initialTrustSha256 after replacing every placeholder.
./tooling/proof-api/target/release/prividium-proof-api \
  --config tooling/proof-api/config.json
```

Secrets are read only from the environment variables named in configuration.
Authenticated remote endpoints must use HTTPS; plaintext HTTP is accepted only
for loopback endpoints. A bearer token is mandatory if the gRPC listener is not
bound to a loopback address. HTTP redirects are disabled.

For a container release, first copy the four reviewed ELFs into one artifact
directory and place the reviewed profile at a stable path. Build from the
repository root with both named contexts required by the Dockerfile:

```bash
export ELF_DIR="$PWD/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
export PROFILE_DIR="$PWD/target/proof-api-source-profile"
install -d -m 755 "$PROFILE_DIR"
install -m 644 "$PRIVIDIUM_SOURCE_PROFILE" "$PROFILE_DIR/source-profile.json"

docker buildx build --load \
  --build-context circuit-artifacts="$ELF_DIR" \
  --build-context source-profile="$PROFILE_DIR" \
  -f tooling/proof-api/Dockerfile \
  -t prividium-proof-api:reviewed .
```

For a host deployment that generates the configuration and starts the service
in one step, copy and complete the protected environment template:

```bash
install -d -m 700 /etc/prividium-l1-proof-api
install -m 600 tooling/proof-api/config/operator.env.example \
  /etc/prividium-l1-proof-api/operator.env
${EDITOR:-vi} /etc/prividium-l1-proof-api/operator.env

tooling/proof-api/scripts/start-proof-api.sh \
  /etc/prividium-l1-proof-api/operator.env
```

The default request timeout is 1,800 seconds because SP1 proof jobs can exceed
five minutes. `prover.proofTimeoutSeconds` independently bounds each SP1 network
proof and accepts values up to 24 hours. The API admits at most
`maxConcurrentRequests` proof workers
and bounds waiting work with `maxQueuedRequests`. Matching in-flight retries
share one engine job. Height lookups use the independent
`maxConcurrentHeightRequests` pool, so long proof jobs cannot starve relayer
finality checks. Successful height-bound proof results use a bounded memory
cache; changing Trust Updates and height lookups are never cached. New work is
rejected with `RESOURCE_EXHAUSTED` when a bounded capacity is full.

## Latest provable height

The service reads the L2 head through `eth_blockNumber`, then searches backward
within `l2Rpc.maxBatchLookback` using decimal
`unstable_getBatchByBlockNumber` parameters. It returns the first batch with a
non-null `execute_sl_block_number` and its authenticated
`batch_info.last_block_timestamp`. Null or unexecuted batches are not exposed.

## Initial trust and Lighthouse 404 fallback

At startup the service calls:

```text
GET /eth/v1/beacon/light_client/bootstrap/{finalizedCheckpointRoot}
```

A successful response is accepted only for Fulu and only if the SSZ root of the
returned Beacon header equals the configured checkpoint root. The committee
size and all BLS public-key widths are checked.

Only an explicit HTTP 404 activates the pinned `initialTrustPath` fallback.
The file must match `initialTrustSha256`, the configured checkpoint root,
SourceProfile ID, and sync-committee size. The API recomputes the complete
current-committee SSZ root and compares it with the declared trusted root.
Timeouts, authentication failures, 5xx responses, malformed JSON, fork
mismatches, and root mismatches fail startup instead of activating fallback.

`initial-trust.example.json` is a template containing invalid zero placeholders.
For a demo, replace it with a finalized canonical Fulu checkpoint and complete
committee approved out of band by the demo owner. This is an explicit initial
trust assumption.

## Trust Update

The Proof API reads the destination contract's exact current consensus
trust state, determines the reachable sync-committee period, obtains one Fulu
`/eth/v1/beacon/light_client/updates` response, and supplies the full signing
committee. Before submission it checks slot monotonicity, fork, branch sizes,
bitfield padding, and the required two-thirds committee participation.

The returned artifact must be the Trust Update program/version, bind the
configured SourceProfile, bind the pre-update destination trust digest, and
contain a valid monotonic finalized transition. The destination trust digest is
read again after proving; a concurrent change invalidates the result and forces
a retry.

When `StateProof` needs trust from a later sync-committee period, the API first
generates the required Trust Update proof or proofs and then generates the
Settlement proof against the resulting trust digest. Up to eight Trust Updates
and the Settlement are returned in one composite envelope for the Router. If
the gap is larger, the API first submits earlier Trust Updates individually
through the Router, waits for every receipt, and verifies each stored trust
digest. It then returns the final Trust Updates and Settlement through normal
`StateProof`. Any invalid composite component reverts its transaction.

## Settlement Update

For `StateProof`, the API:

1. maps the requested L2 event block to its executed L1 batch `K`;
2. calls `zks_getProof` for the configured native-root probe at batch `K`;
3. binds the response to address, slot, and batch and extracts the batch-end L2 block and
   authenticated batch timestamp;
4. fetches the Fulu optimistic light-client update;
5. derives the Diamond `storedBatchHash[K]` mapping slot and loads the reviewed
   `totalBatchesExecuted` slot from the SourceProfile;
6. calls L1 `eth_getProof` for both slots at the execution block authenticated
   by that update;
7. validates the full 256-bit nonzero stored-batch value, requires
   `K <= totalBatchesExecuted`, and validates both proof shapes; and
8. binds the generated artifact to the batch-end L2 block, `K`, timestamp,
   SourceProfile, and the
   destination trust digest.

The SP1 circuit remains authoritative: it authenticates the sync-committee
signature and SSZ execution branch, verifies the L1 Merkle-Patricia proof, and
binds the stored batch hash to the native ZKsync proof, and independently
enforces the executed-batch counter. Host validation rejects bad evidence early
but is not substituted for circuit verification.

## Packet proofs

For every packet the API derives the reviewed logical path:

```text
counterpartyClientId || pathType || sequence_be_u64
```

It derives the configured direct Solidity mapping slots and makes one real
ZKsync OS v0.20.8 `zks_getProof` request for all slots in a Membership request.
The validator binds address, ordered slots, batch, state-commitment fields, and
L1 verification data. Duplicate logical paths are rejected.

Membership and acknowledgement require the tagged `existing` variant, including
an existing zero value. Receipt absence requires the tagged `nonExisting`
variant; the left and right leaf keys must strictly bracket the derived native
key and `left.nextIndex` must equal `right.index`. Receipt absence additionally
requires a nonzero packet timeout reached by the authenticated L2 batch
timestamp.

Requests are limited to 64 packets, one payload per packet, 1 MiB per payload,
and 256 bytes per packet text field. A Membership or acknowledgement request
produces one shared Membership SP1 proof for the whole request. Receipt absence
continues to produce one Non-Membership proof per packet. Packet direction is
checked against the configured client pair before any RPC or proving work
starts.

The complete reviewed SourceProfile file is hash-pinned. Its profile ID,
storage addresses and slots, path/storage selectors, absence rule, committee
size, and consensus timing parameters must exactly match configuration.

## Artifact and destination binding

The API rejects unknown artifact fields, trailing JSON, malformed/noncanonical
hex, an incorrect program name or version, an incorrect SourceProfile, and
incorrect public-value length. It independently checks request-specific public
values before constructing the ABI envelope expected by the destination light
client.

Trust and Settlement requests pin `getConsensusTrustState()` with `eth_call` at
an explicit destination block and compute the same
`keccak256(abi.encode(...))` digest as Solidity. The digest is checked again
after proof generation; destination blocks may advance, but a changed trust
digest makes the proof result stale and it is discarded.

At startup and before state-sensitive work, the API resolves the light client
through `Router.getClient(clientId)`, validates Router counterparty ID and
Merkle prefix, and checks the SourceProfile ID, four VKeys, IBC store, absence
profile, verifier, and Router getters. It also checks the configured chain ID
against each L2, L1, and destination JSON-RPC endpoint.

For Membership, the embedded program returns one artifact whose public values
commit to the ordered claim count and Merkle root. The API returns a FULL
envelope for the first packet and CACHED envelopes for the remaining packets.
The destination contract verifies and stores the shared proof during the first
Membership call, so no separate registration transaction is required. For
Non-Membership, the service generates one artifact per packet.

The trust-update signer is configured under
`destination.trustUpdateRegistrar`. Set
`privateKeyEnv` to the environment variable containing its private key.
`chainId`, `receiptTimeoutSeconds`, `receiptPollMilliseconds`, and `maxGas`
bound transaction submission. The account needs native currency only when the
destination reports a nonzero gas price. It must also have permission to call
`updateClient` on the destination Router. The service uses that permission only
when consensus trust requires more than one bounded catch-up transaction.

`maxAutomaticTrustUpdates` controls the number of sequential Trust Update
proofs retained in each catch-up group. The default is `8`; valid values are
`1..=8`. When the committee gap is larger, the service submits the completed
group as individual `Router.updateClient` transactions, checks every receipt
and resulting trust digest, and continues. Once the Settlement signature
period is reachable, the final Trust Updates and Settlement are returned in
the normal `StateProof` response. The upper bound is eight because that final
composite accepts at most nine components: eight Trust Updates and Settlement.

## SP1 connection and readiness

`prover.networkRpcUrl` is the SP1 network gateway used by the embedded SDK.
`prover.networkPrivateKeyEnv` names the environment variable containing the
gateway credential. The service initializes all four programs, derives their
VKeys, compares them with destination configuration, and checks gateway
readiness before opening the gRPC listener.

The generated public values are decoded and checked against the original
request before any proof is returned or registered. For a Membership or
acknowledgement request containing 1 to 64 packets, the service produces one
shared artifact. For receipt absence, it produces one Non-Membership artifact
per packet.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --all-targets --locked
PRIVIDIUM_SP1_ELF_DIR="$PWD/../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release" \
  cargo build --release --locked --features sp1
```

Live integration still requires the deployment-specific L2, L1 execution,
Beacon, destination Besu, and SP1 network gateway endpoints plus their
credentials.
