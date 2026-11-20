# Integration

This guide describes how the four-circuit client connects to the proving
service, relayer, source RPCs, destination Router, and SP1 network.

## Runtime flow

```text
relayer request
    -> Proof API reads destination trust/state
    -> Proof API collects and validates exact source evidence
    -> Proof API encodes the witness and submits the embedded ELF to SP1
    -> Proof API verifies the Groth16 proof and validates public outputs
    -> relayer submits through ICS26 Router
    -> light client verifies the selected VKey route
```

## Endpoints

The service needs a Beacon REST API, L1 execution JSON-RPC, ZKsync OS
JSON-RPC with batch metadata and `zks_getProof`, destination JSON-RPC, SP1
network gateway, and a gRPC listener reachable by the relayer.

Use authenticated TLS or a private authenticated network. Keep tokens and
private keys outside the repository.

## End-to-end components

| Component | Required behavior |
| --- | --- |
| Beacon endpoint | Supplies bootstrap, period updates, optimistic updates, genesis, spec, and fork schedule |
| L1 execution endpoint | Retains exact blocks and supports `eth_getProof` for settlement evidence |
| ZKsync endpoint | Maps L2 blocks to batches and serves `zks_getProof` after batch execution |
| Destination endpoint | Reads trust/client identity and accepts Router transactions |
| Proof API | Collects evidence, constructs witnesses, proves the four embedded ELFs through SP1, verifies proofs locally, and serves gRPC |
| SP1 network gateway | Accepts proof jobs from the embedded SP1 SDK and returns Groth16 artifacts |
| Relayer | Uses the standard remote-prover interface and preserves request context/order |
| Router | Resolves the registered client and invokes the light-client interface |

## Startup identity

Before listening, verify source and destination chain identities, destination
Router and resolved client, counterparty client and prefix, SourceProfile ID,
four VKeys, IBC store, absence profile, SP1 gateway and route, and destination
consensus trust.

Recheck mutable Router/client identity before proving and before returning a
proof. Reject stale work if relevant destination state changes while proving.

## Submission order

`StateProof` normally returns one Settlement envelope. If the Settlement needs
a later sync-committee period, the service creates ordered Trust Update proofs.
For a large gap, its trust-update signer submits and confirms earlier Trust Updates as
individual `Router.updateClient` transactions. The final response contains any
remaining Trust Updates followed by Settlement. The relayer still makes its normal
`StateProof` request. Membership or Non-Membership is submitted only after the
required trust and Settlement state exist.

Settlement and packet-proof generation may run in parallel because both are
bound to the same source batch and root. On-chain execution is strictly
ordered: `updateClient` must execute before `recvPacket`, acknowledgement, or
timeout verification. The Settlement update and Router packet call may be in
one atomic Router transaction. The first Membership call verifies the shared
SP1 proof and stores its root. Later CACHED claims can use that root only after
the FULL envelope succeeds. Non-Membership is rejected when its Settlement
state does not exist.

## Proof packages

An update envelope contains the operation discriminator, exact ABI public
values, and Groth16 proof bytes. Trust and Settlement updates use different
VKeys and public-value layouts.

One Membership proof covers 1 to 64 ordered claims. The first returned FULL
envelope carries the shared public values, SP1 proof, batch metadata, leaf
index, and Merkle siblings. Each later CACHED envelope omits the SP1 payload
and carries only the same batch metadata and its Merkle branch. The contract
recomputes every leaf from the Router path and value before checking the
branch. The relayer submits these opaque envelopes without a separate
registration transaction.

Non-Membership remains a direct proof envelope containing its exact public
values and proof bytes. The relayer still supplies proof height and path. The
contract recomputes request bindings rather than trusting response metadata.

Raw Groth16 bytes alone are insufficient. Public values and the route-specific
envelope must remain intact.

## Height mapping

Settlement public values contain the authenticated batch-end L2 block
`B_end`, L1 batch number `K`, native root, and timestamp. The contract stores
that state by `K`. The relayer may request a packet proof using the
packet event block. The proof commits that exact event height. The contract
requires it to equal the relayer-supplied height and not be newer than
`B_end`, then binds the proof's `K` and root to the accepted Settlement state.

## Proof API status

`tooling/proof-api` is the standalone gRPC service for this four-circuit flow.
It implements latest provable height, Settlement state proof, Membership, and
Non-Membership requests used by the relayer. Trust maintenance is performed
automatically inside `StateProof`; an optional standalone Trust Update endpoint
is retained for administrative use. The service embeds the four reviewed ELFs
and uses the SP1 SDK directly. It does not depend on a separate witness/proof
backend process.

Deploy it with the reviewed release artifacts by following
[`../tooling/proof-api/docs/DEPLOYMENT.md`](../tooling/proof-api/docs/DEPLOYMENT.md).
That guide provides both the Docker Compose path and the direct host launcher.
This settlement-backed hard-finality service does not use an attestor key.

The service bounds concurrent workers and queued requests. Matching in-flight
retries share one proof job, successful completed results remain in a bounded
memory cache, and excess distinct work is rejected instead of growing memory
without limit. A restart discards in-memory work; matching relayer retries
submit it again.

The soft-finality `proof-api-operator` branches are not compatible. They use
an attestor-signed Update Client statement instead of Beacon Trust Update and
Settlement Update.

## Relayer compatibility

Correctness must not require a relayer source-code patch. The Proof API must
accept the published gRPC request shapes, preserve input order, split work
within circuit/service limits, and return proof envelopes in corresponding
order.

Relayer request timeout must exceed worst-case queue plus proving time, or
proofs must be prewarmed and cached. A timeout may trigger a retry; identical
requests must be deduplicated rather than generating unlimited duplicate jobs.

## Forward, acknowledgement, and timeout flows

### Forward receive

1. Source transaction writes a packet commitment.
2. Relayer requests source proof at the event height.
3. Proof service resolves the authenticated batch and destination trust.
4. For a large committee gap, the Proof API trust-update signer submits earlier Trust
   Updates individually through the Router and confirms each resulting state.
5. `StateProof` returns Settlement alone or the final Trust Update(s) plus
   Settlement composite.
6. The Router stores the resulting trust and batch/root/timestamp.
7. One Membership proof authenticates up to 64 requested packet commitments.
8. The first FULL Membership envelope verifies and stores the shared batch root.
9. The Proof API returns CACHED claims for the remaining packets.
10. Router submits `recvPacket` on the destination.

### Reverse acknowledgement

The destination acknowledgement is source state for the reverse client. It
requires the proof service for that reverse chain direction. This four-circuit
Prividium service proves only Prividium/ZKsync source state; it cannot replace
a proof service for the Besu source direction.

### Timeout

1. Packet timeout is reached without successful receive.
2. Relayer requests receipt absence on the Prividium/ZKsync source.
3. Settlement for the selected batch/root is accepted.
4. Non-Membership proves the receipt key is natively absent.
5. Router submits the timeout transaction.

An existing zero value is not absence and must fail the Non-Membership route.

## Runtime configuration and health

Production configuration should expose:

- endpoint URLs, token environment names, response-size limits, and TLS policy;
- destination Router, client ID, counterparty, gateway, and chain ID;
- SourceProfile ID and all four VKeys;
- destination trust-update signer key environment variable, destination chain ID,
  receipt timeout, polling interval, and maximum transaction gas; the account
  must have the Router `updateClient` permission;
- `maxAutomaticTrustUpdates` in `1..=8`, which bounds each in-memory catch-up
  group and the final composite; larger gaps are advanced through individually
  confirmed Trust Update transactions before Settlement;
- SP1 endpoint, credential environment name, and proof timeout;
- bounded concurrent requests and queued jobs;
- cache path, size, retention, and restart behavior; and
- polling/readiness intervals.

Readiness must be false when RPCs, SP1, Router resolution, client identity,
VKeys, verifier route, or trust state cannot be validated. Health must not
report ready merely because the TCP listener is open.

## Integration acceptance checklist

Before switching Router traffic:

1. prove or confirm committee maintenance;
2. accept a fresh Settlement state;
3. relay a Membership packet;
4. relay a full 64-packet Membership request and confirm that it produces one
   SP1 proof, one registration, and 64 compact claims;
5. verify destination execution;
6. prove and submit the acknowledgement return leg;
7. run a separate timeout invoking Non-Membership; and
8. restart the service and confirm retry/cache recovery.

Record the Proof API and circuit commits, profile hash, four VKeys, contract,
relayer version, RPC identities, and transaction hashes.

Also confirm overload rejection, duplicate retry handling, exact-height RPC
retention, stale-state cancellation, client migration detection, TLS/auth,
reverse-direction proof availability, and source/destination clock behavior.
