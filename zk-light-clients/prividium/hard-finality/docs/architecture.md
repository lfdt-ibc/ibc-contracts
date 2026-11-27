# Architecture

This light client authenticates IBC state from a Prividium/ZKsync OS source
chain through its private Ethereum PoS settlement chain. Verification is split
across four SP1 programs so consensus maintenance, settlement acceptance, and
application-state proofs remain separate.

## Components

```text
Beacon API        L1 execution RPC        ZKsync OS RPC
    |                    |                     |
    +---------- witness collection -----------+
                         |
                         v
                 proving host / Proof API
                         |
             +-----------+-----------+
             |           |           |
             v           v           v
         Trust       Settlement   Membership /
         Update        Update     Non-Membership
             |           |           |
             +-----------+-----------+
                         |
                         v
              destination ICS26 Router
                         |
                         v
              PrividiumZKLightClient
                         |
                         v
                  SP1 verifier gateway
```

| Component | Responsibility |
| --- | --- |
| Beacon API | Supplies bootstrap, light-client updates, optimistic updates, and committee data |
| L1 execution RPC | Supplies settlement account and storage proofs |
| ZKsync OS RPC | Supplies batch metadata and native storage proofs |
| Proving host | Collects consistent evidence, builds witnesses, validates them natively, and invokes SP1 |
| Destination Router | Calls the light-client update and packet-verification interface |
| Light-client contract | Routes VKeys, stores consensus trust and accepted batch roots, and binds Router requests |
| SP1 gateway | Verifies Groth16 proofs for the pinned verifier route |

## Stored state

```text
ConsensusTrustState {
    finalizedBeaconSlot
    finalizedBeaconHeaderRoot
    currentSyncCommitteeRoot
    nextSyncCommitteeRoot
    nextSyncCommitteeKnown
}

acceptedBatches[K] = {
    l2BlockNumber
    nativeRoot
    l2BatchTimestamp
    exists
}
```

Trust Update is the only program that changes `ConsensusTrustState`.
Settlement Update authenticates one L1 batch `K` using the current trust
digest and stores its native root and timestamp. Membership and
Non-Membership are read-only and can use only an accepted batch.

## Trust Update

Trust Update verifies a full Ethereum light-client update. It binds the proof
to the destination's current trust digest, verifies the sync-committee
signature and SSZ branches, and outputs the next finalized header and
committee roots.

This is a maintenance path. It is needed when stored committee state can no
longer authenticate the signature used by a new Settlement proof.

## Settlement Update

Settlement Update verifies:

```text
trusted sync committee
    -> signed Beacon header
    -> execution payload state root
    -> settlement account proof
    -> batch-specific stored-hash proof
    -> totalBatchesExecuted proof from the same L1 state
    -> batch number <= totalBatchesExecuted
    -> ZKsync stored-batch commitment
    -> native root and source timestamp
```

The contract accepts the first root and timestamp for a batch and rejects a
conflicting replay.

The attested Beacon header must be at or after the finalized checkpoint
already stored by the light client. At the same slot, its root must match the
trusted finalized root. A newer header remains optimistic and is authenticated
by its reachable sync committee.

Both storage proofs are verified against the settlement account storage root
authenticated by the same Beacon execution payload. The host-side
`executeSLBlockNumber` check is an early availability check; the SP1 program
independently proves that the candidate batch has reached execution.

Settlement authenticates the batch-end L2 block `B_end` together with L1
batch number `K`, root, and timestamp. The contract stores the accepted state
by `K`. A packet event height may precede `B_end`; it cannot be newer than the
authenticated batch state used by Membership or Non-Membership.

## Membership and Non-Membership

Membership proves that an expected value exists at the derived native-tree
key. Non-Membership proves native absence under the configured absence rule.
Both programs bind the SourceProfile, accepted batch and root, IBC store,
logical path, derived storage key, and request digest.

Membership additionally binds the expected value. Non-Membership binds the
absence profile. The contract checks the proof root against the root already
accepted by Settlement Update before invoking the appropriate VKey.

## SourceProfile and artifact identity

The SourceProfile freezes the consensus and storage rules that guests cannot
discover safely at runtime. It includes:

- Beacon genesis and slot/epoch constants;
- fork schedule and supported header schemas;
- finality, next-committee, and execution generalized indices;
- settlement proxy and stored-batch mapping information;
- ZKsync OS and native-root binding rules;
- IBC store address, mapping base slot, and path grammar; and
- absence profile and maximum client-ID length.

The profile is canonicalized and hashed to `SOURCE_PROFILE_ID`. Guest
constants and therefore ELFs/VKeys depend on it. The host, four guests,
deployment manifest, and contract must all use the same identity.

## Contract ordering and replay behavior

```text
current consensus trust
       |
       +-- Trust Update ----------> new consensus trust
       |
       +-- Settlement Update K ---> acceptedBatches[K]
                                          |
                       +------------------+------------------+
                       |                                     |
                       v                                     v
                 Membership                           Non-Membership
```

Settlement proofs bind the previous trust digest but do not mutate trust.
Trust Update does not mutate accepted batches. Membership and Non-Membership
do not mutate either state.

The first valid Settlement proof inserts `(K, root, timestamp)`. Repeating
the same tuple is a no-op. A different root or timestamp for the same `K`
reverts. Packet proofs cannot be accepted before their batch exists.

## Protocol bounds

| Bound | Value or source | Enforcement |
| --- | --- | --- |
| Host input file | 64 MiB | Proving CLI before allocation |
| RPC response | 64 MiB | Bounded RPC reader |
| Ethereum MPT nodes | 65 | MPT verifier |
| Ethereum MPT node size | 4,096 bytes | MPT verifier |
| SourceProfile text field | 256 bytes | Profile parser |
| SourceProfile list | 128 entries | Profile parser |
| Client ID | Profile-defined; synthetic profile uses 128 bytes | IBC path parser |
| Absence profile | ID 1, native non-existing only | Profile, guest, and contract |
| IBC Router path | One non-empty path element in the current contract | Destination contract |

These are protocol or safety bounds, not Proof API queue settings. Changing a
guest-enforced bound can change the ELF and VKey.

## Failure behavior

The implementation fails closed when the previous trust digest, profile,
schema, program version, committee, branch, settlement proof, native proof,
path, value, root, request digest, or VKey route does not match. The contract
verifies SP1 before writing state.

RPC availability, exact-height retention, proving capacity, queueing, and
relayer retries are operational concerns. They must not weaken guest or
contract validation.

## Security assumptions and limitations

The SourceProfile is compiled into every guest and identifies the consensus,
settlement, ZKsync, and IBC storage rules. A profile change produces a new
artifact set and normally new VKeys.

The host is not trusted to assert roots or public outputs. Security-critical
bindings must be verified inside a guest or by the destination contract. The
host remains responsible for availability, exact-height collection, request
ordering, resource limits, retries, and secure credential handling.

Settlement Update authenticates an optimistic Beacon header. This is an
explicit security model and must not be described as Ethereum finality.
Durable finalized trust is advanced only by Trust Update.

The current contract has no maximum-clock-drift check, emergency pause, or
accepted-batch invalidation mechanism. The current E2E deployment helper also
uses the broadcaster as Router and leaves its newly deployed verifier route
unfrozen. These are production review items, not properties to copy into a
deployment.

Settlement public values commit the batch-end L2 block, L1 batch `K`, root,
and timestamp. Membership and Non-Membership use the accepted state for `K`;
the relayer's event height must not be newer than that authenticated batch-end
block.

Detailed encodings and algorithms are defined in [spec.md](spec.md).
