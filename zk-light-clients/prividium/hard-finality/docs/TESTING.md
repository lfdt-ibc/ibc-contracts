# Testing

Testing is divided into fast logic tests, mock-verifier contract tests, real
SP1 tests, and connected E2E tests. Passing one layer does not replace another.

## Verification layers

| Layer | Purpose | Generates Groth16 |
| --- | --- | ---: |
| Rust unit and regression tests | Exercise parsing, hashing, proof verification, and transitions | No |
| Native witness validation | Runs the same shared statement outside zkVM | No |
| SP1 execute | Runs the compiled guest and checks committed public values | No |
| SP1 core | Produces the SP1 core proof used for debugging/performance | No Groth16 wrap |
| SP1 Groth16 | Produces the deployable proof envelope | Yes |
| Foundry mock verifier | Tests contract state and request binding quickly | No |
| Deployed gateway | Tests the real verifier route and calldata | Verifies Groth16 |
| Connected E2E | Tests RPC collection, proving, relayer, Router, and both chains | Yes |

## Rust checks

```bash
export PRIVIDIUM_SOURCE_PROFILE="$PWD/profiles/example.synthetic.json"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
```

These tests cover consensus transitions, BLS and SSZ validation, Ethereum MPT,
settlement storage, ZKsync native proofs, IBC key derivation, public-value
encoding, witness parsing, and the four program statements.

The standalone Proof API has its own lockfile and test command:

```bash
cd tooling/proof-api
cargo fmt --all -- --check
cargo clippy --all-targets --locked --no-default-features -- -D warnings
cargo test --all-targets --locked
PRIVIDIUM_SP1_ELF_DIR="$PWD/../../target/elf-compilation/riscv64im-succinct-zkvm-elf/release" \
  cargo build --release --locked --features sp1
cd ../..
```

These tests cover strict configuration, RPC response handling, bootstrap
fallback, destination-state binding, packet validation, proof artifacts,
request limits, and gRPC response encoding. They do not replace a connected
test against the selected SP1 network gateway.

## Solidity tests

```bash
./scripts/install-contract-deps.sh
cd contracts
forge fmt --check
forge test -vvv
```

The mock verifier makes lifecycle tests fast. It does not prove that the real
SP1 gateway accepts a generated Groth16 proof.

Contract coverage should include authorized and unauthorized Router calls,
strict decoding, four distinct VKey routes, verifier-before-write ordering,
trust transitions, stale digests, Settlement replay behavior, request binding,
and rejection before Settlement acceptance.

## Required regression matrix

### SourceProfile and artifacts

- unknown fields, incomplete fork maps, invalid schemas, and zero generalized
  indices fail;
- profile canonicalization produces a stable ID;
- changing a security field changes the profile ID;
- all four ELFs use the same profile;
- VKeys are nonzero, distinct, and match their ELFs; and
- two clean builds produce identical ELF hashes.

### Trust Update

- previous trust digest must match;
- current and next committee period boundaries are enforced;
- committee root, participation bits, BLS signature, fork/domain, finality
  branch, and next-committee branch are authenticated;
- same-slot conflicting finalized roots fail;
- verifier failure leaves trust unchanged; and
- Trust proof cannot be routed as Settlement.

### Settlement Update

- previous trust digest and SourceProfile must match;
- optimistic-header signature and execution branch are authenticated;
- L1 account and storage proofs bind the configured settlement proxy and slot;
- stored-batch hash binds every required batch field;
- native root and timestamp come from the authenticated state commitment;
- identical replay is a no-op;
- conflicting root or timestamp fails; and
- Settlement never mutates consensus trust.

### Native state and IBC paths

- account, storage slot, native key, path grammar, and mapping base slot bind;
- compressed and full paths reconstruct the same root;
- malformed ordering, links, siblings, and proof types fail;
- existing zero remains Membership, not absence;
- only native `NonExisting` satisfies the current absence profile; and
- multiple requested slots reconstruct one root.

### Membership and Non-Membership

Membership batching must cover request sizes 1, 2, 63, and 64. For 64
compatible claims, assert that the source collector makes one multi-slot
`zks_getProof` request, the service generates one Membership artifact, and the
API returns one FULL envelope followed by 63 CACHED claims in request order.
Also reject CACHED-before-FULL, malformed modes and payloads, an empty batch,
65 claims, duplicate paths, reordered
slots, a wrong batch root, an invalid entry index, a wrong branch length, and
a claim whose path or value differs from the Router request.

Non-Membership remains one proof per absence request. It must not be accepted
as a Membership claim or verified under the Membership VKey.

- accepted batch and root must exist and match;
- IBC store, path digest, storage slot, native key, value hash, absence profile,
  and request digest must match;
- wrong proof height and revision fail;
- wrong dedicated VKey fails;
- unauthorized Router caller fails; and
- malformed or trailing ABI data fails.

### Destination deployment

- zero configuration and duplicate VKeys fail;
- constructor trust state is canonical;
- verifier is called before state writes;
- deployed immutable values match the manifest;
- Router resolution and counterparty settings match; and
- verifier route cannot silently change under the selected governance policy.

## Real SP1 tests

For each program:

1. collect or construct a witness;
2. validate it natively;
3. execute the guest;
4. compare committed public values with the native result;
5. generate a Groth16 proof;
6. verify it locally; and
7. verify it through the deployed gateway.

Use only ELFs built from the same profile and commit as the deployed VKeys.

## Connected lifecycle

The deterministic Router integration suite covers the local contract boundary
without requiring live chains or Groth16 generation:

```bash
IBC_CONTRACTS_DIR=/path/to/pinned/ibc-contracts \
  ./e2e/scripts/run-router-e2e.sh
```

It deploys the real `ICS26Router`, registers the Prividium client and a test
application, and exercises Settlement-before-Membership packet receipt and
Settlement-backed Non-Membership timeout. See [`../e2e/README.md`](../e2e/README.md)
for the dependency pin and setup. This suite uses a mock SP1 verifier and does
not replace the live connected lifecycle below.

```text
read destination trust
    -> StateProof returns Settlement Update alone, or an atomic
       Trust Update(s) + Settlement Update composite when required
    -> Membership
    -> destination recvPacket
    -> acknowledgement return leg
```

The timeout path must independently exercise Non-Membership. A timed-out
packet alone does not prove that this Non-Membership program ran. Retain the
Proof API logs, program name, VKey, timing, and destination transaction.

Also test Router call ordering. Membership and Non-Membership must fail before
their Settlement batch is accepted, succeed when `updateClient` precedes them
in the same atomic transaction, and leave no accepted batch behind when a
later packet-proof verification reverts.

Run connected tests against a separately managed environment containing the
Beacon, L1 execution, ZKsync OS, destination EVM, SP1 gateway, Proof API, and
relayer services. Capture fresh addresses, VKeys, witnesses, and timings for
every run.

## Performance evidence

Record source inclusion, batch settlement and `zks_getProof` readiness,
witness collection, queue wait, SP1 proving, local verification, relayer
submission, destination mining, and acknowledgement return separately.

For each proof, record cold/warm status, CPU, memory, GPU average and peak,
proof size, public-value size, source height, batch number, and transaction
hash. Do not report relayer waiting or settlement delay as SP1 proving time.

## Release acceptance

A production candidate requires all fast checks, reproducible ELFs, a reviewed
four-VKey manifest, real gateway verification for all four programs, forward
Membership, acknowledgement return, timeout Non-Membership, and retry/restart
tests.

## Coverage

Measure Rust coverage with the project-approved `cargo llvm-cov` version and
Solidity coverage with Foundry. Exclude generated bindings, third-party
dependencies, and guest entrypoint boilerplate only when the exclusion is
recorded.

Run the project coverage workflow:

```bash
./scripts/coverage.sh all
```

It writes LCOV and text summaries under `target/coverage/core`,
`target/coverage/proof-api`, and `target/coverage/contracts`. Individual
actions are `core`, `proof-api`, and `contracts`; set `HTML=1` for Rust HTML
reports.

Coverage percentage is not proof of security. Every consensus branch,
boundary, malformed witness, stale-state condition, and contract authorization
path still needs an explicit assertion.

## Test evidence

For each release retain commands, commit, dirty status, profile checksum and
ID, ELF hashes, VKeys, test output, proof artifacts, gateway result, source and
destination transaction hashes, and resource samples. Put large evidence under
ignored `target/test-evidence/` or an artifact store.
