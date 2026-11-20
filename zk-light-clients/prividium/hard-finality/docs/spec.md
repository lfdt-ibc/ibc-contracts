# Prividium SP1 IBC Light Client - Implementation Specification v1.2

Document ID: `prividium-sp1-ibc-client-spec-v1.2`
Status: Normative implementation specification with explicit implementation gates
Audience: Rust engineers, Solidity engineers, ZK engineers, QA/security engineers, SREs, and coding agents
Primary proving system: SP1
Source execution environment: Prividium / ZKsync OS L2, pinned to ZKsync OS server `v0.20.8` / commit `dbb5c03d4a94ceb1acea9f79242590f354660239` for the current target profile
Source settlement environment: private Ethereum Proof-of-Stake L1 using Lighthouse `v8.1.3-176cce5` and Reth `v1.11.3-d6324d6` for the current target profile
Destination environment: generic EVM IBC chain with an SP1-backed Prividium light client
IBC integration baseline: upstream `lfdt-ibc/ibc-contracts` Solidity interfaces and Router semantics, pinned by the release manifest

---

# Document index

This index lists every section and subsection in this specification.

- [0. Normative language and implementation posture](#0-normative-language-and-implementation-posture)
  - [0.1 Single-source rule](#01-single-source-rule)
  - [0.2 Four-program rule](#02-four-program-rule)
  - [0.3 Core trust boundary](#03-core-trust-boundary)
  - [0.4 No fuzz-testing requirement](#04-no-fuzz-testing-requirement)
  - [0.5 Known-version and deployment-specificity rule](#05-known-version-and-deployment-specificity-rule)
- [1. Scope and architecture](#1-scope-and-architecture)
  - [1.1 Goal](#11-goal)
  - [1.2 Separation of responsibilities](#12-separation-of-responsibilities)
    - [Trust Update](#trust-update)
    - [Settlement Update](#settlement-update)
    - [Membership](#membership)
    - [Non-Membership](#non-membership)
  - [1.3 In scope](#13-in-scope)
  - [1.4 Out of scope for v1](#14-out-of-scope-for-v1)
- [2. Pinned external baselines](#2-pinned-external-baselines)
  - [2.1 Required release pins](#21-required-release-pins)
  - [2.2 Confirmed target deployment baselines](#22-confirmed-target-deployment-baselines)
  - [2.3 ZKsync OS reference profile](#23-zksync-os-reference-profile)
  - [2.4 Prototype code reuse rule](#24-prototype-code-reuse-rule)
- [3. Source profile and deployment-independence](#3-source-profile-and-deployment-independence)
  - [3.1 No organization-specific data in the repository](#31-no-organization-specific-data-in-the-repository)
  - [3.2 Profile-bound build](#32-profile-bound-build)
  - [3.3 SourceProfileV1 logical fields](#33-sourceprofilev1-logical-fields)
  - [3.4 Runtime-only values](#34-runtime-only-values)
  - [3.5 Gasless network operation](#35-gasless-network-operation)
- [4. Repository and module structure](#4-repository-and-module-structure)
  - [4.1 Dependency direction](#41-dependency-direction)
- [5. Canonical encoding and primitive types](#5-canonical-encoding-and-primitive-types)
  - [5.1 General rules](#51-general-rules)
  - [5.2 Guest stdin](#52-guest-stdin)
  - [5.3 Public values](#53-public-values)
- [6. Canonical consensus types](#6-canonical-consensus-types)
  - [6.1 ConsensusTrustState](#61-consensustruststate)
  - [6.2 BeaconBlockHeader](#62-beaconblockheader)
  - [6.3 SyncCommittee](#63-synccommittee)
  - [6.4 SyncAggregate](#64-syncaggregate)
  - [6.5 Light-client header](#65-light-client-header)
  - [6.6 Execution payload header](#66-execution-payload-header)
- [7. Shared Ethereum consensus verification](#7-shared-ethereum-consensus-verification)
  - [7.1 Slot, epoch, and sync-committee period](#71-slot-epoch-and-sync-committee-period)
  - [7.2 Signing committee reachability](#72-signing-committee-reachability)
  - [7.3 Authenticate full committee witness](#73-authenticate-full-committee-witness)
  - [7.4 Participant selection](#74-participant-selection)
  - [7.5 Fork version and sync-committee domain](#75-fork-version-and-sync-committee-domain)
  - [7.6 Signing root](#76-signing-root)
  - [7.7 BLS verification](#77-bls-verification)
  - [7.8 Generic SSZ branch verification](#78-generic-ssz-branch-verification)
- [8. Trust Update SP1 program](#8-trust-update-sp1-program)
  - [8.1 Statement](#81-statement)
  - [8.2 TrustUpdateWitness](#82-trustupdatewitness)
  - [8.3 Previous trust digest](#83-previous-trust-digest)
  - [8.4 Slot ordering](#84-slot-ordering)
  - [8.5 Authenticate attested Beacon header](#85-authenticate-attested-beacon-header)
  - [8.6 Finality branch](#86-finality-branch)
  - [8.7 Next sync committee branch](#87-next-sync-committee-branch)
  - [8.8 State transition](#88-state-transition)
  - [8.9 TrustUpdatePublicValues](#89-trustupdatepublicvalues)
  - [8.10 Guest algorithm](#810-guest-algorithm)
- [9. Settlement Update SP1 program](#9-settlement-update-sp1-program)
  - [9.1 Statement](#91-statement)
  - [9.2 No target-finality rule](#92-no-target-finality-rule)
  - [9.3 SettlementWitness](#93-settlementwitness)
  - [9.4 Authenticate recent Beacon header](#94-authenticate-recent-beacon-header)
  - [9.5 Execution payload root](#95-execution-payload-root)
  - [9.6 Execution branch](#96-execution-branch)
  - [9.7 Ethereum account MPT](#97-ethereum-account-mpt)
  - [9.8 Strict RLP/MPT requirements](#98-strict-rlpmpt-requirements)
  - [9.9 Settlement storage keys](#99-settlement-storage-keys)
  - [9.10 Storage MPT verification](#910-storage-mpt-verification)
  - [9.11 Batch acceptance](#911-batch-acceptance)
  - [9.12 K -> R_K binding](#912-k-rk-binding)
  - [9.13 SettlementPublicValues](#913-settlementpublicvalues)
  - [9.14 Guest algorithm](#914-guest-algorithm)
- [10. ZKsync OS native storage proof](#10-zksync-os-native-storage-proof)
  - [10.1 RPC model](#101-rpc-model)
  - [10.2 Canonical witness](#102-canonical-witness)
  - [10.3 Native tree key](#103-native-tree-key)
  - [10.4 Existing leaf hash](#104-existing-leaf-hash)
  - [10.5 Merkle path](#105-merkle-path)
  - [10.6 Native verifier strictness](#106-native-verifier-strictness)
- [11. IBC path and L2 storage profile](#11-ibc-path-and-l2-storage-profile)
  - [11.1 Supported logical path model](#111-supported-logical-path-model)
  - [11.2 Guest path derivation](#112-guest-path-derivation)
  - [11.3 Solidity storage slot](#113-solidity-storage-slot)
  - [11.4 Address/key binding](#114-addresskey-binding)
  - [11.5 Application value decoding](#115-application-value-decoding)
- [12. Membership SP1 program](#12-membership-sp1-program)
  - [12.1 Statement](#121-statement)
  - [12.2 MembershipWitness](#122-membershipwitness)
  - [12.3 Trust-anchor binding](#123-trust-anchor-binding)
  - [12.4 Guest algorithm](#124-guest-algorithm)
  - [12.5 MembershipPublicValues](#125-membershippublicvalues)
  - [12.6 Request digest](#126-request-digest)
- [13. Non-Membership SP1 program](#13-non-membership-sp1-program)
  - [13.1 Statement](#131-statement)
  - [13.2 Critical rule](#132-critical-rule)
  - [13.3 NonMembershipWitness](#133-nonmembershipwitness)
  - [13.4 Guest algorithm](#134-guest-algorithm)
  - [13.5 NonMembershipPublicValues](#135-nonmembershippublicvalues)
- [14. Destination light-client state](#14-destination-light-client-state)
  - [14.1 Core state](#141-core-state)
  - [14.2 State ownership by program](#142-state-ownership-by-program)
  - [14.3 Bootstrap](#143-bootstrap)
  - [14.4 Settlement idempotency/conflict rule](#144-settlement-idempotencyconflict-rule)
  - [14.5 Trust Update idempotency/conflict rule](#145-trust-update-idempotencyconflict-rule)
- [15. Solidity/SP1 verifier integration](#15-soliditysp1-verifier-integration)
  - [15.1 Required verifier](#151-required-verifier)
  - [15.2 Four VKeys](#152-four-vkeys)
  - [15.3 Update envelope](#153-update-envelope)
  - [15.4 Membership proof envelope](#154-membership-proof-envelope)
  - [15.5 Verification order](#155-verification-order)
- [16. Destination updateClient behavior](#16-destination-updateclient-behavior)
  - [16.1 Trust Update acceptance](#161-trust-update-acceptance)
  - [16.2 Settlement Update acceptance](#162-settlement-update-acceptance)
- [17. Membership and non-membership Solidity binding](#17-membership-and-non-membership-solidity-binding)
  - [17.1 IBC proof height mapping](#171-ibc-proof-height-mapping)
  - [17.2 verifyMembership binding](#172-verifymembership-binding)
  - [17.3 verifyNonMembership binding](#173-verifynonmembership-binding)
  - [17.4 IBC timestamp implementation gate](#174-ibc-timestamp-implementation-gate)
- [18. Off-chain proving script](#18-off-chain-proving-script)
  - [18.1 Required logical commands](#181-required-logical-commands)
  - [18.2 Trust Update Host flow](#182-trust-update-host-flow)
  - [18.3 Settlement Host flow](#183-settlement-host-flow)
  - [18.4 Membership Host flow](#184-membership-host-flow)
  - [18.5 Non-Membership Host flow](#185-non-membership-host-flow)
  - [18.6 Fail-closed RPC parsing](#186-fail-closed-rpc-parsing)
- [19. Error categories](#19-error-categories)
- [20. Test-data requirements](#20-test-data-requirements)
  - [20.1 Test-data manifest](#201-test-data-manifest)
  - [20.2 Mutation discipline](#202-mutation-discipline)
- [21. Rigorous deterministic unit tests](#21-rigorous-deterministic-unit-tests)
  - [21.1 Canonical serialization/public-value tests](#211-canonical-serializationpublic-value-tests)
  - [21.2 Hash primitive tests](#212-hash-primitive-tests)
  - [21.3 BeaconBlockHeader SSZ tests](#213-beaconblockheader-ssz-tests)
  - [21.4 SyncCommittee SSZ tests](#214-synccommittee-ssz-tests)
  - [21.5 Slot/epoch/period tests](#215-slotepochperiod-tests)
  - [21.6 Fork/domain tests](#216-forkdomain-tests)
  - [21.7 Signing-root tests](#217-signing-root-tests)
  - [21.8 Participant-bit tests](#218-participant-bit-tests)
  - [21.9 BLS tests](#219-bls-tests)
  - [21.10 SSZ Merkle branch tests](#2110-ssz-merkle-branch-tests)
  - [21.11 Finality branch tests](#2111-finality-branch-tests)
  - [21.12 Next committee branch tests](#2112-next-committee-branch-tests)
  - [21.13 Trust transition tests](#2113-trust-transition-tests)
  - [21.14 ExecutionPayloadHeader SSZ tests](#2114-executionpayloadheader-ssz-tests)
  - [21.15 Execution branch tests](#2115-execution-branch-tests)
  - [21.16 Strict RLP tests](#2116-strict-rlp-tests)
  - [21.17 Ethereum account MPT tests](#2117-ethereum-account-mpt-tests)
  - [21.18 Ethereum storage MPT tests](#2118-ethereum-storage-mpt-tests)
  - [21.19 Settlement slot derivation tests](#2119-settlement-slot-derivation-tests)
  - [21.20 Batch acceptance tests](#2120-batch-acceptance-tests)
  - [21.21 K -> R_K binding tests](#2121-k-rk-binding-tests)
  - [21.22 Native tree-key tests](#2122-native-tree-key-tests)
  - [21.23 Native leaf tests](#2123-native-leaf-tests)
  - [21.24 Native Merkle path tests](#2124-native-merkle-path-tests)
  - [21.25 IBC path tests](#2125-ibc-path-tests)
  - [21.26 IBC storage-slot tests](#2126-ibc-storage-slot-tests)
  - [21.27 Membership tests](#2127-membership-tests)
  - [21.28 Non-membership tests](#2128-non-membership-tests)
  - [21.29 Public binding tests](#2129-public-binding-tests)
- [22. SP1 execution and proof-generation tests](#22-sp1-execution-and-proof-generation-tests)
  - [22.1 Native/SP1 differential execution](#221-nativesp1-differential-execution)
  - [22.2 Guest rejection must be real](#222-guest-rejection-must-be-real)
  - [22.3 Core proof suite](#223-core-proof-suite)
  - [22.4 Groth16 EVM proof suite](#224-groth16-evm-proof-suite)
  - [22.5 Four-program VKey isolation](#225-four-program-vkey-isolation)
  - [22.6 Proof/public-value tamper tests](#226-proofpublic-value-tamper-tests)
- [23. Solidity integration and end-to-end tests](#23-solidity-integration-and-end-to-end-tests)
  - [23.1 Mock-verifier policy](#231-mock-verifier-policy)
  - [23.2 Trust Update contract tests](#232-trust-update-contract-tests)
  - [23.3 Settlement contract tests](#233-settlement-contract-tests)
  - [23.4 Membership contract tests](#234-membership-contract-tests)
  - [23.5 Non-membership contract tests](#235-non-membership-contract-tests)
  - [23.6 Local end-to-end topology](#236-local-end-to-end-topology)
  - [23.7 Positive E2E scenarios](#237-positive-e2e-scenarios)
  - [23.8 Negative E2E scenarios](#238-negative-e2e-scenarios)
  - [23.9 Historical data availability tests](#239-historical-data-availability-tests)
- [24. Implementation gates - confirmed target values and remaining deployment inputs](#24-implementation-gates-confirmed-target-values-and-remaining-deployment-inputs)
  - [24.1 Consensus profile](#241-consensus-profile)
  - [24.2 Bootstrap trust material](#242-bootstrap-trust-material)
  - [24.3 Settlement contract source/layout](#243-settlement-contract-sourcelayout)
  - [24.4 Exact batch acceptance rule](#244-exact-batch-acceptance-rule)
  - [24.5 Exact settlement data -> R_K rule](#245-exact-settlement-data-rk-rule)
  - [24.6 Exact v0.20.8 non-membership / absent-key behavior](#246-exact-v0208-non-membership-absent-key-behavior)
  - [24.7 IBC source contract and storage layout](#247-ibc-source-contract-and-storage-layout)
  - [24.8 Exact IBC value and timestamp semantics](#248-exact-ibc-value-and-timestamp-semantics)
  - [24.9 Root correspondence](#249-root-correspondence)
  - [24.10 Historical proof retention](#2410-historical-proof-retention)
  - [24.11 Destination IBC integration](#2411-destination-ibc-integration)
  - [24.12 SP1 verifier deployment](#2412-sp1-verifier-deployment)
- [25. Performance and resource gates](#25-performance-and-resource-gates)
  - [25.1 Required measurements](#251-required-measurements)
  - [25.2 No invented SLA](#252-no-invented-sla)
  - [25.3 BLS memory gate](#253-bls-memory-gate)
  - [25.4 Regression baseline](#254-regression-baseline)
- [26. Reproducible build, ELF, and VKey requirements](#26-reproducible-build-elf-and-vkey-requirements)
  - [26.1 Pinned inputs](#261-pinned-inputs)
  - [26.2 ELF reproducibility](#262-elf-reproducibility)
  - [26.3 VKey reproducibility](#263-vkey-reproducibility)
- [27. Release manifest](#27-release-manifest)
- [28. Coding-agent implementation rules](#28-coding-agent-implementation-rules)
  - [28.1 Required implementation order](#281-required-implementation-order)
  - [28.2 Required coding-agent completion report](#282-required-coding-agent-completion-report)
- [29. Final implementation acceptance checklist](#29-final-implementation-acceptance-checklist)
  - [29.1 Architecture](#291-architecture)
  - [29.2 Trust Update](#292-trust-update)
  - [29.3 Settlement Update](#293-settlement-update)
  - [29.4 Membership](#294-membership)
  - [29.5 Non-Membership](#295-non-membership)
  - [29.6 Solidity/SP1 binding](#296-soliditysp1-binding)
  - [29.7 Tests](#297-tests)
  - [29.8 Release](#298-release)
- [30. POC evidence appendix - non-normative](#30-poc-evidence-appendix-non-normative)
  - [30.1 Trust Update POC evidence](#301-trust-update-poc-evidence)
  - [30.2 Settlement POC evidence](#302-settlement-poc-evidence)
  - [30.3 Membership POC evidence](#303-membership-poc-evidence)
  - [30.4 Related non-normative reference implementation](#304-related-non-normative-reference-implementation)
- [31. Final v1.2 guarantee](#31-final-v12-guarantee)
    - [Trust Update](#trust-update)
    - [Settlement Update](#settlement-update)
    - [Membership](#membership)
    - [Non-Membership](#non-membership)

---

# 0. Normative language and implementation posture

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` use their RFC-style meanings.

- `MUST` / `MUST NOT`: required for conformance.
- `SHOULD` / `SHOULD NOT`: may be changed only through a reviewed specification revision.
- `MAY`: optional behavior that cannot weaken a `MUST` requirement.

## 0.1 Single-source rule

This file is the normative implementation source for the Prividium path.

If code, comments, old POC code, README text, copied prototype logic, deployment notes, or test fixtures conflict with this specification, implementation MUST stop with:

```text
BLOCKED_ON_SPEC
```

and report the exact conflict. A coding agent MUST NOT silently select one behavior.

## 0.2 Four-program rule

Version 1 contains exactly four top-level SP1 guest programs:

1. `trust-update`
2. `settlement-update`
3. `membership`
4. `non-membership`

The four programs MUST have separate ELFs and separate program verification keys.

There is no combined Trust Update + Settlement program.
There is no combined Settlement + Membership program.
There is no generic `proofKind` guest that dynamically switches among all statements.

Shared deterministic cryptographic libraries are required, but proof state and VKeys remain isolated.

The programs are separate proof statements, but they MAY execute sequentially as part of one higher-level settlement workflow.

If a Settlement target requires a sync committee that is not reachable from the currently stored current/next committee trust, the Host MUST first generate the required `trust-update` proof or proofs. It MUST then generate the `settlement-update` proof against the resulting trust state. The separate proof envelopes MAY be returned in one ordered composite update so a standard relayer can submit them atomically through one `updateClient(bytes)` call.

A Settlement proof MUST NOT internally perform, embed, or simulate a Trust Update.

## 0.3 Core trust boundary

The source RPC nodes, Beacon API, proof Host, relayer, JSON responses, cached committee data, and prover-supplied witnesses are not trust authorities.

The security authority is split between:

```text
SP1 guest
  -> cryptographic verification and deterministic derivation

Destination light-client contract
  -> exact VKey selection
  -> binding public values to current on-chain state
  -> binding membership requests to exact IBC arguments
  -> applying only the specified state transition
```

A Host-side pre-check MAY avoid wasting prover work, but a security-critical statement MUST be re-derived in the guest or checked by the destination contract.

## 0.4 No fuzz-testing requirement

Fuzz testing is not required by v1.

The test suite MUST instead use deterministic, named, reviewable positive, negative, malformed-input, boundary, one-field mutation, integration, and end-to-end vectors.

No acceptance item in this specification depends on a fuzz target or fuzz-coverage percentage.

## 0.5 Known-version and deployment-specificity rule

Where the target deployment version is already confirmed in this specification, the implementation MUST target that exact version and MUST NOT silently substitute a generic, latest, or approximately compatible implementation.

Confirmed target baselines in v1.2 include Lighthouse `v8.1.3-176cce5`, Reth `v1.11.3-d6324d6`, and ZKsync OS server `v0.20.8` at commit `dbb5c03d4a94ceb1acea9f79242590f354660239`.

Generic internal abstractions are allowed only when their externally observable behavior is byte-for-byte compatible with the pinned target profile. Deployment-specific values that have not yet been confirmed MUST remain explicit profile/build gates and MUST NOT be guessed from Ethereum Mainnet defaults, public fixtures, validator count, or a newer client release.

---

# 1. Scope and architecture

## 1.1 Goal

The repository implements a reusable SP1-backed light client for a Prividium / ZKsync OS source path whose state is settled on an Ethereum PoS L1 and consumed by an EVM IBC destination.

The trust chain is:

```text
                  DESTINATION EVM IBC CHAIN
                            |
                            v
                +-------------------------+
                | Prividium ZK LightClient|
                +------------+------------+
                             |
              +--------------+----------------+
              |                               |
              v                               v
      ConsensusTrustState              AcceptedBatchState
      -------------------              ------------------
      finalized Beacon slot            accepted K -> (B_end, R_K, timestamp)
      finalized Beacon root
      current committee root
      next committee root
      next-known flag
              |                               |
      +-------+-------+                       |
      |               |                       |
      v               v                       v
 TRUST UPDATE    SETTLEMENT UPDATE        MEMBERSHIP /
                                         NON-MEMBERSHIP
      |               |                       |
      |               +--> recent L1          +--> prove
      |                    authentication           application
      |                    -> K -> R_K              state under R_K
      |
      +--> finalized trust and committee advancement
```

## 1.2 Separation of responsibilities

### Trust Update

Proves a valid Ethereum Beacon light-client update and advances durable consensus trust:

```text
old trusted committee
  -> authenticate attested Beacon header by sync-committee BLS
  -> authenticate finalized checkpoint by SSZ finality branch
  -> authenticate next sync committee by SSZ branch
  -> derive new ConsensusTrustState
```

### Settlement Update

Proves a recent, consensus-authenticated L1 execution state and authenticates the Prividium batch/native root without waiting for target Beacon finality:

```text
trusted committee
  -> authenticate recent attested Beacon header by BLS
  -> authenticate ExecutionPayloadHeader by execution SSZ branch
  -> obtain authenticated L1 state root R_L1
  -> verify settlement account MPT
  -> verify settlement storage MPT
  -> authenticate batch K and settlement data
  -> derive/authenticate Prividium native root R_K
```

Settlement Update MUST NOT mutate durable finalized Beacon trust.

### Membership

Starts only from an already accepted `K -> R_K` and proves:

```text
State(R_K, IBC_STORE, P) = V
```

### Non-Membership

Starts only from an already accepted `K -> R_K` and proves the configured application-level absence statement for logical path `P` under `R_K`.

## 1.3 In scope

- Ethereum Beacon `BeaconBlockHeader` SSZ hashing.
- Ethereum `SyncCommittee` SSZ hashing using the `SYNC_COMMITTEE_SIZE` pinned by the source-network consensus preset, including every ordered committee pubkey position and the aggregate pubkey.
- slot -> epoch -> sync-committee-period arithmetic.
- fork selection and sync-committee domain derivation.
- Ethereum sync-committee signing-root derivation.
- participant selection from the `SYNC_COMMITTEE_SIZE`-bit participation bitvector.
- BLS12-381 Ethereum sync-committee FastAggregateVerify-equivalent verification in SP1.
- strict SSZ Merkle branch verification.
- finality branch verification.
- next-sync-committee branch verification.
- trust-state binding and committee rotation.
- recent optimistic Beacon header authentication for Settlement.
- fork-correct execution payload header SSZ hashing.
- execution branch verification.
- Ethereum account/storage MPT verification on the settlement L1.
- pinned settlement storage-slot derivation for batch `K`.
- pinned batch-acceptance semantics.
- pinned settlement-state -> native-root `R_K` derivation.
- ZKsync OS native proof parsing and verification.
- exact logical IBC path -> application storage slot derivation.
- membership value authentication.
- non-membership according to a pinned absence profile.
- SP1 execute, core prove, Groth16 EVM prove, local verify, and Solidity verifier integration.
- deterministic negative and malformed-input testing.
- reproducible ELF/VKey generation.

## 1.4 Out of scope for v1

- re-executing Casper FFG from all Beacon attestations.
- re-executing LMD-GHOST.
- trusting a Host-supplied Beacon finality flag.
- trusting a Host-supplied BLS domain or signing root.
- using L2 `eth_getProof` for Prividium native state.
- using Ethereum MPT verification for `zks_getProof` native proofs.
- recursive composition of the four SP1 programs.
- a REST/gRPC proof service, database, persistent job queue, scheduler, or distributed worker system.
- general arbitrary Solidity-storage proofs unrelated to the configured IBC state profile.
- fuzz-testing requirements.
- private deployment credentials or organization-specific configuration in source control.

---

# 2. Pinned external baselines

## 2.1 Required release pins

Every tagged release MUST pin exact immutable versions for:

- Rust toolchain.
- SP1 SDK/toolchain.
- matching `sp1-contracts` verifier release.
- `lfdt-ibc/ibc-contracts` release/commit used by the destination integration.
- Ethereum consensus-spec reference commit used for SSZ/light-client rules.
- BLS library/crate and exact version.
- RLP/Keccak/SHA-256/BLAKE2s dependencies.
- ZKsync OS source release and commit used for native-tree compatibility.
- Solidity compiler.
- Foundry version.

The POC workspace used the SP1 6.7 toolchain family. The implementation MUST inspect the actual repository `Cargo.lock` and pin the exact SP1 patch versions used by the production workspace. Do not guess or silently upgrade them.

## 2.2 Confirmed target deployment baselines

The current target profile has the following confirmed implementation baselines:

```text
L1 consensus client: Lighthouse v8.1.3-176cce5
L1 execution client: Reth v1.11.3-d6324d6
L1 active validator count: 1
ZKsync OS server: v0.20.8
ZKsync OS source commit: dbb5c03d4a94ceb1acea9f79242590f354660239
transaction policy: gasless / zero-fee
```

These values are not placeholders. E2E and live-compatibility testing for the current target profile MUST use these versions unless an explicit upgrade is being tested and recorded.

The active validator count is an operational fact only. It MUST NOT be used to infer `SYNC_COMMITTEE_SIZE`. The sync-committee size, fork schedule, genesis values, and other consensus-preset constants must come from the private Beacon-chain consensus configuration.

## 2.3 ZKsync OS reference profile

The currently validated native-proof algorithm is based on:

```text
ZKsync OS server version: v0.20.8
Pinned source commit: dbb5c03d4a94ceb1acea9f79242590f354660239
```

A different server version or commit MUST NOT reuse v0.20.8 proof rules without running the full native-proof conformance suite and updating the release profile.

## 2.4 Prototype code reuse rule

Prototype repositories MAY be used for architecture patterns, fixtures, or cross-checks, but consensus verification code MUST NOT be imported wholesale unless each file is independently reviewed for:

- SP1 version compatibility.
- fork correctness.
- host-vs-guest trust assumptions.
- checked BLS point decoding.
- subgroup/identity rejection.
- fixed bitvector and committee lengths.
- exact Ethereum SSZ root semantics.
- generalized-index correctness.
- integer slot width (`u64`).
- license/provenance compatibility.

Known prototype anti-patterns that MUST NOT be copied include:

- Host-supplied BLS domain treated as trusted.
- unchecked G1/G2 decoding.
- `unwrap` on hostile witness data.
- `zip`-based participant selection that can silently truncate length mismatches.
- ad-hoc committee commitments that are not the canonical Ethereum `SyncCommittee` SSZ root.
- `u32` Beacon slots.
- hard-coded generalized indices copied across forks without schema validation.

---

# 3. Source profile and deployment-independence

## 3.1 No organization-specific data in the repository

The repository MUST NOT contain:

- private RPC URLs.
- API keys.
- bearer tokens.
- private keys.
- organization names in program identifiers.
- private deployment labels.

The project MAY contain generic example profiles and synthetic addresses.

## 3.2 Profile-bound build

Every production set of ELFs/VKeys MUST be built against one reviewed `SourceProfileV1`.

The profile contains public, security-critical source configuration. It is not a runtime Host assertion.

A build script MUST canonicalize the profile and derive:

```text
SOURCE_PROFILE_ID = Keccak256(canonical SourceProfileV1 bytes)
```

The generated `SOURCE_PROFILE_ID` MUST be compiled into all four guest programs and configured immutably in the destination light client.

Changing any security-critical profile field requires new ELFs, new VKeys, and a new deployment/migration process.

## 3.3 SourceProfileV1 logical fields

The exact machine-readable representation MAY be JSON or TOML, but the canonical hashing format MUST be fixed and tested.

At minimum the profile MUST contain:

```text
profileSchemaVersion
profileName                 // generic public label only

consensus:
    genesisValidatorsRoot
    genesisTime
    secondsPerSlot
    slotsPerEpoch
    epochsPerSyncCommitteePeriod
    syncCommitteeSize
    forkSchedule[]:
        forkId
        activationEpoch
        forkVersion[4]
    supportedLightClientHeaderSchemas[]
    supportedExecutionPayloadHeaderSchemas[]
    forkSpecificFinalityGindices[]
    forkSpecificNextCommitteeGindices[]
    forkSpecificExecutionGindices[]

settlement:
    diamondProxyAddress
    diamondSourceCommit
    settlementStorageProfileId
    acceptedLifecycleRuleId
    nativeRootBindingRuleId

prividiumL2:
    chainId
    zksyncOsVersion
    zksyncOsCommit
    nativeTreeProfileId
    ibcStoreAddress
    ibcStorageProfileId
    absenceProfileId

ibc:
    ibcContractsCommit
    supportedPathShapeId
```

Generalized indices MUST be derived/reviewed from the pinned Ethereum consensus schema. The Host MUST NOT provide a generalized index as authoritative witness data.

## 3.4 Runtime-only values

The following are runtime values and MUST NOT be compiled into guests:

- Beacon API URL.
- L1 execution JSON-RPC URL.
- Prividium L2 RPC URL.
- destination RPC URL.
- credentials/tokens.
- target L2 block `B`.
- candidate batch `K`.
- current on-chain trust state.
- proof request path/value.

## 3.5 Gasless network operation

The supported target deployment profile operates with gasless / zero-fee transaction submission. This is an operational transaction-policy property, not a cryptographic trust assumption.

Deployment, relayer, proving-workflow, and end-to-end tooling MUST support the configured zero-fee transaction policy for state-changing destination transactions. Tooling MUST NOT assume that a positive gas price or transaction fee is required for correctness.

Gas-cost regression snapshots are not a conformance requirement for this profile.

Canonical Ethereum execution-payload fields such as `gas_limit`, `gas_used`, `base_fee_per_gas`, `blob_gas_used`, and `excess_blob_gas` MUST still be parsed, SSZ-hashed, and authenticated exactly according to the active consensus fork. Gasless transaction submission MUST NOT be used to omit or rewrite consensus fields.

---

# 4. Repository and module structure

The implementation SHOULD use the following logical structure. Minor naming changes are allowed only if dependency boundaries remain equivalent.

```text
prividium-ibc-zk/
|
|-- README.md
|-- docs/spec.md
|-- LICENSE
|-- Cargo.toml
|-- Cargo.lock
|-- rust-toolchain.toml
|-- justfile
|-- .env.example
|-- .gitignore
|
|-- profiles/
|   |-- schema/source-profile-v1.schema.json
|   `-- examples/
|       `-- local-dev.json
|
|-- crates/
|   |-- types/
|   |   `-- src/
|   |       |-- consensus.rs
|   |       |-- light_client.rs
|   |       |-- settlement.rs
|   |       |-- membership.rs
|   |       |-- non_membership.rs
|   |       |-- zksync_proof.rs
|   |       |-- public_values.rs
|   |       `-- error.rs
|   |
|   |-- ssz/
|   |   `-- src/
|   |       |-- basic.rs
|   |       |-- merkleize.rs
|   |       |-- beacon_header.rs
|   |       |-- sync_committee.rs
|   |       |-- execution_payload_header.rs
|   |       |-- signing_data.rs
|   |       `-- branch.rs
|   |
|   |-- beacon-light-client/
|   |   `-- src/
|   |       |-- period.rs
|   |       |-- fork.rs
|   |       |-- domain.rs
|   |       |-- participants.rs
|   |       |-- finality.rs
|   |       |-- next_committee.rs
|   |       |-- transition.rs
|   |       `-- trust_digest.rs
|   |
|   |-- bls/
|   |   `-- src/
|   |       |-- decode.rs
|   |       |-- hash_to_curve.rs
|   |       |-- aggregate.rs
|   |       `-- verify.rs
|   |
|   |-- evm-mpt/
|   |   `-- src/
|   |       |-- rlp.rs
|   |       |-- nibble.rs
|   |       |-- hex_prefix.rs
|   |       |-- node.rs
|   |       |-- proof.rs
|   |       |-- account.rs
|   |       `-- storage.rs
|   |
|   |-- settlement-profile/
|   |   `-- src/
|   |       |-- slot.rs
|   |       |-- acceptance.rs
|   |       `-- native_root_binding.rs
|   |
|   |-- zksync-native/
|   |   `-- src/
|   |       |-- tree_key.rs
|   |       |-- leaf.rs
|   |       |-- empty.rs
|   |       |-- path.rs
|   |       `-- proof.rs
|   |
|   |-- ibc-storage/
|   |   `-- src/
|   |       |-- path.rs
|   |       |-- slot.rs
|   |       |-- value.rs
|   |       `-- absence.rs
|   |
|   `-- public-values/
|       `-- src/
|           |-- codec.rs
|           `-- digest.rs
|
|-- programs/
|   |-- trust-update/
|   |   `-- src/main.rs
|   |-- settlement-update/
|   |   `-- src/main.rs
|   |-- membership/
|   |   `-- src/main.rs
|   `-- non-membership/
|       `-- src/main.rs
|
|-- tooling/
|   `-- proof-api/
|       `-- src/
|           |-- main.rs
|           |-- server.rs
|           |-- engine.rs
|           |-- rpc.rs
|           |-- bootstrap.rs
|           |-- destination.rs
|           |-- backend.rs
|           `-- artifact.rs
|
|-- contracts/
|   |-- foundry.toml
|   |-- remappings.txt
|   |-- src/
|   |   |-- PrividiumZKLightClient.sol
|   |   |-- PrividiumZKTypes.sol
|   |   `-- PublicValuesCodec.sol
|   |-- test/
|   |   |-- PrividiumZKLightClient.t.sol
|   |   |-- SP1VerifierIntegration.t.sol
|   |   `-- mocks/MockSP1Verifier.sol
|   `-- script/DeployLightClient.s.sol
|
|-- test-data/
|   |-- consensus/
|   |   |-- official/
|   |   |-- synthetic/
|   |   `-- malformed/
|   |-- settlement/
|   |   |-- account-mpt/
|   |   |-- storage-mpt/
|   |   `-- binding/
|   |-- zksync-native/
|   |-- ibc/
|   |-- public-values/
|   `-- live-compat/
|
|-- e2e/
|   |-- docker-compose.yml
|   |-- source-pos/
|   |-- source-prividium/
|   |-- destination-evm/
|   `-- tests/
|
|-- scripts/
|   |-- build-sp1.sh
|   |-- generate-source-profile.sh
|   |-- generate-vkeys.sh
|   |-- check-vkeys.sh
|   |-- check-reproducible-build.sh
|   |-- collect-beacon-test-data.sh
|   |-- collect-l1-proof-test-data.sh
|   |-- collect-zksync-proof-test-data.sh
|   |-- verify-settlement-layout.sh
|   |-- verify-ibc-storage-layout.sh
|   `-- run-e2e.sh
|
|-- release/
|   |-- expected-vkeys.json
|   |-- manifest.json
|   `-- performance-baseline.json
|
`-- docs/
    |-- DEVELOPMENT.md
    |-- TESTING.md
    |-- DEPLOYMENT.md
    |-- SECURITY.md
    `-- RELEASE.md
```

## 4.1 Dependency direction

```text
programs/trust-update
    -> types, ssz, beacon-light-client, bls, public-values

programs/settlement-update
    -> types, ssz, beacon-light-client, bls, evm-mpt,
       settlement-profile, public-values

programs/membership
    -> types, zksync-native, ibc-storage, public-values

programs/non-membership
    -> types, zksync-native, ibc-storage, public-values

tooling/proof-api
    -> RPC/network/protobuf crates
    -> local witness builders and embedded reviewed ELFs
    -> authenticated SP1 network gateway

shared deterministic crates
    -> MUST NOT depend on HTTP/RPC/network crates
```

Guest entrypoints MUST remain thin. Security logic belongs in deterministic shared crates that can run in native tests and unchanged inside SP1.

---

# 5. Canonical encoding and primitive types

## 5.1 General rules

- `bytes32` -> `[u8; 32]`.
- EVM address -> `[u8; 20]`.
- compressed BLS G1 pubkey -> `[u8; 48]`.
- compressed BLS G2 signature -> `[u8; 96]`.
- sync committee bits -> exactly `ceil(SYNC_COMMITTEE_SIZE / 8)` bytes, with any unused high bits in the final byte required to be zero.
- Beacon slot/epoch/period quantities -> `u64`.
- ZKsync L1 batch `K` -> `u64`.
- ZKsync native leaf/index values defined as 64-bit MUST use `u64`.
- fixed protocol-length values MUST NOT use unconstrained `Vec<u8>` in canonical typed witnesses.
- variable-length protocol fields MUST have explicit maximums and checked lengths before allocation/use.
- all arithmetic affecting lengths, generalized indices, slot derivation, offsets, or proof traversal MUST use checked arithmetic.

## 5.2 Guest stdin

Private witness transport MUST use the exact serializer supported by the pinned SP1 workspace:

```rust
let mut stdin = SP1Stdin::new();
stdin.write(&witness);
```

and inside the guest:

```rust
let witness: Witness = sp1_zkvm::io::read();
```

Do not introduce a second ad-hoc serializer for guest stdin.

## 5.3 Public values

Public values MUST use Solidity ABI encoding and MUST be committed as raw ABI bytes.

Conceptually:

```rust
let encoded = PublicValues::abi_encode(&public_values);
sp1_zkvm::io::commit_slice(&encoded);
```

Every public-values struct starts with:

```text
schemaVersion = 1
programVersion = circuit-specific version
sourceProfileId = SOURCE_PROFILE_ID
```

Rust and Solidity MUST have byte-for-byte golden vectors for every public-values structure.

---

# 6. Canonical consensus types

## 6.1 ConsensusTrustState

```rust
pub struct ConsensusTrustState {
    pub finalized_beacon_slot: u64,
    pub finalized_beacon_header_root: [u8; 32],
    pub current_sync_committee_root: [u8; 32],
    pub next_sync_committee_root: [u8; 32],
    pub next_sync_committee_known: bool,
}
```

If `next_sync_committee_known == false`, v1 requires:

```text
next_sync_committee_root == 0x00..00
```

## 6.2 BeaconBlockHeader

```rust
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}
```

`hash_tree_root(BeaconBlockHeader)` MUST follow canonical SSZ.

## 6.3 SyncCommittee

`SYNC_COMMITTEE_SIZE` is a build-time constant generated from the reviewed `SourceProfileV1.consensus.syncCommitteeSize`. It is not derived from the active validator count.

Conceptually:

```rust
pub const SYNC_COMMITTEE_SIZE: usize = SOURCE_PROFILE_SYNC_COMMITTEE_SIZE;
pub const SYNC_COMMITTEE_BITS_BYTES: usize =
    (SYNC_COMMITTEE_SIZE + 7) / 8;

pub struct SyncCommittee {
    pub pubkeys: [[u8; 48]; SYNC_COMMITTEE_SIZE],
    pub aggregate_pubkey: [u8; 48],
}
```

The guest MUST preserve all `SYNC_COMMITTEE_SIZE` ordered committee positions when computing the canonical SSZ root. The aggregate pubkey is part of the SSZ object and MUST be included in its root.

For the current private target deployment, the active validator count is known to be `1`, but the private network's `SYNC_COMMITTEE_SIZE` has not yet been confirmed. The implementation MUST NOT substitute `1` or Ethereum Mainnet's `512` until the authoritative private consensus preset is captured.

## 6.4 SyncAggregate

Conceptually:

```rust
pub struct SyncAggregate {
    pub sync_committee_bits: [u8; SYNC_COMMITTEE_BITS_BYTES],
    pub sync_committee_signature: [u8; 96],
}
```

The serialized participation bitvector MUST contain exactly `SYNC_COMMITTEE_SIZE` bits. If `SYNC_COMMITTEE_SIZE` is not byte-aligned, unused high bits in the last byte MUST be zero.

## 6.5 Light-client header

The logical header is:

```rust
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ForkExecutionPayloadHeader,
    pub execution_branch: Vec<[u8; 32]>,
}
```

`ForkExecutionPayloadHeader` MUST be an explicit enum/typed variant for every source fork supported by the release profile. Unknown or future schemas MUST be rejected.

The Host MUST NOT supply a free-form list of execution fields.

## 6.6 Execution payload header

The `ExecutionPayloadHeader` MUST use the exact SSZ schema applicable to the active consensus fork selected from the pinned source profile. The Host MUST NOT relabel a response as an older fork merely because the execution-header fields happen to be identical.

The captured Lighthouse compatibility fixture used during specification work reports top-level `version = fulu`. This is a compatibility fixture, not proof that the private target network is currently running Fulu. For Fulu operation, the implementation MUST dispatch using the Fulu fork profile and the exact schema/gindices inherited or defined by the pinned Ethereum consensus specification. If the canonical Fulu execution-header schema is byte-for-byte identical to an earlier supported schema, the implementation MAY reuse the same internal Rust structure, but the fork selection and reviewed schema mapping MUST remain explicit.

The captured Fulu response contains the following execution-header fields:

```text
parent_hash
fee_recipient
state_root
receipts_root
logs_bloom
prev_randao
block_number
gas_limit
gas_used
timestamp
extra_data
base_fee_per_gas
block_hash
transactions_root
withdrawals_root
blob_gas_used
excess_blob_gas
```

`extra_data` MUST obey its SSZ maximum length.

Every supported fork MUST have a reviewed fork-to-schema mapping and golden vectors. Any additional or changed field required by a supported fork MUST be represented by the exact fork-correct type. Unknown or future schemas MUST be rejected; the implementation MUST NOT append unknown fields dynamically.

---

# 7. Shared Ethereum consensus verification

This section is shared by Trust Update and Settlement Update.

## 7.1 Slot, epoch, and sync-committee period

Using profile constants:

```text
epoch(slot) = floor(slot / SLOTS_PER_EPOCH)

syncCommitteePeriod(slot) =
    floor(epoch(slot) / EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
```

No floating-point arithmetic is allowed.

All inputs/outputs are `u64` and boundary arithmetic MUST be checked.

## 7.2 Signing committee reachability

Given stored trust:

```text
trustedPeriod = syncCommitteePeriod(previousTrust.finalizedBeaconSlot)
signaturePeriod = syncCommitteePeriod(signatureSlot)
```

Selection rule:

```text
if signaturePeriod == trustedPeriod:
    expectedCommitteeRoot = currentSyncCommitteeRoot

else if signaturePeriod == trustedPeriod + 1
        and nextSyncCommitteeKnown:
    expectedCommitteeRoot = nextSyncCommitteeRoot

else:
    reject / Trust Update required before Settlement can continue
```

The Host MAY select a candidate committee for witness construction, but the guest MUST independently derive the expected period/root.

## 7.3 Authenticate full committee witness

Before any public key is used:

```text
computedCommitteeRoot = hash_tree_root(fullSyncCommittee)
require computedCommitteeRoot == expectedCommitteeRoot
```

The guest MUST verify exact committee length and fixed pubkey widths.

## 7.4 Participant selection

Let:

```text
N = SourceProfileV1.consensus.syncCommitteeSize
bitvectorBytes = ceil(N / 8)
```

The guest MUST:

1. require exactly `bitvectorBytes` bytes;
2. require unused high bits in the final byte to be zero when `N` is not byte-aligned;
3. interpret the first `N` bits using the Ethereum consensus bit ordering;
4. select the pubkey at the exact committee position for every set bit;
5. reject zero active participants;
6. never silently truncate bits or pubkeys;
7. require the full committee witness to contain exactly `N` ordered pubkeys;
8. derive participant count in the guest.

## 7.5 Fork version and sync-committee domain

The guest derives the fork applicable to the signature slot using the Ethereum light-client signature-slot lookback:

```text
forkVersionSlot = max(signatureSlot, 1) - 1
forkEpoch = epoch(forkVersionSlot)
forkVersion = configuredForkVersionAt(forkEpoch)
```

Then:

```text
forkDataRoot = hash_tree_root(ForkData {
    current_version: forkVersion,
    genesis_validators_root: GENESIS_VALIDATORS_ROOT
})

domain = DOMAIN_SYNC_COMMITTEE || forkDataRoot[0..28]
```

The Host MUST NOT supply `domain` as an authoritative value.

## 7.6 Signing root

```text
objectRoot = hash_tree_root(attested_header.beacon)

signingRoot = hash_tree_root(SigningData {
    object_root: objectRoot,
    domain: domain,
})
```

The guest derives both values.

## 7.7 BLS verification

Use the Ethereum consensus minimal-public-key BLS12-381 convention:

- compressed pubkeys are G1 points, 48 bytes;
- aggregate signature is a compressed G2 point, 96 bytes;
- the signing root is hashed to G2 using the pinned Ethereum POP ciphersuite/domain separation rules;
- selected participant pubkeys are aggregated in G1;
- the aggregate signature is verified by the equivalent of Ethereum `FastAggregateVerify`.

At minimum the implementation MUST enforce:

- exact compressed lengths;
- canonical compressed decoding;
- on-curve validation;
- subgroup validation;
- rejection of invalid/infinity points where the Ethereum ciphersuite requires it;
- no unchecked constructors on untrusted witness bytes;
- no ignored decode errors;
- no host-provided aggregate key accepted without recomputation from selected participant keys.

Conceptually:

```text
PK_agg = sum_G1(participantPubkeys)
H = hash_to_G2(signingRoot, pinned Ethereum BLS POP DST)
sigma = checked_decode_G2(signature)
require pairing(PK_agg, H) == pairing(G1_GENERATOR, sigma)
```

If the chosen BLS library exposes a hardened `FastAggregateVerify` implementation compatible with Ethereum, it SHOULD be preferred to hand-rolled verification after conformance vectors pass.

## 7.8 Generic SSZ branch verification

The shared branch verifier accepts:

```text
leaf [32]
branch[] of [32]
gindex
expectedRoot [32]
```

It MUST:

- reject zero/invalid generalized indices;
- require branch length to equal the depth implied by the pinned location;
- use checked shifts/index arithmetic;
- apply SHA-256 in exact left/right order;
- require final reconstructed root equality;
- reject extra branch nodes and truncated branches.

Security-critical gindices are fork/profile constants, not untrusted witness inputs.

---

# 8. Trust Update SP1 program

## 8.1 Statement

The Trust Update program proves:

> Starting from the exact consensus trust state already stored by the destination light client, a valid Ethereum sync-committee update authenticates an attested Beacon header; the authenticated BeaconState commits to the supplied finalized Beacon header and supplied next sync committee; the resulting state transition is fork/period-correct; therefore the new compact consensus trust state may replace the old one.

## 8.2 TrustUpdateWitness

Logical witness:

```rust
pub struct TrustUpdateWitness {
    pub schema_version: u32,
    pub previous_trust: ConsensusTrustState,
    pub full_signing_sync_committee: SyncCommittee,
    pub update: LightClientUpdateWitness,
}

pub struct LightClientUpdateWitness {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vec<[u8; 32]>,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<[u8; 32]>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}
```

If the pinned Lighthouse schema includes additional proof-relevant fields, add them explicitly to the fork-specific type. Do not pass raw JSON into the guest.

## 8.3 Previous trust digest

The exact digest is:

```text
previousConsensusTrustDigest =
    Keccak256(
        abi.encode(
            finalizedBeaconSlot,
            finalizedBeaconHeaderRoot,
            currentSyncCommitteeRoot,
            nextSyncCommitteeRoot,
            nextSyncCommitteeKnown
        )
    )
```

Field order is normative.

## 8.4 Slot ordering

The guest MUST require:

```text
signatureSlot > attestedSlot
attestedSlot >= finalizedSlot
```

and MUST require the finalized state not move backward:

```text
finalizedSlot >= previousTrust.finalizedBeaconSlot
```

If the finalized slot is equal to the previous slot:

```text
newFinalizedBeaconHeaderRoot == previousTrust.finalizedBeaconHeaderRoot
```

## 8.5 Authenticate attested Beacon header

The guest MUST apply Sections 7.1-7.7 and authenticate `attested_header.beacon` with the correct stored current/next sync committee.

No later branch is trusted until this BLS check succeeds.

## 8.6 Finality branch

Compute:

```text
newFinalizedRoot = hash_tree_root(finalized_header.beacon)
```

Verify `newFinalizedRoot` at the fork-correct `BeaconState.finalized_checkpoint.root` generalized index against:

```text
attested_header.beacon.state_root
```

A successful branch proves the supplied finalized header corresponds to the finalized checkpoint committed by the authenticated BeaconState.

## 8.7 Next sync committee branch

Compute:

```text
newNextRoot = hash_tree_root(next_sync_committee)
```

Verify `newNextRoot` at the fork-correct `BeaconState.next_sync_committee` generalized index against the same authenticated:

```text
attested_header.beacon.state_root
```

The guest MUST NOT trust the next committee merely because the Beacon API supplied it.

## 8.8 State transition

The guest MUST derive the transition from old/new periods and authenticated roots.

It MUST NOT accept Host-selected output committee roots.

At minimum it MUST correctly handle:

- no period transition;
- exact transition into the next known period;
- acquisition of the subsequent next committee;
- `nextSyncCommitteeKnown == false` bootstrap/update behavior;
- rejection of a signature period more than one period beyond currently reachable trust;
- no finalized-slot regression;
- same-finalized-slot root consistency.

The exact transition MUST match the pinned Ethereum light-client specification for the supported fork(s).

## 8.9 TrustUpdatePublicValues

```rust
pub struct TrustUpdatePublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: [u8; 32],
    pub previous_consensus_trust_digest: [u8; 32],
    pub last_signature_slot: u64,
    pub new_finalized_beacon_slot: u64,
    pub new_finalized_beacon_header_root: [u8; 32],
    pub new_current_sync_committee_root: [u8; 32],
    pub new_next_sync_committee_root: [u8; 32],
    pub new_next_sync_committee_known: bool,
}
```

No full committee array is public.

## 8.10 Guest algorithm

The guest MUST execute in this order:

1. Read and structurally validate `TrustUpdateWitness`.
2. Require schema/profile/program versions.
3. Validate `previous_trust` representation.
4. Compute `previousConsensusTrustDigest`.
5. Read `signatureSlot`, `attestedSlot`, `finalizedSlot`.
6. Enforce slot ordering.
7. Derive trusted/signature periods.
8. Select expected committee root.
9. SSZ-hash the full signing committee.
10. Require committee root equality.
11. Validate/decode participation bits.
12. Select participant pubkeys.
13. Derive fork version/domain from `signatureSlot`.
14. SSZ-hash `attested_header.beacon`.
15. Derive the signing root.
16. Verify aggregate BLS signature.
17. Compute finalized Beacon header root.
18. Verify finality branch against authenticated Beacon state root.
19. Enforce finalized monotonicity and same-slot root consistency.
20. SSZ-hash supplied next sync committee.
21. Verify next committee branch against authenticated Beacon state root.
22. Apply fork-correct period/committee transition.
23. Construct `TrustUpdatePublicValues` only from verified/derived values.
24. ABI-encode and commit public values.

---

# 9. Settlement Update SP1 program

## 9.1 Statement

The Settlement Update program proves:

> Starting from the exact consensus trust state stored by the destination light client, the reachable trusted sync committee authenticated a recent Beacon header; the header commits to the supplied execution payload header; the authenticated execution state root commits to the configured settlement contract account and exact batch-specific storage values; those values satisfy the configured accepted lifecycle rule and cryptographically bind batch K to the Prividium native root R_K.

The Settlement Update does not claim that the recent target header is Beacon-finalized.

## 9.2 No target-finality rule

The program MUST NOT require a target `finality_branch` for the normal Settlement path.

The authenticated recent attested header MUST NOT overwrite:

```text
finalizedBeaconSlot
finalizedBeaconHeaderRoot
currentSyncCommitteeRoot
nextSyncCommitteeRoot
nextSyncCommitteeKnown
```

## 9.3 SettlementWitness

Logical witness:

```rust
pub struct SettlementWitness {
    pub schema_version: u32,
    pub previous_trust: ConsensusTrustState,

    pub full_signing_sync_committee: SyncCommittee,
    pub optimistic_update: OptimisticUpdateWitness,

    pub prividium_native_root: [u8; 32],
    pub settlement_account_proof: Vec<Vec<u8>>,
    pub stored_batch_hash_proof: EvmStorageProofWitness,
    pub total_batches_executed_proof: EvmStorageProofWitness,
    pub state_commitment_preimage: StateCommitmentPreimage,
    pub l1_verification_data: L1VerificationData, // contains candidate K
}

pub struct OptimisticUpdateWitness {
    pub attested_header: LightClientHeader,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}
```

The configured settlement account address and slot formulas come from `SourceProfileV1`, not from arbitrary Host witness values.

## 9.4 Authenticate recent Beacon header

The guest MUST reuse the same reviewed implementations from Sections 7.1-7.7.

The Settlement program MUST NOT contain a second independent copy of BLS/domain/committee logic.

Before using the attested header, the guest MUST compare it with the finalized
checkpoint in `previous_trust`:

```text
attestedSlot < previousTrust.finalizedBeaconSlot
    -> reject

attestedSlot == previousTrust.finalizedBeaconSlot
and attestedRoot != previousTrust.finalizedBeaconHeaderRoot
    -> reject
```

An attested header that exactly matches the trusted finalized slot and root MAY
reuse that trust without another sync-committee signature. A newer attested
header MUST carry a valid signature from a committee reachable from
`previous_trust`. This rule preserves optimistic Settlement while preventing a
stale or conflicting header from contradicting an already finalized
checkpoint.

## 9.5 Execution payload root

The guest computes:

```text
executionRoot = hash_tree_root(attested_header.execution)
```

using the fork-correct `ExecutionPayloadHeader` SSZ schema.

## 9.6 Execution branch

The guest verifies `attested_header.execution_branch` at the fork-correct `BeaconBlockBody.execution_payload` generalized index against:

```text
attested_header.beacon.body_root
```

Only after this succeeds may the guest use:

```text
N_L1 = execution.block_number
B_L1 = execution.block_hash
R_L1 = execution.state_root
```

## 9.7 Ethereum account MPT

The settlement account secure trie key is:

```text
accountTrieKey = Keccak256(raw 20-byte settlement account address)
```

Do not hash textual `0x...` ASCII.

The account proof is verified under authenticated `R_L1`.

The account leaf MUST decode canonically as exactly:

```text
[nonce, balance, storageRoot, codeHash]
```

The guest extracts authenticated `storageRoot`.

An absent settlement account is invalid.

## 9.8 Strict RLP/MPT requirements

The shared Ethereum MPT verifier MUST support:

- branch node, list length 17;
- extension/leaf node, list length 2;
- canonical hex-prefix compact paths;
- hashed children;
- inline children;
- exact root hash verification;
- exact secure trie-key nibble traversal.

It MUST reject:

- malformed/non-canonical RLP;
- invalid length-of-length;
- leading-zero RLP integer encodings where forbidden;
- invalid hex-prefix flags/padding;
- missing referenced nodes;
- child references longer than protocol-allowed form;
- hash mismatch;
- wrong path;
- truncated proof;
- duplicate supplied node hash mapped to different bytes;
- parser failure treated as absence.

## 9.9 Settlement storage keys

For every required storage field, the guest MUST derive the logical slot from:

```text
K
+ pinned settlement storage profile
+ mapping base slot(s)
+ struct offsets / nested mapping rules
```

The Host may calculate the same slots to issue `eth_getProof`, but the guest independently re-derives them.

For a Solidity mapping, only when confirmed by the authoritative layout:

```text
mappingSlot = Keccak256(ABIEncode32(K) || ABIEncode32(baseSlot))
```

For a struct field:

```text
fieldSlot = mappingSlot + checkedFieldOffset
```

The exact production slot set is an implementation gate in Section 24.

## 9.10 Storage MPT verification

For each logical slot:

```text
storageTrieKey = Keccak256(ABIEncode32(logicalSlot))
```

The guest verifies the storage proof under the authenticated settlement-account `storageRoot`.

The returned RLP storage value is decoded canonically to the exact configured field width/type.

## 9.11 Batch acceptance

The guest MUST authenticate the exact lifecycle field(s) for `K` and require the configured accepted state.

Examples such as `committed`, `proved`, or `executed` MUST NOT be chosen by guesswork.

The accepted rule is defined by `acceptedLifecycleRuleId` and the authoritative settlement profile.

For `zksync-v30.2-executed-batch-v1`, the guest MUST authenticate both of the
following values from the settlement account storage root committed by the
same execution payload:

1. `storedBatchHashes[K]`, which MUST equal the recomputed `StoredBatchInfo`
   hash for batch `K`; and
2. `totalBatchesExecuted`, which MUST satisfy `K <= totalBatchesExecuted`.

The host MAY check the batch execution stage before proving, but that check
does not replace either guest constraint.

## 9.12 K -> R_K binding

The guest MUST derive/authenticate `R_K` from the authenticated settlement values using the exact pinned rule.

The Host MUST NOT provide an arbitrary `R_K` that is merely copied to public output.

The final dependency must be:

```text
BLS-authenticated Beacon header
  -> authenticated ExecutionPayloadHeader
  -> authenticated R_L1
  -> authenticated settlement account storageRoot
  -> authenticated K-specific settlement fields
  -> exact pinned binding rule
  -> R_K
```

## 9.13 SettlementPublicValues

```rust
pub struct SettlementPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: [u8; 32],
    pub previous_consensus_trust_digest: [u8; 32],
    pub l2_block_number: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: [u8; 32],
    pub l2_batch_timestamp: u64,
}
```

`signature_slot` remains an authenticated witness input used by Settlement
verification, but it is not part of the committed Settlement public-value ABI.
`l2_batch_timestamp` is derived from the authenticated ZKsync state
commitment and is returned by Membership and Non-Membership for IBC timeout
handling.

`l2_block_number` is the batch-end block authenticated by the ZKsync state
commitment. Together with `l1_batch_number`, it binds the relayer's L2 event
height to the accepted batch state. The candidate batch `K` is read once from
`l1_verification_data.batch_number`; there is no duplicate witness field for
it.

## 9.14 Guest algorithm

1. Read/validate `SettlementWitness`.
2. Require schema/profile/program versions.
3. Compute previous trust digest.
4. Derive committee reachability from stored trust and `signature_slot`.
5. SSZ-hash full signing committee and bind to expected root.
6. Decode bits and select participant keys.
7. Derive fork/domain/signing root.
8. Verify BLS aggregate signature over attested Beacon header.
9. SSZ-hash the fork-correct execution payload header.
10. Verify execution branch against authenticated Beacon `body_root`.
11. Extract authenticated `N_L1`, `B_L1`, `R_L1`.
12. Derive settlement account secure trie key.
13. Verify account MPT under `R_L1`.
14. Extract settlement account `storageRoot`.
15. Derive exact `K`-specific logical storage slots.
16. Require returned proof keys match the guest-derived slots where represented.
17. Verify all required storage MPT proofs.
18. Decode authenticated lifecycle/settlement values.
19. Require configured batch-acceptance predicate.
20. Derive/authenticate `R_K` using the pinned binding rule.
21. Construct `SettlementPublicValues`.
22. ABI-encode and commit.

---

# 10. ZKsync OS native storage proof

This section is shared by Membership and Non-Membership.

## 10.1 RPC model

The native storage proof is requested conceptually as:

```text
zks_getProof(
    IBC_STORE_ADDRESS,
    [solidityStorageSlot],
    K
)
```

`K` is the ZKsync L1 batch number and is encoded as the integer format required by the pinned server API.

The full response is untrusted.

## 10.2 Canonical witness

The normalized v1 witness MUST contain only fields required by the pinned verifier algorithm, for example:

```rust
pub struct NativeStorageProof {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub index: u64,
    pub next_index: u64,
    pub proof: Vec<[u8; 32]>,
}

pub struct ZksGetProofWitness {
    pub address: [u8; 20],
    pub storage_proofs: Vec<NativeStorageProof>,
}
```

If the exact v0.20.8 response includes additional proof-relevant fields, they MUST be added explicitly after source-level verification.

## 10.3 Native tree key

The POC-validated v0.20.8 key derivation is:

```text
nativeTreeKey = BLAKE2s(
    12 zero bytes
    || raw address20
    || storageSlot32
)
```

The guest MUST independently derive this value.

## 10.4 Existing leaf hash

The POC-validated existing-leaf hash is:

```text
leafHash = BLAKE2s(
    nativeTreeKey
    || value32
    || U64_LE(nextIndex)
)
```

The leaf's own `index` is used for traversal and is not included in this leaf hash.

## 10.5 Merkle path

The validated native tree depth is 64.

The verifier MUST:

- start from the leaf hash;
- consume explicitly supplied siblings in the pinned v0.20.8 order;
- expand omitted levels using deterministic empty-subtree hashes exactly as the pinned implementation does;
- choose left/right concatenation from the exact bit order of `index`;
- use BLAKE2s for internal-node hashing;
- reconstruct exactly one root;
- require the reconstructed root to equal the accepted `R_K`.

The Host MUST NOT supply a precomputed root that bypasses reconstruction.

## 10.6 Native verifier strictness

The verifier MUST reject:

- wrong proof depth or impossible level count;
- malformed hash length;
- wrong address/key binding;
- wrong storage slot;
- wrong native tree key;
- mutated value;
- mutated `nextIndex`;
- mutated leaf index;
- mutated sibling;
- reversed sibling ordering;
- wrong path-bit order;
- wrong empty-node insertion;
- extra proof data not consumed by the canonical algorithm;
- truncated proof;
- root mismatch;
- proof for another batch/root.

---

# 11. IBC path and L2 storage profile

## 11.1 Supported logical path model

The v1 POC path profile constructs a terminal key as:

```text
clientId || pathType || U64_BE(sequence)
```

with the standard path-type identifiers used by the pinned IBC integration profile:

```text
0x01 = packet commitment
0x02 = receipt
0x03 = acknowledgement commitment
```

For `ibc-eureka-v2-terminal-path-v1`, the Router-facing `bytes[]` contains
exactly one non-empty raw terminal path. Router registration MUST use one empty
Merkle-prefix element so upstream prefixing preserves that one-element shape.
The terminal path is `clientId || pathType || U64_BE(sequence)`, where path type
is packet `0x01`, receipt `0x02`, or acknowledgement `0x03`.

## 11.2 Guest path derivation

The guest MUST receive the logical request components or exact Router-supplied path and independently derive the canonical terminal path.

The Host MUST NOT supply an authoritative pre-hashed application key or authoritative storage slot.

## 11.3 Solidity storage slot

The v1 implementation supports a profile-defined Solidity mapping layout.

Conceptually:

```text
canonicalPath = canonicalize(P)
applicationKey = Keccak256(canonicalPath)

slot = SolidityLayout(applicationKey, configuredBaseSlot, configuredOffsets)
```

For a direct mapping `mapping(bytes32 => bytes32)` at base slot `p`:

```text
slot = Keccak256(ABIEncode32(applicationKey) || ABIEncode32(p))
```

The production profile `cosmos-solidity-ibc-eureka-erc7201-v1` fixes `p` to
the upstream `IBCStoreUpgradeable` commitments namespace:

```text
0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600
```

Profile compilation MUST reject that profile with any other base slot.

For nested mappings or structs, the exact recursive formula MUST come from the authoritative storage-layout artifact.

## 11.4 Address/key binding

The native proof MUST be bound to the configured IBC store:

```text
proof.address == configured IBC store address
proof.storageProof[i].key == guestDerivedSlot[i]
```

The guest MUST reject a cryptographically valid proof for another contract or another storage key.

## 11.5 Application value decoding

The guest MUST decode authenticated storage according to the pinned `ibcStorageProfileId`.

The production Eureka profile supports the Router's direct
`mapping(bytes32 => bytes32)` commitment word. The synthetic and local test
profiles retain the same one-word proof shape for development.

If the production layout uses:

- multiple slots;
- dynamic bytes;
- packed fields;
- a struct;
- a nested mapping;
- an explicit existence flag;

then the profile and implementation MUST define exact reconstruction before release.

---

# 12. Membership SP1 program

## 12.1 Statement

The Membership program proves, for an ordered batch of 1 to 64 claims:

> At accepted Prividium batch K, whose accepted native state root is R_K, the configured IBC store contains the exact logical path P with the exact application value V.

Abstractly:

```text
for every i: State(R_K, IBC_STORE, P_i) = V_i
```

## 12.2 MembershipWitness

```rust
pub struct MembershipWitness {
    pub schema_version: u32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: [u8; 32],
    pub entries: Vec<MembershipEntryWitness>,
    pub proof: NativeProofBatch,
}

pub struct MembershipEntryWitness {
    pub logical_path: Vec<u8>,
    pub expected_application_value: [u8; 32],
}
```

The configured IBC store address/profile is not chosen by the Host; it comes from the compiled source profile.

## 12.3 Trust-anchor binding

The guest MUST bind:

```text
SOURCE_PROFILE_ID
programVersion
B_event
K
R_K
```

and MUST reconstruct `R_K` from the native proof.

The destination contract separately checks that the public `K/R_K` pair equals its already accepted batch state.

## 12.4 Guest algorithm

1. Read and structurally validate `MembershipWitness`.
2. Require schema/profile/program versions.
3. Require `K` is in the supported integer domain.
4. Require 1 to 64 entries and reject duplicate paths.
5. Canonicalize every logical IBC path `P_i`.
6. Derive every exact Solidity storage slot.
7. Require proof address equals configured IBC store.
8. Require proof entry count equals the claim count.
9. Require every proof key equals the corresponding guest-derived slot.
10. Derive native tree key for each slot.
11. Reconstruct each native leaf using the authenticated value/metadata.
12. Reconstruct the native root using the depth-64 BLAKE2s path algorithm.
13. Require reconstructed root == `R_K`.
14. Decode every application value from authenticated storage words.
15. Require every authenticated value equals its independently supplied `V_i`.
16. Hash indexed `(pathDigest, valueHash)` leaves into a padded binary Merkle root.
17. Commit the claim count, batch root, and request digest.
18. Construct public values only after all checks pass.
19. ABI-encode and commit.

## 12.5 MembershipPublicValues

```rust
pub struct MembershipPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: [u8; 32],
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: [u8; 32],
    pub ibc_store: [u8; 20],
    pub entry_count: u32,
    pub batch_root: [u8; 32],
    pub request_digest: [u8; 32],
}
```

The ordered claim leaves are indexed, so reordering claims changes the root.
The tree is padded deterministically to the next power of two. A request with
more than 64 claims must be split into multiple Membership proofs.

## 12.6 Request digest

The exact v1 request digest MUST be fixed in one shared Rust/Solidity codec.

Recommended canonical statement:

```text
requestDigest = Keccak256(
    abi.encode(
        schemaVersion,
        programVersion,
        sourceProfileId,
        proofHeight,
        K,
        R_K,
        ibcStore,
        entryCount,
        batchRoot
    )
)
```

No field may be omitted from the Solidity-side comparison if it is security-relevant to the request.

---

# 13. Non-Membership SP1 program

## 13.1 Statement

The Non-Membership program proves:

> At accepted Prividium batch K, whose accepted native state root is R_K, the exact logical IBC path P satisfies the configured application-level absence predicate.

Abstractly:

```text
Absent(State(R_K, IBC_STORE, P), absenceProfileId) == true
```

## 13.2 Critical rule

The program MUST NOT equate any of the following with absence unless the pinned source/application semantics prove it:

```text
RPC returned zero
index == 0
empty proof array
missing JSON field
Host says key does not exist
```

Parser failure is never absence.

## 13.3 NonMembershipWitness

```rust
pub struct NonMembershipWitness {
    pub schema_version: u32,
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: [u8; 32],
    pub logical_path: Vec<u8>,
    pub proof: ZksGetProofWitness,
}
```

`absenceProfileId` comes from the compiled source profile.

## 13.4 Guest algorithm

1. Bind `SOURCE_PROFILE_ID`, program version, `B_event`, `K`, and `R_K`.
2. Canonicalize `P`.
3. Derive exact Solidity slot(s).
4. Bind proof address/key to the configured store and guest-derived slot(s).
5. Execute the exact pinned v0.20.8 absent-key/native-proof verification behavior.
6. Require reconstructed root == `R_K`.
7. Decode authenticated application storage state.
8. Apply the configured absence predicate.
9. Reject any state that does not satisfy the exact predicate.
10. Commit public values.

## 13.5 NonMembershipPublicValues

```rust
pub struct NonMembershipPublicValues {
    pub schema_version: u32,
    pub program_version: u32,
    pub source_profile_id: [u8; 32],
    pub proof_height: u64,
    pub l1_batch_number: u64,
    pub prividium_native_root: [u8; 32],
    pub ibc_store: [u8; 20],
    pub path_digest: [u8; 32],
    pub solidity_storage_slot: [u8; 32],
    pub native_tree_key: [u8; 32],
    pub absence_profile_id: u32,
    pub request_digest: [u8; 32],
}
```

The exact absent-key verifier cannot be considered production-frozen until Section 24.6 is satisfied.

---

# 14. Destination light-client state

## 14.1 Core state

The destination contract logically stores:

```solidity
struct ConsensusTrustState {
    uint64 finalizedBeaconSlot;
    bytes32 finalizedBeaconHeaderRoot;
    bytes32 currentSyncCommitteeRoot;
    bytes32 nextSyncCommitteeRoot;
    bool nextSyncCommitteeKnown;
}

struct AcceptedBatchState {
    uint64 l2BlockNumber;
    bytes32 root;
    uint64 l2BatchTimestamp;
    bool exists;
}

bytes32 public immutable SOURCE_PROFILE_ID;
ConsensusTrustState internal consensusTrust;
mapping(uint64 => AcceptedBatchState) internal acceptedBatches;
```

The explicit `exists` flag avoids treating an all-zero mapping read as an accepted root.

## 14.2 State ownership by program

```text
Bootstrap:
    initializes ConsensusTrustState
    acceptedBatches is empty

Trust Update:
    MAY update ConsensusTrustState
    MUST NOT change acceptedBatches

Settlement Update:
    MUST NOT change ConsensusTrustState
    MAY add K -> (B_end, R_K, timestamp) to acceptedBatches

Membership / Non-Membership:
    read acceptedBatches[K]
    MUST NOT modify consensus trust or accepted batches
```

## 14.3 Bootstrap

Bootstrap is a deployment/governance trust action, not an SP1 proof.

Deployment MUST provide and independently review:

```text
SOURCE_PROFILE_ID
initial finalizedBeaconSlot
initial finalizedBeaconHeaderRoot
initial currentSyncCommitteeRoot
initial nextSyncCommitteeRoot
initial nextSyncCommitteeKnown
matching full committee preimage(s) available to the Host
four nonzero program VKeys
SP1 verifier/gateway address
IBC Router address
```

If `nextSyncCommitteeKnown == false`, the next root MUST be zero.

## 14.4 Settlement idempotency/conflict rule

After a valid Settlement proof:

```text
if acceptedBatches[K].exists == false:
    store root = R_K, exists = true

else if acceptedBatches[K].root == R_K:
    NoOp

else:
    revert ConflictingAcceptedBatch(K)
```

An already accepted batch root MUST NOT be overwritten with a different root.

## 14.5 Trust Update idempotency/conflict rule

A Trust Update that produces exactly the currently stored `ConsensusTrustState` MAY return `NoOp`.

A proof whose `previousConsensusTrustDigest` does not equal the digest of current stored trust MUST fail before any state write.

---

# 15. Solidity/SP1 verifier integration

## 15.1 Required verifier

The project MUST use the upstream SP1 verifier interface/deployment compatible with the pinned SP1 proof mode.

The project MUST NOT implement its own pairing/Groth16 verifier contract.

## 15.2 Four VKeys

The destination contract stores/configures four nonzero, pairwise-distinct program VKeys:

```text
TRUST_UPDATE_VKEY
SETTLEMENT_UPDATE_VKEY
MEMBERSHIP_VKEY
NON_MEMBERSHIP_VKEY
```

Mapping is fixed:

```text
Trust update message       -> TRUST_UPDATE_VKEY
Settlement update message  -> SETTLEMENT_UPDATE_VKEY
verifyMembership           -> MEMBERSHIP_VKEY
verifyNonMembership        -> NON_MEMBERSHIP_VKEY
```

The relayer MUST NOT choose the VKey.

## 15.3 Update envelope

Because both Trust Update and Settlement use the IBC `updateClient(bytes)` path, v1 defines an explicit operation discriminator:

```solidity
enum UpdateKind {
    TrustUpdate,
    SettlementUpdate,
    CompositeUpdate
}

struct UpdateProofEnvelope {
    UpdateKind kind;
    bytes publicValues;
    bytes proofBytes;
}
```

`CompositeUpdate` is a Host-level transport envelope, not an SP1 guest program.
Its `publicValues` field contains the canonical ABI encoding of `bytes[]`, its
outer `proofBytes` field is empty, and each array element is a complete update
envelope. It MUST contain one to eight Trust Update envelopes followed by
exactly one Settlement Update envelope. Nested composites and every other order
MUST be rejected. Each component retains its own public values, proof bytes,
ELF, and VKey.

The contract MUST strictly decode exactly one canonical envelope and reject:

- unknown kind;
- empty proof for a non-composite update;
- empty public values;
- malformed ABI;
- truncated ABI;
- trailing bytes/non-canonical re-encoding.

The contract selects the VKey from each non-composite component kind. Applying
a composite is atomic: failure of any component MUST revert all earlier state
changes from the same call.

## 15.4 Membership proof envelope

The Proof API returns one canonical ABI envelope per packet. The first packet
uses FULL mode and carries the shared public values and SP1 proof. Remaining
packets use CACHED mode and omit those two byte strings. Every envelope carries
the L1 batch number, committed batch root, entry count, entry index, and Merkle
siblings. The first successful Membership verification stores the shared root;
CACHED mode is valid only after that storage entry exists.

Non-Membership continues to use `SP1ProofEnvelope` directly, and
`verifyNonMembership` selects `NON_MEMBERSHIP_VKEY`.

## 15.5 Verification order

Cheap deterministic context/public-value checks SHOULD happen before the external SP1 verifier call.

No state write and no state-changing external call may happen before proof verification succeeds.

---

# 16. Destination updateClient behavior

## 16.1 Trust Update acceptance

For `UpdateKind.TrustUpdate`, the contract MUST:

1. require authorized IBC Router caller where the pinned interface requires Router mediation;
2. strictly decode the envelope;
3. strictly decode `TrustUpdatePublicValues`;
4. require schema/program/profile IDs;
5. recompute digest of currently stored `ConsensusTrustState`;
6. require it equals `previousConsensusTrustDigest`;
7. apply any destination-time/freshness rule explicitly defined by the source profile;
8. verify proof using `TRUST_UPDATE_VKEY`;
9. re-check no prohibited state is modified;
10. update `ConsensusTrustState` exactly to the proven new fields;
11. leave all `acceptedBatches` untouched;
12. emit a Trust Update event;
13. return the pinned IBC update result.

## 16.2 Settlement Update acceptance

For `UpdateKind.SettlementUpdate`, the contract MUST:

1. require authorized Router caller where applicable;
2. strictly decode envelope/public values;
3. require schema/program/profile IDs;
4. recompute current consensus-trust digest;
5. require equality with `previousConsensusTrustDigest`;
6. verify proof using `SETTLEMENT_UPDATE_VKEY`;
7. apply the idempotency/conflict rule for `K/R_K`;
8. leave all consensus-trust fields unchanged;
9. emit a Settlement event for a newly accepted batch;
10. return the pinned IBC update result.

---

# 17. Membership and non-membership Solidity binding

## 17.1 IBC proof height mapping

The relayer supplies the packet's L2 event block as proof height.
Settlement authenticates the batch-end L2 block `B_end` and L1 batch `K`.

For an IBC `Height`, v1 SHOULD use:

```text
revisionNumber = 0
revisionHeight = packet event block B_event
```

The circuit commits `B_event` as `proofHeight`. The contract MUST require that
it exactly equals the Router-supplied height, is nonzero, and is not newer than
`B_end` for the accepted batch selected by the packet proof's public `K`.

## 17.2 verifyMembership binding

`verifyMembership` MUST:

1. require the authorized Router caller where applicable;
2. require a nonzero L2 event height in `msg_.proofHeight`;
3. strictly decode the FULL or CACHED envelope;
4. in FULL mode, validate public values, verify `MEMBERSHIP_VKEY`, and store
   the shared batch root; in CACHED mode, require that root already exists;
5. require `acceptedBatches[K].exists`, proof height `<= B_end`, and the
   Membership native root equals the accepted Settlement root;
6. recompute the indexed leaf from the Router path and expected value;
7. verify the leaf and canonical sibling count against the stored shared root;
8. return the authenticated timestamp for accepted `K`.

## 17.3 verifyNonMembership binding

The destination contract MUST perform the analogous binding for:

```text
K
R_K
sourceProfileId
IBC store
exact path digest
absenceProfileId
requestDigest
NON_MEMBERSHIP_VKEY
```

It MUST NOT accept a Membership proof under the Non-Membership path.

## 17.4 IBC timestamp implementation gate

If the pinned `ILightClient` interface requires `verifyMembership` / `verifyNonMembership` to return a source timestamp used by timeout logic, the source of that timestamp MUST be cryptographically defined and bound to the same accepted source state.

The current `K -> R_K` state alone does not specify such a timestamp.

The implementation MUST NOT silently substitute:

- local wall-clock time;
- L1 settlement timestamp;
- an unverified L2 RPC timestamp;
- the timestamp from an unrelated batch/header.

Until the authenticated timestamp semantics are provided, timeout-path on-chain integration is:

```text
BLOCKED_ON_SPEC
```

Membership cryptographic proof generation itself is not blocked by this item.

---

# 18. Off-chain proving script

The repository MUST include a local Rust CLI/script. It is not a proof service and is not a trust authority.

## 18.1 Required logical commands

At minimum:

```text
execute trust-update
prove trust-update

execute settlement-update
prove settlement-update

execute membership
prove membership

execute non-membership
prove non-membership

print-vkeys
collect-test-data
```

Exact CLI spelling is not security-critical.

## 18.2 Trust Update Host flow

1. Read current destination `ConsensusTrustState`.
2. Determine the period needed for the next update.
3. Query Beacon light-client updates for the required period.
4. Obtain full signing committee preimage from bootstrap/authenticated committee cache.
5. Parse exact fork-specific response into typed witness.
6. Perform optional Host sanity checks.
7. Execute guest locally if requested.
8. Prove using the canonical Trust Update ELF.
9. Verify locally with SDK.
10. Accumulate no more than the configured `1..=8` Trust Updates in one group.
11. If more periods remain, submit every update in that group individually
    through the destination Router, wait for each successful receipt, and
    verify the exact stored trust digest after every transition.
12. Repeat until the Settlement signing period is reachable.
13. Output the final proof/public values for the normal `StateProof` response.

## 18.3 Settlement Host flow

1. Receive target L2 block `B` from the application/relayer.
2. Query L2 block -> batch mapping to obtain candidate `K`.
3. If mapping is unavailable/null, return a retryable readiness error.
4. Read current destination `ConsensusTrustState`.
5. Query Beacon optimistic update.
6. Determine required signing committee witness.
7. Parse the execution header/branch.
8. Obtain authenticated target execution block number from the optimistic header for witness construction.
9. Derive candidate settlement storage slots using the same deterministic profile code.
10. Query L1 `eth_getProof` for the configured settlement account and slots at the target execution block.
11. Normalize proof nodes.
12. Build `SettlementWitness`.
13. Execute/prove/verify.
14. Output proof/public values.

The Host's candidate `K`, slot values, account fields, and storage values remain untrusted until guest verification.

## 18.4 Membership Host flow

1. Receive the exact IBC proof request and packet event height `B_event`.
2. Resolve the executed batch `K` and authenticated batch-end block `B_end`.
3. Require `B_event <= B_end`.
4. Collect 1 to 64 compatible claims in request order and reject duplicates.
5. Canonicalize every request path and derive all Solidity slots.
6. Make one `zks_getProof(configuredStore, slots, K)` request.
7. Require the response address, key order, and count match the request.
8. Normalize the exact native proof response.
9. Build one `MembershipWitness` containing all original paths and values.
10. Execute/prove/verify one Membership proof.
11. Return one FULL envelope followed by CACHED Merkle-branch envelopes in the
    original request order.

## 18.5 Non-Membership Host flow

Same as Membership, but with no expected value and using the configured absence profile.

## 18.6 Fail-closed RPC parsing

The Host MUST reject rather than default on:

- null required object;
- missing required field;
- wrong JSON type;
- malformed hex;
- wrong fixed-byte length;
- numeric overflow;
- unknown Beacon response version/fork;
- unexpected branch length;
- malformed BLS bytes;
- empty required account proof;
- storage proof count mismatch;
- returned storage key mismatch;
- unsupported L2 proof schema;
- transport timeout;
- JSON-RPC error;
- historical state unavailable.

The Host MUST NOT replace missing fields with zeros, empty vectors, latest state, or defaults.

---

# 19. Error categories

Deterministic crates SHOULD expose typed errors in native mode.

Canonical categories:

| Category | Examples |
|---|---|
| Schema/structure | unsupported schema, bad length, integer overflow, trailing data |
| Source profile | wrong profile ID, unsupported fork/profile version |
| SSZ | wrong container length, bad list limit, wrong branch depth, root mismatch |
| Period/fork | invalid slot ordering, unreachable signature period, unknown fork |
| BLS | malformed compressed point, subgroup failure, infinity, invalid signature |
| Finality | finality branch mismatch, finalized slot regression, same-slot root conflict |
| Committee | wrong committee root, bitvector length mismatch, no participants |
| Execution | unsupported execution schema, execution branch mismatch |
| RLP/MPT | malformed RLP, wrong node reference, path mismatch, absent account |
| Settlement profile | unknown slot rule, slot mismatch, invalid lifecycle value |
| Native ZKsync proof | wrong native key, leaf mismatch, path/root mismatch, malformed depth |
| IBC path | malformed path, unsupported type, wrong sequence encoding |
| Membership | authenticated value mismatch |
| Non-membership | absence predicate not satisfied |
| Public binding | wrong schema/profile/K/root/path/request digest |
| SP1 | wrong VKey, malformed proof, verifier failure |
| RPC/Host | null response, unsupported version, historical data unavailable |

No parser/verifier may turn an error into a successful zero/default/absent result unless this specification explicitly defines that representation as valid.

---

# 20. Test-data requirements

## 20.1 Test-data manifest

Every immutable fixture directory MUST contain a machine-readable manifest recording:

```text
testDataId
testDataVersion
sourceType            // official-vector | synthetic | local-dev | captured-compatible
sourceReference
sourceProfileId
inputFiles[]
expectedSuccess
expectedDecodedFields
expectedHashes
expectedPublicValuesHex
expectedError         // when failure is expected
mutation              // for derived negative vectors
```

Network access MUST NOT occur inside deterministic unit tests.

Live data is collected by explicit scripts and then frozen as fixtures.

A captured Lighthouse light-client update whose top-level response version is `fulu` SHOULD be retained as a `captured-compatible` fixture for parser, fork-dispatch, SSZ, branch, participation-bit, and BLS compatibility tests. The fixture validates compatibility with that captured response; it MUST NOT by itself define the private deployment's `SYNC_COMMITTEE_SIZE`, consensus preset, production fork schedule, fork versions, or generalized indices. Those remain pinned by `SourceProfileV1` and the reviewed consensus-spec baseline.

The fixture manifest SHOULD record the consensus-client/version and exact Beacon API request used to capture it when those values are independently known. They MUST NOT be inferred from the JSON body when the body does not encode them.

## 20.2 Mutation discipline

A negative fixture derived from a valid fixture SHOULD change exactly one security-relevant field unless the test specifically targets malformed structure.

The mutation MUST be documented.

---

# 21. Rigorous deterministic unit tests

Testing is normative. A security-relevant function is incomplete until named positive, negative, malformed-input, boundary, and one-field mutation cases reach every explicit rejection branch.

No fuzz tests are required.

## 21.1 Canonical serialization/public-value tests

For every witness/public-values type:

- encode -> decode -> exact equality;
- minimum legal integer values;
- maximum legal integer values;
- zero where legal;
- zero where forbidden;
- fixed byte lengths;
- truncated input;
- trailing input;
- unknown schema version;
- unknown program version;
- wrong source profile ID;
- vector length zero where forbidden;
- oversized vector;
- length overflow;
- malformed ABI/public bytes;
- Rust ABI bytes == Solidity `abi.encode` bytes.

## 21.2 Hash primitive tests

Known public vectors MUST cover:

- SHA-256 empty;
- SHA-256 `abc`;
- Keccak-256 empty;
- Keccak-256 `abc`;
- BLAKE2s empty;
- BLAKE2s `abc`;
- explicit distinction between Keccak-256 and standardized SHA3-256;
- Ethereum account secure key;
- Ethereum storage secure key;
- native ZKsync tree key;
- native existing-leaf hash;
- consensus trust digest;
- membership request digest.

## 21.3 BeaconBlockHeader SSZ tests

Positive:

- official consensus-spec vectors;
- slot 0 where type permits;
- nonzero representative header;
- `u64::MAX` integer serialization cross-check.

For each field, mutate one byte/value and require root changes:

- slot;
- proposer index;
- parent root;
- state root;
- body root.

Reject malformed fixed lengths before hashing.

## 21.4 SyncCommittee SSZ tests

Let `N = SourceProfileV1.consensus.syncCommitteeSize`.

Positive:

- one source-profile-sized `N`-member committee vector;
- exact aggregate-pubkey inclusion;
- host/native/guest root equality;
- the official 512-member Ethereum vector MAY remain as a supplemental compatibility regression vector and MUST NOT define the private deployment profile.

Negative:

- `N - 1` pubkeys;
- `N + 1` pubkeys;
- malformed 47/49-byte pubkey input at parser boundary;
- aggregate pubkey mutation;
- one committee pubkey mutation;
- committee ordering mutation;
- host-supplied expected root from another committee.

## 21.5 Slot/epoch/period tests

Cover exact boundaries:

```text
slot 0
slot SLOTS_PER_EPOCH - 1
slot SLOTS_PER_EPOCH
period boundary - 1
period boundary
period boundary + 1
u64::MAX where arithmetic is defined
```

Cross-check integer formulas and forbid floating point.

## 21.6 Fork/domain tests

For every supported fork boundary:

- one slot before activation boundary;
- exact activation boundary;
- one slot after;
- signature slot 0/1 lookback boundary;
- wrong fork version;
- wrong genesis validators root;
- wrong domain type;
- mutated fork-data root.

Guest result MUST match independently generated consensus-spec vectors.

## 21.7 Signing-root tests

- official signing-root vector;
- mutate each Beacon header field -> signing root changes;
- mutate signature slot across fork boundary -> domain/signing root changes;
- Host-supplied fake signing root is ignored/recomputed;
- Host-supplied fake domain is ignored/recomputed.

## 21.8 Participant-bit tests

Let `N = SourceProfileV1.consensus.syncCommitteeSize` and `L = ceil(N / 8)`.

- exactly one participant;
- first bit only;
- last valid bit only;
- multiple sparse bits;
- all `N` valid bits set;
- representative source-profile bitvector;
- zero participants -> fail;
- `L - 1` byte input -> fail;
- `L + 1` byte input -> fail;
- non-zero unused high bits in the final byte when `N % 8 != 0` -> fail;
- bit-order inversion -> mismatch/fail;
- committee/pubkey count mismatch cannot silently truncate.

## 21.9 BLS tests

Positive:

- official Ethereum sync-committee aggregate signature vector;
- multiple participant counts;
- exact signing root/participant list.

Negative:

- malformed G1 encoding;
- malformed G2 encoding;
- point not on curve;
- point not in subgroup;
- prohibited infinity encoding;
- mutated pubkey;
- mutated signature;
- signature from another message;
- signature from another participant set;
- mutated signing root;
- wrong participant bit;
- wrong committee root;
- duplicate/additional key not selected by bits;
- aggregate of wrong key order if the implementation accidentally depends on ordering where it should not;
- decode failure must not panic Host/native tests or be converted to valid.

## 21.10 SSZ Merkle branch tests

Positive:

- depth 1;
- multiple depths;
- left and right directions;
- official finality/committee branch vectors.

Negative:

- wrong leaf;
- wrong sibling at every branch position;
- reversed branch order;
- truncated branch;
- extra branch;
- wrong gindex;
- gindex zero;
- wrong expected root;
- depth mismatch;
- checked-shift/overflow boundary.

## 21.11 Finality branch tests

Positive:

- authenticated attested state root + valid finalized header branch.

Negative independently mutate:

- finalized header slot;
- finalized header parent root;
- finalized header state root;
- finalized header body root;
- finality sibling;
- attested state root;
- fork/gindex selection;
- finalized slot older than stored slot;
- same finalized slot with different finalized root.

## 21.12 Next committee branch tests

Positive:

- full committee SSZ root matches valid next-committee branch.

Negative:

- one pubkey changed;
- aggregate pubkey changed;
- sibling changed;
- wrong state root;
- wrong fork gindex;
- branch from another update;
- committee from another update.

## 21.13 Trust transition tests

Required deterministic cases:

- same period, finality advances, committee roots remain correct;
- period boundary exact transition;
- current A / next B -> current B / authenticated next C;
- next unknown valid acquisition case according to pinned spec;
- signature period beyond reachable trust -> fail;
- finalized slot regression -> fail;
- equal finalized slot / unequal root -> fail;
- Host-proposed output roots differing from derived values cannot affect result.

## 21.14 ExecutionPayloadHeader SSZ tests

For every supported schema:

- official/reference vector root;
- empty `extra_data`;
- max-length `extra_data`;
- each fixed field mutated independently;
- each integer boundary;
- wrong variable-length mix-in;
- unsupported fork schema -> fail;
- field omission/reordering -> fail.

## 21.15 Execution branch tests

Positive:

- fork-correct execution root/branch reconstructs authenticated Beacon body root.

Negative:

- mutate execution `state_root`;
- mutate `block_number`;
- mutate `block_hash`;
- mutate any branch sibling;
- wrong execution gindex;
- branch from another Beacon header;
- wrong Beacon body root;
- truncated/extra branch.

## 21.16 Strict RLP tests

Cover:

- empty byte string;
- single byte < `0x80`;
- single byte >= `0x80`;
- short/long string boundary 55/56;
- short/long list boundary 55/56;
- nested lists;
- exact consumption.

Reject:

- overlong encoding;
- leading-zero length-of-length;
- long form where short form required;
- payload shorter/longer than declared;
- integer with forbidden leading zero;
- truncated nested list;
- integer overflow;
- length overflow;
- trailing bytes.

## 21.17 Ethereum account MPT tests

Positive structures:

- branch -> leaf;
- branch -> extension -> leaf;
- extension -> branch -> leaf;
- multiple extensions;
- hashed child;
- inline child.

Negative:

- wrong root;
- wrong account address;
- wrong secure key;
- wrong nibble;
- wrong branch child;
- wrong extension prefix;
- wrong leaf suffix;
- mutated node RLP;
- mutated child hash;
- missing node;
- malformed node;
- truncated proof;
- neighboring account proof;
- absent settlement account.

## 21.18 Ethereum storage MPT tests

Positive:

```text
verify_storage(storageRoot, logicalSlot, proof) == Present(expectedWord)
```

Negative:

- wrong storage root;
- wrong logical slot;
- wrong secure trie key;
- wrong value;
- mutated branch;
- mutated extension;
- mutated leaf;
- mutated inline child;
- mutated hashed child;
- truncated proof;
- extra node attempting ambiguous traversal;
- proof for neighboring key;
- non-canonical storage integer encoding.

## 21.19 Settlement slot derivation tests

For every production storage field:

- authoritative Solidity reference slot == Rust native slot == SP1 guest slot;
- `K=0`, `K=1`, representative K, `u64::MAX` where accepted;
- mutate K -> slot changes;
- mutate base slot -> slot changes;
- mutate field offset -> slot changes;
- wrong field order/profile ID -> fail;
- overflow in offset arithmetic -> fail.

## 21.20 Batch acceptance tests

At minimum:

- exact accepted state -> pass;
- every other lifecycle state -> fail unless explicitly accepted by profile;
- malformed encoded status -> fail;
- proof authenticates status for another K -> fail;
- status slot correct but root/commitment slot from another K -> fail.

## 21.21 K -> R_K binding tests

Use at least one real/reference batch vector when available.

Positive must establish:

```text
authenticated L1 storage fields
  -> exact binding algorithm
  -> expected R_K
```

Negative independently mutate:

- K;
- settlement commitment;
- verification data;
- lifecycle status;
- field slot;
- field value;
- final native root;
- one byte of any hashed preimage.

## 21.22 Native tree-key tests

For known vectors:

```text
BLAKE2s(12 zero bytes || address20 || slot32)
```

Cross-check Rust native == SP1 guest == pinned source/reference.

Mutate independently:

- address byte;
- slot byte;
- zero prefix length/content;
- byte order.

## 21.23 Native leaf tests

Positive:

```text
BLAKE2s(nativeKey || value || U64_LE(nextIndex))
```

Negative:

- nextIndex big-endian instead of little-endian;
- own leaf index incorrectly included in preimage;
- key mutation;
- value mutation;
- nextIndex mutation.

## 21.24 Native Merkle path tests

Positive:

- full explicit path;
- compressed/omitted levels exactly as v0.20.8 permits;
- path with left/right changes;
- real/reference `zks_getProof` vector.

Negative:

- one sibling modified at every possible supplied position;
- reverse sibling order;
- reverse index-bit order;
- wrong empty hash at an omitted level;
- one extra sibling;
- one missing sibling;
- wrong leaf index;
- wrong nextIndex;
- wrong root;
- proof from another K/root.

## 21.25 IBC path tests

For packet, receipt, and acknowledgement paths:

- canonical client ID + type byte + 8-byte big-endian sequence;
- sequence 0 if allowed by pinned upstream semantics;
- sequence 1;
- sequence `2^32`;
- sequence `2^64-1`;
- empty client ID -> fail;
- malformed identifier -> fail;
- wrong type byte -> fail;
- wrong sequence width -> fail;
- little-endian sequence -> fail;
- trailing bytes -> fail;
- truncated path -> fail.

## 21.26 IBC storage-slot tests

For each supported path type:

```text
Rust native slot == SP1 guest slot == Solidity/Foundry reference slot
```

Mutating path, path type, sequence, mapping base slot, or layout profile MUST change/reject the derived slot.

## 21.27 Membership tests

Positive:

- authenticated packet commitment equals expected `V`;
- authenticated acknowledgement commitment equals expected `V`;
- full integrated native proof reconstructs exact accepted `R_K`.

Negative independently test:

- wrong source profile;
- wrong K;
- wrong accepted R_K;
- wrong IBC store address;
- wrong logical path;
- wrong path type;
- wrong sequence;
- wrong derived Solidity slot;
- proof key for another slot;
- wrong native tree key;
- wrong leaf value;
- wrong nextIndex;
- wrong leaf index;
- wrong sibling;
- wrong root;
- wrong expected `V`;
- correct proof for another batch;
- packet value used for acknowledgement path;
- acknowledgement value used for packet path;
- malformed public values;
- request digest mismatch.

## 21.28 Non-membership tests

Once the absence profile is frozen, required tests include:

- key never existed -> valid absence if the pinned source algorithm says so;
- deleted key -> expected result according to pinned application semantics;
- key exists -> fail;
- present zero value -> result according to exact application semantics, never assumed absent by default;
- proof for another absent key -> fail;
- wrong K/root/path/slot/native key -> fail;
- mutated sibling/index/nextIndex -> fail;
- malformed absent-proof shape -> fail;
- parser failure -> fail, not absence;
- Membership proof under Non-Membership VKey -> fail.

## 21.29 Public binding tests

For each of four public-value structs:

- Rust encoding == golden bytes;
- Solidity decoding == expected struct;
- Solidity re-encoding == golden bytes;
- one byte changed in every field -> corresponding binding check fails;
- truncated bytes -> fail;
- appended bytes -> fail;
- wrong schema/program/profile -> fail.

---

# 22. SP1 execution and proof-generation tests

## 22.1 Native/SP1 differential execution

Every golden vector MUST be run through both:

```text
native deterministic verifier
SP1 execute mode
```

Acceptance/rejection and public-value bytes MUST match exactly.

## 22.2 Guest rejection must be real

For every major negative class, tests MUST disable Host pre-checks or directly construct the witness so invalid data reaches the guest.

A test is not sufficient if the Host rejects before SP1 and the guest rejection branch is never exercised.

## 22.3 Core proof suite

At least one golden valid vector per program MUST:

1. build the canonical ELF;
2. run SP1 setup;
3. generate a core proof;
4. locally verify it;
5. assert exact public values.

## 22.4 Groth16 EVM proof suite

At least one golden valid vector per program MUST, for release/conformance:

1. generate the configured SP1 Groth16/BN254 EVM proof;
2. verify it with the SP1 SDK;
3. verify it through the matching upstream EVM verifier/gateway;
4. assert exact public values;
5. write a deterministic verifier fixture.

The prior BLS memory waiver is not a final release waiver. Trust Update and Settlement MUST be proven through infrastructure capable of completing the BLS-heavy proof.

## 22.5 Four-program VKey isolation

Tests MUST assert all 16 relevant correct/wrong combinations. At minimum:

```text
trust proof + TRUST_UPDATE_VKEY       -> valid
trust proof + any other VKey          -> invalid

settlement proof + SETTLEMENT_VKEY    -> valid
settlement proof + any other VKey     -> invalid

membership proof + MEMBERSHIP_VKEY    -> valid
membership proof + any other VKey     -> invalid

non-membership + NON_MEMBERSHIP_VKEY  -> valid
non-membership + any other VKey       -> invalid
```

## 22.6 Proof/public-value tamper tests

For each valid proof artifact:

- mutate proof byte -> verifier fails;
- truncate proof -> fails;
- mutate one public-value byte -> verifier or contract binding fails;
- truncate public values -> strict decoder fails;
- append public values -> strict decoder fails;
- pair proof with another program's public values -> fail;
- pair proof/public values with wrong profile ID -> fail.

---

# 23. Solidity integration and end-to-end tests

## 23.1 Mock-verifier policy

A mock SP1 verifier MAY be used only for fast Solidity state-machine and public-binding unit tests.

A mock verifier is not evidence that real SP1 integration works.

Release/conformance MUST include the real upstream SP1 verifier/gateway.

## 23.2 Trust Update contract tests

Required:

- valid real proof updates only consensus trust fields;
- old-trust digest mismatch fails;
- wrong source profile fails;
- wrong Trust Update VKey/proof fails;
- finalized slot regression fails in guest;
- same-slot different root fails;
- identical state transition follows explicit NoOp rule;
- accepted batch mapping remains unchanged;
- malformed/trailing envelope bytes fail.

## 23.3 Settlement contract tests

Required:

- valid real proof adds `K -> R_K`;
- consensus trust fields remain byte-for-byte unchanged;
- old-trust digest mismatch fails;
- wrong K/root binding fails;
- same K/same root -> NoOp;
- same K/different root -> conflict revert;
- Trust Update proof cannot be used as Settlement proof;
- malformed public values fail.

## 23.4 Membership contract tests

Required:

- accepted K/root + valid proof succeeds;
- unknown K fails;
- wrong stored R_K fails;
- wrong source profile fails;
- wrong store fails;
- wrong path digest fails;
- wrong expected value binding fails;
- wrong request digest fails;
- Non-Membership proof cannot be used;
- malformed public values fail.

## 23.5 Non-membership contract tests

Required once Section 24.6 is frozen:

- accepted K/root + valid absence proof succeeds;
- present key fails;
- wrong K/root/path/store fails;
- Membership proof cannot be used;
- wrong absence profile fails;
- malformed public values fail.

## 23.6 Local end-to-end topology

A conformance environment SHOULD run:

```text
Prividium / ZKsync OS local or controlled test source
        |
        v
private Ethereum PoS settlement L1
  - consensus client exposing standard light-client endpoints
  - execution client exposing eth_getProof
        |
        v
Destination EVM chain
  - IBC Router
  - upstream SP1 verifier/gateway
  - PrividiumZKLightClient
```

The current target deployment has one active L1 validator. Validator count is not a guest security constant and MUST NOT be used as `SYNC_COMMITTEE_SIZE`. E2E MUST use the `SYNC_COMMITTEE_SIZE` from the pinned private consensus preset and verify exactly that many ordered committee positions.

For target-deployment conformance, the E2E settlement L1 SHOULD use Lighthouse `v8.1.3-176cce5` and Reth `v1.11.3-d6324d6`, and the source L2 MUST use ZKsync OS `v0.20.8` / commit `dbb5c03d4a94ceb1acea9f79242590f354660239`, unless the test explicitly records an upgrade scenario. The E2E settlement L1 MUST run the fork selected by the E2E source profile. A public/captured Fulu fixture is useful compatibility evidence but does not replace confirmation of the private deployment's actual fork schedule.

All state-changing E2E transactions MUST be submitted using the configured gasless / zero-fee transaction policy. E2E success MUST NOT depend on a positive gas price.

## 23.7 Positive E2E scenarios

At minimum:

1. bootstrap consensus trust;
2. Trust Update advances finality/committee trust;
3. Settlement authenticates a recent optimistic header and accepts a new batch `K/R_K`;
4. packet commitment Membership succeeds against accepted `R_K`;
5. acknowledgement Membership succeeds;
6. Non-Membership succeeds once absence semantics are frozen;
7. multiple Membership proofs reuse one accepted `K/R_K`;
8. later Settlement reuses current/next committee without Trust Update when reachable;
9. Settlement detects an unreachable future signing committee and MUST NOT proceed with that untrusted committee;
10. the Host generates a separate Trust Update proof and a separate Settlement proof, then returns them in one ordered composite update;
11. the destination atomically advances `ConsensusTrustState` and accepts Settlement through the relayer's normal `StateProof` submission;
12. the Trust Update and Settlement proofs use their own ELFs/VKeys and are never merged into one guest proof.

## 23.8 Negative E2E scenarios

Inject and reject:

- fake relayer proof bytes;
- wrong program VKey context;
- modified public values;
- stale previous-trust state;
- wrong full sync committee;
- wrong BLS signature;
- wrong finality branch;
- wrong next committee branch;
- wrong execution branch;
- wrong L1 account proof;
- wrong L1 storage proof;
- wrong K;
- settlement proof for another storage layout/profile;
- wrong R_K;
- native proof from another K;
- native proof for another IBC store;
- wrong IBC path;
- wrong packet/ACK value;
- absent-key proof for wrong path;
- replay of an old proof after trust state changed where the proof is expected to bind current trust.

## 23.9 Historical data availability tests

The E2E environment MUST explicitly test historical reads required by the architecture:

- L1 `eth_getProof` at the execution block authenticated by the Beacon update;
- `zks_getProof` for an accepted historical batch `K` within the supported retention window.

Failure to serve required historical data MUST produce an explicit availability error. The Host MUST NOT fall back to latest state.

---

# 24. Implementation gates - confirmed target values and remaining deployment inputs

The implementation MUST use the confirmed target versions already pinned in Section 2.2 and MUST NOT treat them as open choices. The byte-exact production profile still cannot be frozen until every remaining item below is supplied and validated.

Known target versions and facts are not repeated as open questions. Only the remaining profile inputs below are implementation gates.

## 24.1 Consensus profile

Already confirmed for the current target profile:

```text
consensus client = Lighthouse v8.1.3-176cce5
execution client = Reth v1.11.3-d6324d6
active L1 validator count = 1
```

The following Beacon endpoints are already confirmed for the target private deployment and MUST NOT be re-requested as unknown inputs:

```text
GET /eth/v1/beacon/states/head/finality_checkpoints
GET /eth/v1/beacon/states/{state}/validators
```

The following consensus-profile values still MUST be captured from the private Beacon-chain configuration before the production profile is frozen:

```text
GENESIS_VALIDATORS_ROOT
GENESIS_TIME
SECONDS_PER_SLOT
SLOTS_PER_EPOCH
EPOCHS_PER_SYNC_COMMITTEE_PERIOD
SYNC_COMMITTEE_SIZE
complete active fork schedule
activation epoch for every supported fork
4-byte fork version for every supported fork
```

Preferred collection endpoints are:

```text
GET /eth/v1/beacon/genesis
GET /eth/v1/config/spec
GET /eth/v1/config/fork_schedule
```

The provided private Beacon gateway has not yet been confirmed to expose every endpoint above. If `/eth/v1/config/spec` or `/eth/v1/config/fork_schedule` is unavailable, the deployment team MUST provide the exact private consensus preset/config files containing the same values. The implementation MUST NOT fall back to Ethereum Mainnet defaults.

The following standard light-client endpoints also need availability confirmation for the final Host/E2E flow unless already proven accessible in the target environment:

```text
GET /eth/v1/beacon/light_client/bootstrap/{block_root}
GET /eth/v1/beacon/light_client/updates?start_period=P&count=N
GET /eth/v1/beacon/light_client/optimistic_update
```

Also required:

- exact Ethereum consensus-spec compatibility baseline for Lighthouse `v8.1.3-176cce5` and the private fork schedule;
- exact `LightClientHeader` schema for every fork that may occur during operation;
- exact `ExecutionPayloadHeader` schema for every supported fork;
- fork-correct finality generalized index;
- fork-correct next-sync-committee generalized index;
- fork-correct execution-payload generalized index.

Generalized indices MUST be verified from the pinned schema, not copied from old prototype constants.

## 24.2 Bootstrap trust material

Required:

```text
initial finalized Beacon slot
initial finalized Beacon header root
initial current SyncCommittee root
full current SyncCommittee preimage (`SYNC_COMMITTEE_SIZE` pubkeys + aggregate pubkey)
initial next SyncCommittee root, if known
full next SyncCommittee preimage, if known
nextSyncCommitteeKnown initial value
```

All roots and full committee objects must cross-check under canonical SSZ.

## 24.3 Settlement contract source/layout

Required:

```text
settlement/Diamond proxy address
implementation/facet source repository
exact immutable commit/tag deployed
compiler version/settings if layout-sensitive
storage-layout JSON/artifact
proxy/facet mapping needed to locate storage owner
```

The team must identify the exact fields used for:

```text
batch K
batch lifecycle/acceptance status
settlement commitment / verification data
native state-root binding data
```

## 24.4 Exact batch acceptance rule

Required explicit answer:

```text
What exact authenticated on-chain state means batch K is acceptable?
```

For example, if lifecycle states include committed/proved/executed, specify exactly which one is required and the exact storage field/value proving it.

Do not infer this from an RPC becoming non-null.

## 24.5 Exact settlement data -> R_K rule

Required byte-level algorithm:

```text
which authenticated settlement field(s) commit to R_K
field encoding
field ordering
hash/commitment algorithm
whether K is included in the preimage
whether l1VerificationData or another structure is involved
endianness and widths
any domain/version bytes
```

Provide at least one real vector:

```text
K
L1 execution block
storage slots
raw authenticated storage values
intermediate commitment bytes/hashes
expected R_K
```

S-08/S-09/S-10 synthetic POC behavior MUST NOT be promoted to production constants without this gate.

## 24.6 Exact v0.20.8 non-membership / absent-key behavior

Required real vectors for:

1. a key that has never existed;
2. a key that existed and was later deleted, if this can occur.

Record exact:

```text
address
slot
K
value
index
nextIndex
proof[]
reconstructed root
application meaning of absence
```

Confirm from pinned source:

- leaf/index behavior for absent keys;
- neighbor-leaf or empty-leaf semantics;
- empty-subtree insertion;
- proof compression rules;
- whether zero value is distinguishable from absence.

Pinned native-tree behavior and the v0.20.8 RPC wire variants are frozen by
the source audit, the regression tests under `crates/zksync-native/tests/`,
and the real local-node vectors under
`test-data/zksync-native/v0.20.8/local/`. The controlled v0.20.8 node returned:

- `existing` for a non-zero leaf;
- two strictly ordered, linked neighbor paths for a never-written key;
- `existing` with value zero after a previously non-zero leaf was updated to
  zero; and
- seven explicit siblings with 57 deterministic trailing empty siblings
  omitted from each captured depth-64 path.

Those real local responses reconstruct the same native root as the pinned
server and bind through the v0.20.8 state-commitment transformation to the
local settlement contract's `storedBatchHash(K)`.

Only final production conformance remains `BLOCKED_ON_SPEC` here. It requires:

1. a real response from the deployed v0.20.8 endpoint confirming its deployed
   state, historical availability, and actual `K -> R_K -> settlement`
   correspondence; and
2. the exact IBC application storage/absence semantics required by Sections
   24.7 and 24.8.

The pinned native-tree Non-Membership algorithm itself MUST NOT be treated as
externally unresolved.

## 24.7 IBC source contract and storage layout

Required:

```text
IBC store contract address
proxy address if applicable
implementation address/version
source repository
exact commit/tag
ABI
Solidity storage-layout artifact
```

For every supported object type, provide:

```text
logical path components
canonical path bytes
mapping key formula
base Solidity slot
nested mapping formula, if any
struct field offsets, if any
number/order of slots
stored Solidity type
```

At minimum:

- packet commitment;
- acknowledgement commitment;
- receipt.

If client/consensus/connection/channel state is also required, each needs the same exact definition.

## 24.8 Exact IBC value and timestamp semantics

For Membership, define what `V` means for every supported object:

```text
packet commitment -> exact 32-byte commitment/hash rule
ack commitment -> exact bytes/hash rule
receipt -> exact representation if membership is ever used
```

For Non-Membership, define the exact absence predicate.

If the upstream light-client interface requires a timestamp return value, define the exact authenticated source timestamp associated with proof height `K` and how it is cryptographically bound to the same accepted state.

This must be resolved before timeout behavior is considered production-ready.

## 24.9 Root correspondence

Provide a real batch proving:

```text
R_K accepted by Settlement Update
==
root reconstructed from zks_getProof(..., K)
```

No unauthenticated intermediate or RPC-reported root may be trusted.

## 24.10 Historical proof retention

Confirm operational retention for:

```text
L1 eth_getProof(..., historical N_L1)
zks_getProof(..., historical K)
```

Define the maximum supported proof age/retention window and expected error when unavailable.

## 24.11 Destination IBC integration

Required:

- exact `lfdt-ibc/ibc-contracts` tag/commit;
- Router and `ILightClient` interface version;
- exact `bytes[] path` shape delivered to the light client;
- exact `proofHeight` revision mapping;
- exact `updateClient` message wrapping expectation;
- expected return timestamp semantics;
- caller/access-control assumptions.

## 24.12 SP1 verifier deployment

Required:

- exact SP1 release used by guests/SDK;
- matching `sp1-contracts` tag/commit;
- chosen proof mode (v1 target: Groth16 EVM proof);
- verifier/gateway deployment contract identity for the destination network;
- any verifier route/selector configuration required by that release.

---

# 25. Performance and resource gates

## 25.1 Required measurements

For all four final programs, release CI or a controlled release benchmark MUST record:

- SP1 cycle/instruction count;
- serialized witness size;
- guest memory where available;
- prover-process peak RSS;
- execute wall-clock time;
- core proof wall-clock time;
- Groth16 proof wall-clock time;
- verification wall-clock time;
- proof byte size;
- public-value byte size.

## 25.2 No invented SLA

v1 does not define a universal proof-time SLA. Proof time depends on the selected SP1 proving infrastructure.

Every benchmark report MUST record:

```text
CPU
RAM
accelerator, if any
OS
SP1 prover mode
number of trials
```

## 25.3 BLS memory gate

Because the POC BLS-heavy integrated guests exceeded a 31 GiB server during proof generation, the release process MUST prove Trust Update and Settlement on infrastructure with sufficient memory.

Execution-only success is not sufficient for release conformance.

## 25.4 Regression baseline

The first production-capable tagged release SHOULD establish a baseline for:

```text
cycles
witness size
proof size
peak prover memory
proof time
```

Later releases SHOULD require explicit review for material regression on the same vectors/hardware class.

---

# 26. Reproducible build, ELF, and VKey requirements

## 26.1 Pinned inputs

Release builds MUST pin:

- Rust toolchain;
- SP1 release;
- guest build toolchain/image;
- `Cargo.lock`;
- every Git dependency by immutable commit/tag;
- Solidity compiler/settings;
- Foundry version;
- IBC contract commit;
- SP1 contract commit;
- ZKsync OS commit;
- Ethereum consensus-spec commit;
- exact SourceProfileV1.

No release artifact may depend on an unpinned branch such as `main`.

## 26.2 ELF reproducibility

A script MUST:

1. build all four guests from a clean environment;
2. hash every ELF with SHA-256;
3. destroy build output;
4. build again from identical pinned inputs;
5. require identical ELF hashes.

Required ELFs:

```text
trust-update.elf
settlement-update.elf
membership.elf
non-membership.elf
```

## 26.3 VKey reproducibility

`generate-vkeys.sh` MUST run SP1 setup on every canonical ELF.

`release/expected-vkeys.json` MUST contain:

```json
{
  "trust-update": {"sourceProfileId":"0x...","elfSha256":"0x...","programVKey":"0x..."},
  "settlement-update": {"sourceProfileId":"0x...","elfSha256":"0x...","programVKey":"0x..."},
  "membership": {"sourceProfileId":"0x...","elfSha256":"0x...","programVKey":"0x..."},
  "non-membership": {"sourceProfileId":"0x...","elfSha256":"0x...","programVKey":"0x..."}
}
```

All four `sourceProfileId` values MUST match the profile used to build the
ELFs. Release generation, deployment, and Proof API startup MUST reject a
mismatch.

A changed VKey requires an intentional release update and migration/deployment review.

---

# 27. Release manifest

Every tagged release MUST publish machine-readable metadata containing at least:

```text
spec document ID/version
repository Git commit
Rust toolchain
SP1 SDK/toolchain version
sp1-contracts tag/commit
lfdt-ibc/ibc-contracts tag/commit
Ethereum consensus-spec commit
Lighthouse version
Reth version
private consensus preset/config identity or hash
ZKsync OS tag/commit
Solidity compiler/settings
Foundry version
SourceProfileV1 hash / SOURCE_PROFILE_ID
four ELF SHA-256 hashes
four SP1 program VKeys
light-client ABI hash
light-client deployed-bytecode hash
public-values schema version
program versions
proof mode/verifier route
performance baseline reference
```

The manifest MUST NOT contain secrets.

---

# 28. Coding-agent implementation rules

Who implementing this specification MUST follow these rules.

1. Read the complete specification before changing code.
2. Preserve the four-program separation.
3. Keep deterministic security logic in shared crates, not duplicated guest entrypoints.
4. Never trust a Host-supplied BLS domain, signing root, committee root, generalized index, storage slot, native tree key, or final root when the guest can derive it.
5. Do not copy prototype consensus code wholesale.
6. Do not use unchecked BLS point constructors on witness bytes.
7. Do not use `unwrap`/panic for ordinary hostile parsing in native shared libraries; return typed errors. Guest wrappers may convert an error to proof failure.
8. Do not use `u32` for Beacon slots/epochs/batches.
9. Do not implement L2 native proofs with Ethereum MPT code.
10. Do not implement L1 account/storage proofs with the ZKsync native verifier.
11. Do not invent settlement storage slots or lifecycle rules.
12. Do not invent the K -> R_K formula.
13. Do not invent IBC storage layout/value/absence rules.
14. Do not infer production absence from a zero RPC value.
15. Do not fall back from historical proof height to latest state.
16. Do not let the relayer choose a VKey.
17. Do not store full sync-committee pubkeys on-chain.
18. Do not let Settlement overwrite finalized Beacon trust.
19. Do not let Trust Update modify accepted batch roots.
20. Do not let Membership/Non-Membership modify client trust state.
21. Add deterministic positive and negative tests in the same change as every security-critical branch.
22. Fuzz tests are not required; do not spend implementation scope on fuzzing unless separately requested.
23. Treat the exact target versions in Section 2.2 as fixed implementation inputs, not open choices. If another required implementation-gate item is unresolved, implement only the reusable logic that does not depend on that missing value and report `BLOCKED_ON_SPEC` for the deployment-specific path.
24. Every claimed PASS must correspond to a command actually executed.
25. Do not silently upgrade SP1, BLS, consensus, ZKsync, or IBC dependencies.

## 28.1 Required implementation order

Developer SHOULD implement in this order:

1. pin workspace/toolchains/dependencies;
2. source-profile schema and generated constants;
3. canonical shared types and ABI public-value codecs;
4. SHA-256/Keccak/BLAKE2s wrappers and vectors;
5. SSZ basic/merkleization utilities;
6. BeaconBlockHeader SSZ;
7. SyncCommittee SSZ;
8. slot/epoch/period/fork/domain/signing-root logic;
9. participant selection and hardened BLS verification;
10. generic SSZ branch verifier;
11. finality and next-committee verification;
12. trust transition;
13. Trust Update guest;
14. strict RLP + Ethereum MPT verifier;
15. execution payload SSZ and execution branch;
16. Settlement guest up to generic MPT authentication;
17. settlement-profile slot/acceptance/K->R_K modules after Section 24 inputs are available;
18. complete Settlement guest;
19. ZKsync native tree key/leaf/path verifier;
20. IBC path/storage/value profile;
21. Membership guest;
22. Non-Membership guest after absence semantics are frozen;
23. Host RPC adapters/witness builders;
24. Solidity light client and codecs;
25. deterministic native unit/negative tests;
26. SP1 execute/core proof tests;
27. Groth16/real-verifier integration tests;
28. local/captured end-to-end tests;
29. reproducibility/performance/release tooling.

## 28.2 Required coding-agent completion report

The final implementation report MUST include:

```text
files created/changed
exact dependency versions
SOURCE_PROFILE_ID
four ELF hashes
four VKeys
number/result of native tests
number/result of SP1 execute tests
core proof results
Groth16 proof results
Solidity test results
real verifier/gateway integration result
E2E result
performance/resource measurements
all BLOCKED_ON_SPEC items
```

The agent MUST NOT claim production completion while any mandatory acceptance item is unresolved.

---

# 29. Final implementation acceptance checklist

A repository is conformant only when all applicable items are satisfied.

## 29.1 Architecture

- [ ] Exactly four SP1 programs exist.
- [ ] No combined Trust/Settlement/Membership guest exists.
- [ ] No organization-specific RPC URLs, credentials, or identifiers are committed.
- [ ] Shared deterministic code has no RPC/network dependency.
- [ ] Source profile is pinned and `SOURCE_PROFILE_ID` is reproducible.

## 29.2 Trust Update

- [ ] BeaconBlockHeader SSZ matches official vectors.
- [ ] Full `SYNC_COMMITTEE_SIZE`-member SyncCommittee SSZ root matches the pinned source-profile vector; supplemental 512-member public vectors do not define the private profile.
- [ ] Slots/epochs/periods use `u64` and exact integer arithmetic.
- [ ] Fork version/domain is derived inside guest.
- [ ] Signing root is derived inside guest.
- [ ] Participation bitvector is exactly `ceil(SYNC_COMMITTEE_SIZE / 8)` bytes, unused padding bits are zero, and committee data cannot be truncated.
- [ ] BLS points are checked/canonical/subgroup-valid.
- [ ] BLS aggregate signature verifies inside guest.
- [ ] Finality branch is fork-correct and verified against authenticated state root.
- [ ] Next committee branch is fork-correct and verified against authenticated state root.
- [ ] Finalized slot cannot regress.
- [ ] Same finalized slot cannot change root.
- [ ] Committee rotation is derived, not Host selected.
- [ ] Previous trust digest is exact and Solidity-bound.
- [ ] Trust Update does not change accepted batch roots.
- [ ] A real final proof has been generated and verified on adequate hardware.

## 29.3 Settlement Update

- [ ] Uses the shared Trust Update committee/domain/BLS libraries.
- [ ] Authenticates a recent Beacon header without claiming target finality.
- [ ] Attested slot cannot precede the trusted finalized slot.
- [ ] Attested root at the trusted finalized slot must equal the trusted root.
- [ ] ExecutionPayloadHeader SSZ matches fork-correct vectors.
- [ ] Execution branch binds execution header to authenticated Beacon body root.
- [ ] `R_L1` is used only after execution-branch success.
- [ ] Settlement account MPT is verified under authenticated `R_L1`.
- [ ] Account RLP is strict/canonical and yields authenticated storage root.
- [ ] K-specific storage slots are guest-derived from authoritative layout.
- [ ] Storage MPT proofs are verified under authenticated storage root.
- [ ] Exact accepted lifecycle state is guest-enforced.
- [ ] Exact settlement-data -> `R_K` rule is guest-enforced.
- [ ] `K/R_K` public values are cryptographically derived.
- [ ] Settlement does not modify consensus trust state.
- [ ] Same K/same root is idempotent; same K/different root conflicts.
- [ ] A real final BLS-heavy proof has been generated and verified.

## 29.4 Membership

- [ ] Exact source profile/K/R_K are bound.
- [ ] Destination confirms stored accepted root for K.
- [ ] Logical IBC path is canonicalized in guest.
- [ ] Solidity storage slot is derived in guest.
- [ ] Proof address/key is bound to configured store/slot.
- [ ] v0.20.8 native tree key matches pinned source vectors.
- [ ] v0.20.8 native leaf hash matches pinned source vectors.
- [ ] Depth-64 native Merkle path reconstructs exact `R_K`.
- [ ] Authenticated value is decoded according to source IBC storage profile.
- [ ] Authenticated value equals expected `V`.
- [ ] Public request digest binds exact request.
- [ ] Real Groth16 proof verifies through the matching EVM verifier.
- [ ] Full deterministic negative suite passes.

## 29.5 Non-Membership

- [ ] Exact absent-key behavior is frozen from pinned v0.20.8 source/real vectors.
- [ ] Exact application absence semantics are frozen.
- [ ] Guest derives exact path/slot/native key.
- [ ] Native proof reconstructs exact accepted `R_K`.
- [ ] Parser/RPC failure is not absence.
- [ ] Zero is not assumed absent unless source semantics explicitly define it.
- [ ] Membership proof cannot be reused under Non-Membership VKey.
- [ ] Full deterministic negative suite passes.
- [ ] Real Groth16 proof verifies through the matching EVM verifier.

## 29.6 Solidity/SP1 binding

- [ ] Four nonzero pairwise-distinct VKeys are configured.
- [ ] Relayer cannot supply/override VKeys.
- [ ] Strict proof-envelope decoding rejects trailing/malformed bytes.
- [ ] Real upstream SP1 verifier/gateway accepts the correct proof.
- [ ] Wrong proof/VKey/public-values combinations fail.
- [ ] Public-value Rust/Solidity ABI golden vectors match exactly.
- [ ] No state changes occur before proof verification.

## 29.7 Tests

- [ ] Every explicit rejection branch has at least one named deterministic test.
- [ ] One-field mutation tests cover every security-critical committed field.
- [ ] Native and SP1 execute results agree on golden vectors.
- [ ] Core proof generated for all four programs.
- [ ] Groth16 proof generated for all four programs.
- [ ] Proof/public-value tamper suite passes.
- [ ] Real verifier integration passes.
- [ ] End-to-end positive scenarios pass.
- [ ] End-to-end negative scenarios pass.
- [ ] State-changing E2E transactions succeed under the configured gasless / zero-fee transaction policy without treating fee fields as proof-validity inputs.
- [ ] Historical proof availability behavior is tested.
- [ ] No fuzz-testing gate is required.

## 29.8 Release

- [ ] All dependencies are immutable/pinned.
- [ ] Four ELF hashes are reproducible.
- [ ] Four VKeys are reproducible.
- [ ] Release manifest is complete.
- [ ] Source profile contains no secret.
- [ ] Performance/resource measurements are recorded.
- [ ] No unresolved mandatory `BLOCKED_ON_SPEC` item remains for the claimed deployment profile.

---

# 30. POC evidence appendix - non-normative

The following results motivated this implementation specification. They are engineering evidence, not replacements for Section 29.

## 30.1 Trust Update POC evidence

The POC/public Ethereum fixtures in this appendix may use a 512-position SyncCommittee. That is fixture-specific evidence only and MUST NOT be used to set the private target deployment's `SYNC_COMMITTEE_SIZE`.

Observed SP1 execution/core-proof results included:

```text
BeaconBlockHeader SSZ root             67,420 cycles
SyncCommittee SSZ root              9,472,104 cycles
slot/epoch/period                       9,459 cycles
fork/domain                            34,353 cycles
signing root                          112,937 cycles
participant selection             10,424,058 cycles
BLS FastAggregateVerify           13,894,608 cycles (execute passed; proof memory-limited)
generic SSZ branch                    62,551 cycles
finality branch                       244,538 cycles
next committee branch              9,708,093 cycles
previous trust digest                  24,303 cycles
trust transition                       42,398 cycles
full Trust Update integration      24,376,167 cycles (execute passed; proof not run under memory waiver)
```

## 30.2 Settlement POC evidence

```text
Settlement skeleton                    33,549 cycles
trust reachability                     36,449 cycles
optimistic header authentication   14,193,554 cycles (execute passed; proof memory-limited)
ExecutionPayloadHeader SSZ            361,544 cycles
execution branch                      495,900 cycles
authenticated execution outputs       492,184 cycles
settlement account MPT                 54,828 cycles
settlement storage MPT                 49,630 cycles
synthetic settlement slot derivation   56,054 cycles
synthetic batch acceptance             85,079 cycles
synthetic K -> R_K binding             86,212 cycles
```

The last three values used a synthetic POC settlement profile. Production requires Section 24.3-24.5.

## 30.3 Membership POC evidence

```text
Membership skeleton                    40,439 cycles
trust-anchor binding                   24,719 cycles
IBC path canonicalization              29,768 cycles
IBC storage slot                       49,945 cycles
RPC address/key binding                55,426 cycles
native tree key                        56,066 cycles
native leaf                            65,910 cycles
native Merkle path                    397,505 cycles
R_K root binding                      413,450 cycles
application-value decode              410,199 cycles
value equality                        412,040 cycles
request/public binding                462,821 cycles
full Membership integration           462,812 cycles
mock exact-schema RPC compatibility   456,701 cycles
```

A final SP1 Groth16/BN254 Membership proof was generated and locally verified in the POC environment. The recorded proof fixture was 356 encoded proof bytes with 384 public-value bytes.

The full Membership negative/malformed suite and controlled performance benchmark were outside the POC scope; this specification makes both deterministic suites mandatory.

## 30.4 Related non-normative reference implementation

- [Spectre-RAD reference implementation](https://github.com/jonas089/spectre-rad)

This external repository is an engineering reference only. It does not override any normative requirement in this specification.

---

# 31. Final v1.2 guarantee

A conformant implementation establishes four distinct statements.

### Trust Update

Starting from the exact stored compact Ethereum consensus trust, the guest authenticates the full signing committee against its stored SSZ root, derives the fork/domain/signing root, verifies the sync-committee aggregate BLS signature, proves finalized checkpoint membership in the authenticated BeaconState, proves the next sync committee in the same authenticated state, and derives the next compact trust state. The destination contract binds the proof to its current stored trust before replacing that state.

### Settlement Update

Starting from the exact stored consensus trust, the guest authenticates a recent Beacon header with the reachable trusted sync committee, authenticates the execution payload header by its SSZ execution branch, verifies the configured settlement account/storage under the resulting Ethereum state root, authenticates the exact accepted state for batch K, and derives/authenticates the corresponding Prividium native state root R_K. The destination stores K -> R_K without modifying finalized consensus trust.

### Membership

Starting from a destination-accepted K -> R_K, the guest independently derives the exact IBC storage location, derives the v0.20.8 native tree key, verifies the native BLAKE2s Merkle witness, requires the reconstructed root to equal R_K, decodes the authenticated application value, and requires it to equal the exact expected value from the IBC request. Solidity binds the proof to the stored accepted root and exact request context.

### Non-Membership

Starting from a destination-accepted K -> R_K, the guest independently derives the exact IBC storage location, verifies the exact pinned native absent-key proof under R_K, and enforces the configured application absence predicate. No Host/RPC zero, missing field, or parser error is accepted as absence.

The trust boundary is therefore:

```text
RPC / Beacon API / Host / relayer / prover witness
    -> untrusted data

SP1 guest
    -> cryptographic verification and deterministic derivation

Destination light-client contract
    -> exact VKey + stored-state + IBC-request binding
```

Any implementation that weakens one of these bindings is non-conformant with v1.
