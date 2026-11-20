# Linea (Maru QBFT) Light Client

> [!WARNING]
> This light client is a proof of concept. It has not been audited.

This module contains `LineaLightClient.sol`, a Solidity light client for [Linea](https://linea.build). Linea's consensus client, [Maru](https://github.com/Consensys/linea-monorepo/tree/main/maru), runs QBFT with a single validator over beacon blocks that carry an execution payload. The client is modelled on [`BesuLightClient`](../besu/README.md) and shares its storage model, trust level, misbehaviour handling and membership proofs. This document covers what differs.

## What the validators sign

A Besu QBFT validator seals an execution block header. A Maru validator seals a **beacon block header**:

```solidity
struct BeaconBlockHeader {
    uint64 number;
    uint32 round;
    uint64 timestamp;
    address proposer;
    bytes32 parentRoot;
    bytes32 stateRoot;
    bytes32 bodyRoot;
}
```

The commit seal digest is the keccak256 hash of the header's RLP encoding `[number, round, timestamp, [proposer], parentRoot, stateRoot, bodyRoot]`. Maru writes `number`, `round` and `timestamp` as fixed-width 8, 4 and 8-byte strings rather than minimal RLP integers, so the encoding is always 146 bytes and the light client builds it from the struct instead of taking header RLP.

The header does not contain the execution state root or the validator set. It commits to both:

- `bodyRoot` is the keccak256 hash of the RLP-encoded beacon block body `[prevCommitSeals, executionPayload]`. The execution payload holds the execution block number, timestamp and state root.
- `stateRoot` is the keccak256 hash of the RLP-encoded beacon state `[header, validators]`, where the header has a zero `stateRoot`. The validators are those that seal the block.

`BeaconBlock.sol` implements these encodings. They mirror Maru's [RLP serializers](https://github.com/Consensys/linea-monorepo/tree/main/maru/serialization/src/main/kotlin/maru/serialization/rlp) and were checked against blocks of Maru `1.6.0`.

## Consensus states

```solidity
struct ConsensusState {
    uint64 timestamp;
    bytes32 stateRoot;
    address[] validators;
}
```

Consensus states are keyed by the **execution block number** and hold the execution payload's timestamp and state root, with the validator set of the beacon block that carried the payload. The execution values are the ones that matter to IBC: the counterparty `ICS26Router` checks packet timeouts against the execution `block.timestamp`, and `eth_getProof` proves against the execution state root at an execution block number.

The beacon block number and the beacon header timestamp are only used in the commit seal digest. Maru does not require the header timestamp to equal the execution payload timestamp, and the two were observed to differ by a second on a devnet.

As in the Besu client, only `keccak256(abi.encode(ConsensusState))` is stored per height, and every message carries the preimage of the consensus state it relies on.

## `updateClient(bytes)` ABI

`updateClient` expects `abi.encode(ILineaLightClientMsgs.MsgUpdateClient)`:

```solidity
struct MsgUpdateClient {
    BeaconBlockHeader header;
    bytes bodyRlp;
    address[] validators;
    bytes[] commitSeals;
    IICS02ClientMsgs.Height trustedHeight;
    ConsensusState consensusStatePreimage;
}
```

- `header`: the sealed beacon block header.
- `bodyRlp`: the full RLP-encoded beacon block body. It must hash to `header.bodyRoot`, or the update reverts with `BodyRootMismatch`.
- `validators`: the validator set of the block in strictly ascending order. The beacon state root derived from it must equal `header.stateRoot`, or the update reverts with `BeaconStateRootMismatch`. A relayer therefore cannot shrink the set to lower the quorum or swap in validators of its own.
- `commitSeals`: 65-byte `r || s || v` signatures over the header hash, ordered by recovered signer address in strictly ascending order, with `v` set to 27 or 28. Maru encodes the recovery id as 0 or 1, so the submitter must add 27.
- `trustedHeight` and `consensusStatePreimage`: as in the Besu client.

On update, the contract:

1. checks `bodyRlp` against `header.bodyRoot` and decodes the execution block number, timestamp and state root from it,
2. checks `validators` against `header.stateRoot`,
3. checks the trusted consensus state preimage against the stored hash and the trusting period,
4. recovers the commit-seal signers from the header hash,
5. checks trusted-validator overlap against the preimage validators and quorum against `validators`,
6. stores `keccak256(abi.encode(ConsensusState))` for the execution block number.

Trusted overlap and quorum use the same thresholds as the Besu client: at least `max(min(ceil(n * trustLevel), floor(2n / 3)), floor(n / 3) + 1)` of the trusted set, and `ceil(2n / 3)` of the block's set. With Linea's single validator both are 1.

### Update cost

The body contains every transaction of the block, and all of it is calldata, because `bodyRoot` is a flat hash of the body. An empty block's body is 572 bytes. A relayer can choose any block at or after the height it needs to prove, so it can pick a small one, but a busy chain may not offer one. This is the main cost concern of the design.

## Validator set changes

Maru takes its validator set from the fork schedule in its genesis file, so the set only changes at a fork, and a fork can replace any number of validators in one block. Two consequences follow:

- Unlike the Besu client, this client does not treat validator sets that differ by more validators than their height difference as misbehaviour. There is no `InvalidValidatorSetChange`.
- An update across a fork still needs the trust level's worth of overlap. Replacing the single validator outright leaves no trusted signer, so the client cannot follow the chain and a new client is needed. A handover through a fork whose set holds both validators keeps the client updatable: `{A}` to `{A, B}` needs both seals for quorum, and `{A, B}` to `{B}` needs one trusted seal.

## Misbehaviour

`misbehaviour(bytes)` takes the same `MsgSubmitMisbehaviour` envelope as the Besu client, with `ConflictingConsensusStates` and `ConflictingHeaders` evidence. The client freezes on:

- `DoubleSign`: two validly sealed blocks derive different consensus states at the same execution block number.
- `TimeNonMonotonicity`: execution timestamps do not increase with the execution block number.
- `SubSecondBlockTime`: execution timestamps increase by less than one second per block. Execution timestamps are in whole seconds and strictly increase, and Maru's block time is configured in whole seconds.

## Membership / non-membership proofs

Identical to the Besu client: `msg_.proof` is `abi.encode(ILineaLightClientMsgs.MembershipProof)` with the consensus state preimage, the `eth_getProof` account proof of the counterparty `ICS26Router` and the storage proof of the commitment slot. The merkle prefix is `[abi.encodePacked(counterpartyRouter), abi.encodePacked(IBCSTORE_STORAGE_SLOT), bytes("")]`. See the [Besu client's README](../besu/README.md#membership--non-membership-proofs).

Linea execution blocks carry a standard Merkle Patricia state root, and `eth_getProof` on Linea mainnet returns account proofs under it. The sparse Merkle trie that Linea's prover uses, served by `linea_getProof`, is not involved.

## Open questions

- **Finality.** Blocks sealed by Maru's validator are final for QBFT but are soft-finalized from Ethereum's point of view until their proof lands on L1. This client trusts the Maru validator set, as the Besu client trusts a Besu validator set.
- **Empty blocks.** Linea does not produce empty blocks, so the chain's time only advances when it has transactions. Timeouts of packets sent to Linea need a Linea block at or after the timeout.
- **Forks.** The client reads execution payload fields by position. A Maru fork that changes the header or body encoding needs a new client.

## Tests

- `test/linea/MaruSimSuite.t.sol` runs scenarios against an in-process Maru chain simulator, `test/linea/utils/MaruSimSuite.sol`.
- `test/linea/LineaIntegration.t.sol` runs the ICS26 integration suites on Linea light clients.
- `test/linea/LineaLightClientFixture.t.sol` verifies blocks and proofs captured from a live Maru and Besu network. Regenerate the fixture with `just solidity::generate-fixtures-linea`.
