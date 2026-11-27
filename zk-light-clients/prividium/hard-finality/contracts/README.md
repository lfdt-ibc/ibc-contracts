# Solidity light client

The Solidity package contains the destination light client, strict public-value
decoders, state-transition helpers, mock-verifier tests, and E2E scripts for
the four SP1 programs.

## Contract responsibilities

`PrividiumZKLightClient`:

- stores finalized Beacon and sync-committee trust;
- stores accepted L1 batch, native-root, and timestamp tuples;
- routes Trust, Settlement, Membership, and Non-Membership to distinct VKeys;
- verifies SP1 before changing state;
- rejects conflicting accepted-batch replays;
- binds Membership and Non-Membership to Router path/value requests;
- returns the Settlement-authenticated source timestamp; and
- restricts update and packet verification calls to `IBC_ROUTER`.

The package mirrors the inspected upstream IBC light-client interface. A
production release must pin and test its exact Router version and path shape.

## Toolchain and dependencies

`foundry.toml` pins Solidity 0.8.28, London EVM, optimizer enabled, and 200
runs. Install the reviewed SP1 contracts with:

```bash
cd ..
./scripts/install-contract-deps.sh
cd contracts
```

The expected `sp1-contracts` revision is
`d3629729c3216eb51bd4859d027a8eb729399fa4`. The Groth16 verifier hash is:

```text
0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696
```

## Tests

```bash
forge fmt --check
forge test -vvv
```

The unit suite uses `MockVerifier`; it does not generate or cryptographically
verify Groth16 proofs. Real proof acceptance must also be tested against the
deployed SP1 gateway.

## E2E scripts

| Script | Purpose |
| --- | --- |
| `DeployTrustUpdateE2E.s.sol` | Deploys a local client and validates a Trust fixture/profile binding |
| `DeploySettlementE2E.s.sol` | Deploys a local client at bootstrap trust for Settlement testing |
| `SubmitTrustUpdateE2E.s.sol` | Submits Trust Update and checks every resulting trust field |
| `SubmitSettlementUpdateE2E.s.sol` | Accepts one batch/root/timestamp without changing trust |
| `SubmitMembershipE2E.s.sol` | Verifies one expected value against an accepted batch |
| `SubmitNonMembershipE2E.s.sol` | Verifies one absent path against an accepted batch |

Proof generation is separate so witnesses, public values, proof bytes,
transactions, and post-state can be inspected independently.

## Production warning

The deployment scripts are E2E helpers. They deploy a fresh verifier gateway,
leave its route unfrozen, and bind `IBC_ROUTER` to the broadcaster EOA. Do
not use that behavior for production.

A production deployment must provide the actual Router address, use the
reviewed verifier-gateway governance policy, validate all four VKeys and the
SourceProfile, read every deployed field back from chain, and register or
migrate the client through Router governance. See
[`../docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).
