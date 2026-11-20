# Prividium Router E2E tests

This suite exercises the Prividium light client through the real LFDT IBC
`ICS26Router`. It complements the contract unit tests by covering the
integration boundary used by a relayer:

- client registration and Router-mediated Settlement updates;
- packet receipt through Membership verification;
- packet timeout through Non-Membership verification;
- rejection of packet proofs before their Settlement batch is accepted; and
- Router commitment and application-callback state changes.

The suite uses a mock SP1 verifier so it remains fast and deterministic. The
proof public values, Router path construction, client authorization, accepted
batch state, packet commitments, and callbacks are all exercised without
mocking. Real Groth16 and connected-chain testing remains part of the release
acceptance procedure in `docs/TESTING.md`.

## Run

Prepare the normal contract dependency first:

```bash
./scripts/install-contract-deps.sh
```

Check out the reviewed LFDT IBC contracts commit and install its Solidity
dependencies. Then pass the checkout root to the runner:

```bash
cd /path/to/ibc-contracts/ibc-solidity
bun install --frozen-lockfile

cd /path/to/zk-light-client-prividium
IBC_CONTRACTS_DIR=/path/to/ibc-contracts ./e2e/scripts/run-router-e2e.sh
```

The runner rejects an IBC checkout whose `HEAD` is not the pinned commit. Set
`IBC_SOLIDITY_NODE_MODULES` only when the dependencies are installed in a
separate reviewed checkout.
