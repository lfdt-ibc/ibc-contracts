# Real local ZKsync OS v0.20.8 proof vectors

These fixtures were returned by the real `zks_getProof` and
`unstable_getBatchByBlockNumber` handlers in ZKsync OS server `v0.20.8`, commit
`dbb5c03d4a94ceb1acea9f79242590f354660239`. They are not mocked or assembled
from the Rust fixture types.

## Environment

- Official `x86_64-unknown-linux-gnu` v0.20.8 release binary, SHA-256
  `87002587ca92358ab3f171da23719d96d87e6636d6c01650bc0519a2b117b1a7`.
- The exact `Cargo.lock` and `local-chains/v30.2` data at the pinned commit.
- Foundry/Anvil `1.5.1-stable`.
- L1: the pinned `local-chains/v30.2/l1-state.json.gz` snapshot loaded into
  Anvil on port 8545.
- L2: `local-chains/local_dev.yaml` followed by
  `local-chains/v30.2/default/config.yaml`, chain ID 6565, RPC port 3050.
- Local development fake FRI/SNARK provers were enabled by the pinned config.
  This does not replace a real proving campaign; the RPC handler, state tree,
  batch pipeline, and settlement-contract writes were the real v0.20.8 code.

The minimum service topology was one Anvil L1 plus one server process. The
pinned repository documents this topology in `run_local.sh` and
`local-chains/v30.2/default/README.md`.

## Controlled state

The test deployed this creation bytecode at L2 block 3:

```text
0x6007600c60003960076000f360003560005500
```

Its seven-byte runtime is `PUSH1 0; CALLDATALOAD; PUSH1 0; SSTORE; STOP`, so
the only application storage location it can write is slot zero. The deployed
address was `0xe441cf0795af14ddb9f7984da85cd36db1b8790d`.

At block/batch 4, slot zero contained
`0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff1234`.
Slot `0xff..ff` had provably never been written by this contract. At block/batch
5, slot zero was updated to zero.

## Fixture layout

- `raw-response.json` is the compact response body returned by
  `zks_getProof` and is preserved without field rewriting.
- `raw-batch-response.json` is the compact response body returned by
  `unstable_getBatchByBlockNumber` where applicable.
- `normalized.json` records derived values and experiment provenance
  separately from raw RPC data.
- The compression case references the never-existing raw response and records
  its separate derived assertions in `compressed-proof/normalized.json`.
- The never-existing and existing-nonzero cases share the same batch-4 raw
  response; it is stored once under `existing-nonzero`.

## Root correspondence observed locally

```text
batch 4:
  native root       0x1efd73ca324557ff31d344658562e41262281781c16020ba90ed12b79c56950b
  state commitment  0xd3ec308c0eee7ab0154ef61aa094f8c3e4e3c3f1a3bbcabcd05ab351fe2c4122
  StoredBatch hash  0xff703b2c633721667d0cf9c73cec52f4b1c37ceb7f00adb1eabedacf47bbaf20

batch 5:
  native root       0x931b17233867e41047e3f1fb4a3400647ad8eefcb2d495824918a2916c662932
  state commitment  0xb9af383b2a2a9ff142363956da8ed0349ab104dd10dfdc2ad6418c35fc438181
  StoredBatch hash  0xebca5304715691bf4533d3102c891f2923e3a5df1f706482f50263c0f985e9d1
```

The Bridgehub address from the pinned config was
`0xd8f8df05efacd52f28cdf11be22ce3d6ae0fabf7`; its `getZKChain(6565)` result
was diamond proxy `0x18f438bc08d755e164a7ae7c077e2ea93b0179ef`.
For both batches, the locally computed
`keccak256(abi.encode(StoredBatchInfo))` exactly equalled that proxy's
`storedBatchHash(batchNumber)`.

## Scope

These fixtures freeze the pinned native-tree algorithm, v0.20.8 RPC wire
variants, zero-versus-missing behavior, proof compression, and local
state-commitment/settlement transformation. They do not establish the real
Prividium deployment's state, retention, contract layout, accepted settlement
root, or IBC application absence predicate.
