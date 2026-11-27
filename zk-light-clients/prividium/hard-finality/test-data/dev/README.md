# Deterministic local-development fixtures

The complete synthetic profile is profiles/example.synthetic.json. The four
end-to-end deterministic witness builders live in
crates/program-logic/src/lib.rs tests and cover:

- a BLS-authenticated Trust Update with finality and next-committee branches;
- a BLS/SSZ/MPT/StoredBatchInfo Settlement Update;
- native membership for a canonical packet-commitment path; and
- two-neighbor native non-membership plus rejection of Existing(0).

They intentionally construct all bytes from fixed constants instead of
depending on wall-clock time, randomness, or a live endpoint. The native-tree
wire regression inputs are preserved separately, unchanged, under
test-data/zksync-native/v0.20.8/local/; those are actual responses from the
pinned v0.20.8 RPC handler, not synthetic JSON.

Host-side normalized witness JSON is produced deterministically with the
prividium-prover build-witness command. Raw RPC bodies are collected without
JSON reserialization with the prividium-prover collect command.
