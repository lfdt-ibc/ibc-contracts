#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
ibc_contracts_dir=${IBC_CONTRACTS_DIR:-}
expected_ibc_commit=a051217d31add33ad4b7affb0d72bd12d933b88d
forge_bin=${FORGE_BIN:-forge}

if [[ -z "$ibc_contracts_dir" ]]; then
  echo "IBC_CONTRACTS_DIR must point to a reviewed lfdt-ibc/ibc-contracts checkout" >&2
  exit 1
fi

ibc_contracts_dir=$(cd -- "$ibc_contracts_dir" && pwd)
ibc_solidity_dir="$ibc_contracts_dir/ibc-solidity"
ibc_node_modules=${IBC_SOLIDITY_NODE_MODULES:-"$ibc_solidity_dir/node_modules"}

command -v "$forge_bin" >/dev/null 2>&1 || {
  echo "forge is required (or set FORGE_BIN to its absolute path)" >&2
  exit 1
}

actual_ibc_commit=$(git -C "$ibc_contracts_dir" rev-parse HEAD)
if [[ "$actual_ibc_commit" != "$expected_ibc_commit" ]]; then
  echo "wrong ibc-contracts revision: expected $expected_ibc_commit, got $actual_ibc_commit" >&2
  exit 1
fi
if [[ -n "$(git -C "$ibc_contracts_dir" status --porcelain -- ibc-solidity/contracts)" ]]; then
  echo "ibc-solidity/contracts contains uncommitted changes; use a clean reviewed checkout" >&2
  exit 1
fi

for dependency in \
  "$ibc_solidity_dir/contracts/ICS26Router.sol" \
  "$ibc_node_modules/@openzeppelin/contracts" \
  "$ibc_node_modules/@openzeppelin/contracts-upgradeable" \
  "$ibc_node_modules/@uniswap/permit2"; do
  if [[ ! -e "$dependency" ]]; then
    echo "missing E2E dependency: $dependency" >&2
    echo "install ibc-solidity dependencies before running the suite" >&2
    exit 1
  fi
done

"$forge_bin" test \
  --root "$repo_root/e2e/solidity" \
  --remappings "@ibc-contracts/=$ibc_solidity_dir/contracts/" \
  --remappings "@openzeppelin-contracts/=$ibc_node_modules/@openzeppelin/contracts/" \
  --remappings "@openzeppelin-upgradeable/=$ibc_node_modules/@openzeppelin/contracts-upgradeable/" \
  --remappings "@openzeppelin/=$ibc_node_modules/@openzeppelin/" \
  --remappings "@uniswap/=$ibc_node_modules/@uniswap/" \
  -vvv
