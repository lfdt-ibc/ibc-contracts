#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
dependency_dir="$repo_root/contracts/lib/sp1-contracts"
expected_commit=d3629729c3216eb51bd4859d027a8eb729399fa4

command -v git >/dev/null 2>&1 || {
  echo "git is required" >&2
  exit 1
}

if ! git -C "$dependency_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -e "$dependency_dir" ]]; then
    echo "refusing to replace non-Git path: $dependency_dir" >&2
    exit 1
  fi
  git clone --branch v6.1.1 --depth 1 --recurse-submodules \
    https://github.com/succinctlabs/sp1-contracts.git \
    "$dependency_dir"
fi

actual_commit=$(git -C "$dependency_dir" rev-parse HEAD)
if [[ "$actual_commit" != "$expected_commit" ]]; then
  echo "wrong sp1-contracts revision: expected $expected_commit, got $actual_commit" >&2
  exit 1
fi

submodule_status=$(git -C "$dependency_dir" submodule status --recursive)
if grep -Eq '^[-+U]' <<<"$submodule_status"; then
  git -C "$dependency_dir" submodule update --init --recursive
  submodule_status=$(git -C "$dependency_dir" submodule status --recursive)
fi
if grep -Eq '^[-+U]' <<<"$submodule_status"; then
  echo "sp1-contracts has missing or mismatched submodules" >&2
  printf '%s\n' "$submodule_status" >&2
  exit 1
fi
echo "sp1-contracts is pinned at $actual_commit"
