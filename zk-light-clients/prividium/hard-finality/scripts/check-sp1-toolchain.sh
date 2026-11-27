#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# SP1's CLI does not print its release semver. Pin the build revision emitted
# by the official v6.7.0 installer together with its guest rustc version.
expected_prove_revision="cd7850d"
expected_succinct_rustc="rustc 1.94.0-dev"

prove_version=$(cargo prove --version)
succinct_rustc=$(rustc +succinct --version)

if [[ "$prove_version" != *"($expected_prove_revision "* ]]; then
  printf 'wrong SP1 CLI: expected v6.7.0 revision %s, got: %s\n' \
    "$expected_prove_revision" "$prove_version" >&2
  printf 'install the pinned CLI with: sp1up --version v6.7.0\n' >&2
  exit 1
fi

if [[ "$succinct_rustc" != "$expected_succinct_rustc" ]]; then
  printf 'wrong SP1 guest rustc: expected %s, got: %s\n' \
    "$expected_succinct_rustc" "$succinct_rustc" >&2
  printf 'reinstall the pinned toolchain with: sp1up --version v6.7.0\n' >&2
  exit 1
fi

printf '%s\n%s\n' "$prove_version" "$succinct_rustc"
