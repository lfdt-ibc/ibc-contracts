#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
elf_dir="$repo_root/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"

sha256sum \
  "$elf_dir/prividium-trust-update-program" \
  "$elf_dir/prividium-settlement-update-program" \
  "$elf_dir/prividium-membership-program" \
  "$elf_dir/prividium-non-membership-program"
