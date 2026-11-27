#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <source-profile.json> <output-vkeys.json>" >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=$(realpath -- "$1")
output=$2
output_dir=$(realpath -m -- "$(dirname -- "$output")")
mkdir -p -- "$output_dir"
output=$(realpath -m -- "$output")
temporary=$(mktemp "$output_dir/vkeys.XXXXXX")
generated_profile=$(mktemp "$output_dir/source-profile.XXXXXX")
trap 'rm -f -- "$temporary" "$generated_profile"' EXIT

export PRIVIDIUM_SOURCE_PROFILE="$profile"
"$repo_root/scripts/build-sp1.sh" >/dev/null
elf_dir="$repo_root/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"

profile_output=$(
  cargo run --quiet --locked --offline \
    --manifest-path "$repo_root/Cargo.toml" \
    -p prividium-source-profile --bin profilec -- \
    "$profile" "$generated_profile"
)
source_profile_id=${profile_output#SOURCE_PROFILE_ID=}
if [[ ! $source_profile_id =~ ^0x[0-9a-f]{64}$ ]]; then
  echo "profile compiler returned an invalid SourceProfile ID" >&2
  exit 1
fi

derive_vkey() {
  local program=$1
  local elf="$elf_dir/prividium-$program-program"
  local command_output
  local keys

  if ! command_output=$(cargo prove vkey --elf "$elf" 2>&1); then
    printf '%s\n' "$command_output" >&2
    echo "failed to derive the $program VKey" >&2
    return 1
  fi

  mapfile -t keys < <(
    printf '%s\n' "$command_output" \
      | grep -E '^0x[0-9a-fA-F]{64}$'
  )
  if [[ ${#keys[@]} -ne 1 ]]; then
    printf '%s\n' "$command_output" >&2
    echo "expected exactly one VKey for $program" >&2
    return 1
  fi

  printf '%s\n' "${keys[0],,}"
}

trust_vkey=$(derive_vkey trust-update)
settlement_vkey=$(derive_vkey settlement-update)
membership_vkey=$(derive_vkey membership)
non_membership_vkey=$(derive_vkey non-membership)

if [[ $(printf '%s\n' \
  "$trust_vkey" \
  "$settlement_vkey" \
  "$membership_vkey" \
  "$non_membership_vkey" | sort -u | wc -l) -ne 4 ]]; then
  echo "the four program VKeys must be distinct" >&2
  exit 1
fi

jq -n \
  --arg source_profile_id "$source_profile_id" \
  --arg trust_vkey "$trust_vkey" \
  --arg settlement_vkey "$settlement_vkey" \
  --arg membership_vkey "$membership_vkey" \
  --arg non_membership_vkey "$non_membership_vkey" \
  --arg trust_elf "$(sha256sum "$elf_dir/prividium-trust-update-program" | awk '{print $1}')" \
  --arg settlement_elf "$(sha256sum "$elf_dir/prividium-settlement-update-program" | awk '{print $1}')" \
  --arg membership_elf "$(sha256sum "$elf_dir/prividium-membership-program" | awk '{print $1}')" \
  --arg non_membership_elf "$(sha256sum "$elf_dir/prividium-non-membership-program" | awk '{print $1}')" '
  {
    "trust-update": {
      sourceProfileId: $source_profile_id,
      elfSha256: ("0x" + $trust_elf),
      programVKey: $trust_vkey
    },
    "settlement-update": {
      sourceProfileId: $source_profile_id,
      elfSha256: ("0x" + $settlement_elf),
      programVKey: $settlement_vkey
    },
    membership: {
      sourceProfileId: $source_profile_id,
      elfSha256: ("0x" + $membership_elf),
      programVKey: $membership_vkey
    },
    "non-membership": {
      sourceProfileId: $source_profile_id,
      elfSha256: ("0x" + $non_membership_elf),
      programVKey: $non_membership_vkey
    }
  }' >"$temporary"

mv -- "$temporary" "$output"
echo "Wrote reviewed ELF/VKey candidates to $output"
