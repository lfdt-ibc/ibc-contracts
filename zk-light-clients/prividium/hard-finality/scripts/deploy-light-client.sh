#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/deploy-light-client.sh [SOURCE_PROFILE.json] [INITIAL_TRUST.json] [PROGRAM_VKEYS.json]

Defaults:
  SourceProfile: release/source-profile.json
  initial trust: release/initial-trust.json
  VKey manifest: release/program-vkeys.json

Required environment variables:
  PRIVATE_KEY
  DESTINATION_RPC_URL
  DESTINATION_CHAIN_ID
  IBC_ROUTER
  SP1_VERIFIER_GATEWAY
  CONFIRM_DEPLOYMENT=YES

Optional environment variables:
  PRIVIDIUM_ELF_DIR
    Defaults to target/elf-compilation/riscv64im-succinct-zkvm-elf/release.

The script validates the SourceProfile, initial Beacon trust, four ELFs/VKeys,
destination chain, Router, and SP1 verifier route before broadcasting.
Router registration or migration is a separate governance operation.
EOF
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  usage
  exit 0
fi
if [[ $# -gt 3 ]]; then
  usage >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=${1:-"$repo_root/release/source-profile.json"}
initial_trust=${2:-"$repo_root/release/initial-trust.json"}
vkeys=${3:-"$repo_root/release/program-vkeys.json"}
elf_directory=${PRIVIDIUM_ELF_DIR:-"$repo_root/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"}

for command in awk cargo cast forge jq realpath sha256sum; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required" >&2
    exit 1
  }
done

require_environment() {
  local name=$1
  if [[ -z ${!name:-} ]]; then
    echo "$name is required" >&2
    exit 2
  fi
}

for name in \
  PRIVATE_KEY \
  DESTINATION_RPC_URL \
  DESTINATION_CHAIN_ID \
  IBC_ROUTER \
  SP1_VERIFIER_GATEWAY \
  CONFIRM_DEPLOYMENT; do
  require_environment "$name"
done

if [[ $CONFIRM_DEPLOYMENT != YES ]]; then
  echo "Set CONFIRM_DEPLOYMENT=YES only after reviewing every deployment input" >&2
  exit 2
fi

for file in "$profile" "$initial_trust" "$vkeys"; do
  if [[ ! -f $file || -L $file ]]; then
    echo "deployment input must be a regular, non-symlink file: $file" >&2
    exit 2
  fi
done
profile=$(realpath -- "$profile")
initial_trust=$(realpath -- "$initial_trust")
vkeys=$(realpath -- "$vkeys")
elf_directory=$(realpath -- "$elf_directory")

address_pattern='^0x[0-9a-fA-F]{40}$'
zero_address=0x0000000000000000000000000000000000000000
for name in IBC_ROUTER SP1_VERIFIER_GATEWAY; do
  if [[ ! ${!name} =~ $address_pattern || ${!name,,} == $zero_address ]]; then
    echo "$name must be a nonzero 20-byte 0x-prefixed address" >&2
    exit 2
  fi
done
if [[ ! $PRIVATE_KEY =~ ^0x[0-9a-fA-F]{64}$ \
  || ${PRIVATE_KEY,,} == 0x0000000000000000000000000000000000000000000000000000000000000000 ]]; then
  echo "PRIVATE_KEY must be a nonzero 32-byte 0x-prefixed key" >&2
  exit 2
fi
if [[ ! $DESTINATION_CHAIN_ID =~ ^[1-9][0-9]*$ ]]; then
  echo "DESTINATION_CHAIN_ID must be a positive decimal integer" >&2
  exit 2
fi

temporary_directory=$(mktemp -d /tmp/prividium-l1-deploy.XXXXXX)
cleanup() {
  if [[ -d $temporary_directory && $temporary_directory == /tmp/prividium-l1-deploy.* ]]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT

profile_output=$(
  cargo run --quiet --locked --offline \
    --manifest-path "$repo_root/Cargo.toml" \
    -p prividium-source-profile --bin profilec -- \
    "$profile" "$temporary_directory/generated-source-profile.rs"
)
source_profile_id=${profile_output#SOURCE_PROFILE_ID=}
if [[ ! $source_profile_id =~ ^0x[0-9a-f]{64}$ ]]; then
  echo "profile compiler returned an invalid SourceProfile ID" >&2
  exit 1
fi

sync_committee_size=$(jq -er '.consensus.syncCommitteeSize' "$profile")
if [[ ! $sync_committee_size =~ ^[1-9][0-9]*$ ]]; then
  echo "SourceProfile sync committee size must be a positive integer" >&2
  exit 2
fi

PRIVIDIUM_SOURCE_PROFILE="$profile" \
  cargo run --quiet --locked --offline \
    --manifest-path "$repo_root/tooling/proof-api/Cargo.toml" \
    --bin prividium-validate-initial-trust -- \
    "$initial_trust" \
    "$source_profile_id" \
    "$sync_committee_size" \
    >/dev/null

ibc_store=$(jq -er '.prividiumL2.ibcStoreAddress' "$profile")
absence_profile_id=$(jq -er '.prividiumL2.absenceProfileId' "$profile")
if [[ ! $ibc_store =~ $address_pattern || ${ibc_store,,} == $zero_address ]]; then
  echo "SourceProfile contains an invalid IBC store address" >&2
  exit 2
fi
if [[ ! $absence_profile_id =~ ^[1-9][0-9]*$ || ${#absence_profile_id} -gt 10 ]]; then
  echo "SourceProfile absenceProfileId must be a nonzero uint32" >&2
  exit 2
fi
if (( absence_profile_id > 4294967295 )); then
  echo "SourceProfile absenceProfileId exceeds uint32" >&2
  exit 2
fi

jq -e \
  --arg profile "${source_profile_id,,}" '
    (.purpose == "reviewed production initial trust anchor")
    and (.finalizedBeaconSlot | type == "number" and . > 0)
    and (.finalizedBeaconHeaderRoot
         | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    and (.currentSyncCommitteeRoot
         | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    and (.nextSyncCommitteeRoot
         | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    and (.nextSyncCommitteeKnown | type == "boolean")
    and ((.sourceProfileId | ascii_downcase) == $profile)
    and (.currentSyncCommittee.pubkeys | type == "array" and length > 0)
    and (.currentSyncCommittee.aggregatePubkey
         | type == "string" and test("^0x[0-9a-fA-F]{96}$"))
    and (all(.currentSyncCommittee.pubkeys[];
         type == "string" and test("^0x[0-9a-fA-F]{96}$")))
    and (if .nextSyncCommitteeKnown
         then (.nextSyncCommitteeRoot | test("^0x(?!0{64}$)[0-9a-fA-F]{64}$"))
         else ((.nextSyncCommitteeRoot | ascii_downcase)
               == "0x0000000000000000000000000000000000000000000000000000000000000000")
         end)
  ' "$initial_trust" >/dev/null || {
  echo "initial trust is malformed or does not match the SourceProfile" >&2
  exit 2
}

jq -e --arg profile "${source_profile_id,,}" '
  (keys | sort) == ["membership", "non-membership", "settlement-update", "trust-update"]
  and ([.[] | .programVKey | ascii_downcase] | unique | length) == 4
  and all(.[];
    ((.sourceProfileId | ascii_downcase) == $profile)
    and (.programVKey | type == "string" and test("^0x[0-9a-fA-F]{64}$"))
    and ((.programVKey | ascii_downcase)
         != "0x0000000000000000000000000000000000000000000000000000000000000000")
    and (.elfSha256 | type == "string" and test("^0x[0-9a-fA-F]{64}$")))
  ' "$vkeys" >/dev/null || {
  echo "VKey manifest must contain four programs built from the selected SourceProfile" >&2
  exit 2
}

for program in trust-update settlement-update membership non-membership; do
  elf="$elf_directory/prividium-$program-program"
  if [[ ! -f $elf || -L $elf ]]; then
    echo "reviewed ELF is missing or is a symlink: $elf" >&2
    exit 2
  fi
  expected=$(jq -er --arg program "$program" '.[$program].elfSha256 | ascii_downcase' "$vkeys")
  actual="0x$(sha256sum "$elf" | awk '{print $1}')"
  if [[ $actual != "$expected" ]]; then
    echo "$program ELF does not match program-vkeys.json" >&2
    exit 1
  fi
done

actual_chain_id=$(cast chain-id --rpc-url "$DESTINATION_RPC_URL")
if [[ $actual_chain_id != "$DESTINATION_CHAIN_ID" ]]; then
  echo "destination RPC chain ID mismatch: expected $DESTINATION_CHAIN_ID, got $actual_chain_id" >&2
  exit 1
fi
for address in "$IBC_ROUTER" "$SP1_VERIFIER_GATEWAY"; do
  code=$(cast code "$address" --rpc-url "$DESTINATION_RPC_URL")
  if [[ $code == 0x ]]; then
    echo "destination address has no contract code: $address" >&2
    exit 1
  fi
done

export SOURCE_PROFILE_ID=$source_profile_id
export INITIAL_FINALIZED_SLOT
INITIAL_FINALIZED_SLOT=$(jq -er '.finalizedBeaconSlot' "$initial_trust")
export INITIAL_FINALIZED_ROOT
INITIAL_FINALIZED_ROOT=$(jq -er '.finalizedBeaconHeaderRoot' "$initial_trust")
export INITIAL_CURRENT_COMMITTEE_ROOT
INITIAL_CURRENT_COMMITTEE_ROOT=$(jq -er '.currentSyncCommitteeRoot' "$initial_trust")
export INITIAL_NEXT_COMMITTEE_ROOT
INITIAL_NEXT_COMMITTEE_ROOT=$(jq -er '.nextSyncCommitteeRoot' "$initial_trust")
export INITIAL_NEXT_COMMITTEE_KNOWN
INITIAL_NEXT_COMMITTEE_KNOWN=$(jq -er '.nextSyncCommitteeKnown' "$initial_trust")
export IBC_STORE_ADDRESS=$ibc_store
export ABSENCE_PROFILE_ID=$absence_profile_id
export TRUST_UPDATE_VKEY
TRUST_UPDATE_VKEY=$(jq -er '.["trust-update"].programVKey' "$vkeys")
export SETTLEMENT_UPDATE_VKEY
SETTLEMENT_UPDATE_VKEY=$(jq -er '.["settlement-update"].programVKey' "$vkeys")
export MEMBERSHIP_VKEY
MEMBERSHIP_VKEY=$(jq -er '.membership.programVKey' "$vkeys")
export NON_MEMBERSHIP_VKEY
NON_MEMBERSHIP_VKEY=$(jq -er '.["non-membership"].programVKey' "$vkeys")

printf 'Deploying the hard-finality client with:\n'
printf '  destination chain ID: %s\n' "$DESTINATION_CHAIN_ID"
printf '  ICS26 Router:         %s\n' "$IBC_ROUTER"
printf '  SP1 verifier gateway: %s\n' "$SP1_VERIFIER_GATEWAY"
printf '  SourceProfile ID:     %s\n' "$SOURCE_PROFILE_ID"
printf '  source IBC store:     %s\n' "$IBC_STORE_ADDRESS"
printf '  finalized slot:       %s\n' "$INITIAL_FINALIZED_SLOT"

(
  cd "$repo_root/contracts"
  forge script script/DeployHardFinalityClient.s.sol:DeployHardFinalityClient \
    --rpc-url "$DESTINATION_RPC_URL" \
    --broadcast \
    -vvvv
)

echo "Deployment completed. Record the printed client address and Foundry broadcast receipt."
echo "Register or migrate the Router client only after verifying every on-chain getter."
