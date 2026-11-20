#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/capture-beacon-bootstrap.sh SOURCE_PROFILE.json [OUTPUT.json]

Required environment variables:
  BEACON_API_URL

Optional environment variables:
  BEACON_API_TOKEN
  BEACON_API_DANGER_ACCEPT_INVALID_TLS_CERTIFICATES  Default: false

OUTPUT.json defaults to release/initial-trust.json. The script writes the raw
Beacon genesis, specification, finalized-header, and light-client bootstrap
responses, plus a SHA-256 file, beside the generated initial-trust artifact.
EOF
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

for command in cargo curl jq realpath sha256sum stat; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required" >&2
    exit 1
  }
done

if [[ -z ${BEACON_API_URL:-} ]]; then
  echo "BEACON_API_URL is required" >&2
  exit 2
fi

accept_invalid_tls=${BEACON_API_DANGER_ACCEPT_INVALID_TLS_CERTIFICATES:-false}
if [[ $accept_invalid_tls != true && $accept_invalid_tls != false ]]; then
  echo "BEACON_API_DANGER_ACCEPT_INVALID_TLS_CERTIFICATES must be true or false" >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=$(realpath -- "$1")
if [[ ! -f $profile || -L $profile ]]; then
  echo "SourceProfile must be a regular, non-symlink file: $profile" >&2
  exit 2
fi

output=${2:-"$repo_root/release/initial-trust.json"}
output_directory=$(realpath -m -- "$(dirname -- "$output")")
output="$output_directory/$(basename -- "$output")"
mkdir -p -- "$output_directory"
for target in \
  "$output" \
  "$output_directory/beacon-genesis.raw.json" \
  "$output_directory/beacon-spec.raw.json" \
  "$output_directory/bootstrap-header.raw.json" \
  "$output_directory/bootstrap.raw.json" \
  "$output_directory/initial-trust-sha256.txt"; do
  if [[ -e $target ]]; then
    echo "refusing to overwrite existing bootstrap evidence: $target" >&2
    exit 2
  fi
done

temporary_directory=$(mktemp -d "$output_directory/.beacon-bootstrap.XXXXXX")
cleanup() {
  if [[ -d $temporary_directory \
    && $temporary_directory == "$output_directory"/.beacon-bootstrap.* ]]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT

header_temporary="$temporary_directory/bootstrap-header.raw.json"
bootstrap_temporary="$temporary_directory/bootstrap.raw.json"
genesis_temporary="$temporary_directory/beacon-genesis.raw.json"
spec_temporary="$temporary_directory/beacon-spec.raw.json"
artifact_temporary="$temporary_directory/initial-trust.json"
generated_profile="$temporary_directory/generated-source-profile.rs"

curl_arguments=(
  --fail-with-body
  --silent
  --show-error
  --max-filesize 16777216
  --header 'Accept: application/json'
)
if [[ -n ${BEACON_API_TOKEN:-} ]]; then
  authorization_file="$temporary_directory/authorization.header"
  (umask 077; printf 'Authorization: Bearer %s\n' "$BEACON_API_TOKEN" >"$authorization_file")
  curl_arguments+=(--header "@$authorization_file")
fi
if [[ $accept_invalid_tls == true ]]; then
  curl_arguments+=(--insecure)
fi

beacon_url=${BEACON_API_URL%/}
curl "${curl_arguments[@]}" \
  "$beacon_url/eth/v1/beacon/genesis" \
  --output "$genesis_temporary"
curl "${curl_arguments[@]}" \
  "$beacon_url/eth/v1/config/spec" \
  --output "$spec_temporary"

jq -e --slurpfile profile "$profile" '
  ((.data.genesis_validators_root | ascii_downcase)
    == ($profile[0].consensus.genesisValidatorsRoot | ascii_downcase))
  and ((.data.genesis_time | tonumber) == $profile[0].consensus.genesisTime)
' "$genesis_temporary" >/dev/null || {
  echo "Beacon genesis does not match the reviewed SourceProfile" >&2
  exit 1
}
jq -e --slurpfile profile "$profile" '
  ((.data.SECONDS_PER_SLOT | tonumber) == $profile[0].consensus.secondsPerSlot)
  and ((.data.SLOTS_PER_EPOCH | tonumber) == $profile[0].consensus.slotsPerEpoch)
  and ((.data.EPOCHS_PER_SYNC_COMMITTEE_PERIOD | tonumber)
       == $profile[0].consensus.epochsPerSyncCommitteePeriod)
  and ((.data.SYNC_COMMITTEE_SIZE | tonumber)
       == $profile[0].consensus.syncCommitteeSize)
  and any($profile[0].consensus.supportedLightClientHeaderSchemas[]; . == "fulu")
' "$spec_temporary" >/dev/null || {
  echo "Beacon specification does not match the reviewed SourceProfile" >&2
  exit 1
}

curl "${curl_arguments[@]}" \
  "$beacon_url/eth/v1/beacon/headers/finalized" \
  --output "$header_temporary"

trusted_beacon_root=$(jq -er '.data.root' "$header_temporary")
if [[ ! $trusted_beacon_root =~ ^0x[0-9a-fA-F]{64}$ \
  || ${trusted_beacon_root,,} == 0x0000000000000000000000000000000000000000000000000000000000000000 ]]; then
  echo "Beacon finalized header returned an invalid root" >&2
  exit 1
fi

curl "${curl_arguments[@]}" \
  "$beacon_url/eth/v1/beacon/light_client/bootstrap/$trusted_beacon_root" \
  --output "$bootstrap_temporary"

if (( $(stat -c %s "$bootstrap_temporary") > 16 * 1024 * 1024 )); then
  echo "Beacon bootstrap response exceeds 16 MiB" >&2
  exit 1
fi

profile_output=$(
  cargo run --quiet --locked --offline \
    --manifest-path "$repo_root/Cargo.toml" \
    -p prividium-source-profile --bin profilec -- \
    "$profile" "$generated_profile"
)
source_profile_id=${profile_output#SOURCE_PROFILE_ID=}
if [[ ! $source_profile_id =~ ^0x[0-9a-f]{64}$ \
  || $source_profile_id == 0x0000000000000000000000000000000000000000000000000000000000000000 ]]; then
  echo "profile compiler returned an invalid SourceProfile ID" >&2
  exit 1
fi

sync_committee_size=$(jq -er '.consensus.syncCommitteeSize' "$profile")
if [[ ! $sync_committee_size =~ ^[1-9][0-9]*$ ]]; then
  echo "SourceProfile sync committee size must be a positive integer" >&2
  exit 1
fi

PRIVIDIUM_SOURCE_PROFILE="$profile" \
  cargo run --quiet --locked --offline \
    --manifest-path "$repo_root/tooling/proof-api/Cargo.toml" \
    --bin prividium-bootstrap-artifact -- \
    "$bootstrap_temporary" \
    "${trusted_beacon_root,,}" \
    "$source_profile_id" \
    "$sync_committee_size" \
    >"$artifact_temporary"

jq -e \
  --arg root "${trusted_beacon_root,,}" \
  --arg profile "${source_profile_id,,}" \
  --argjson size "$sync_committee_size" '
    (.purpose == "reviewed production initial trust anchor")
    and (.finalizedBeaconSlot | type == "number" and . > 0)
    and ((.finalizedBeaconHeaderRoot | ascii_downcase) == $root)
    and ((.sourceProfileId | ascii_downcase) == $profile)
    and (.currentSyncCommittee.pubkeys | length == $size)
    and (.currentSyncCommitteeRoot | test("^0x[0-9a-f]{64}$"))
    and (.nextSyncCommitteeKnown == false)
    and (.nextSyncCommitteeRoot
         == "0x0000000000000000000000000000000000000000000000000000000000000000")
  ' "$artifact_temporary" >/dev/null

install -m 0644 "$header_temporary" \
  "$output_directory/bootstrap-header.raw.json"
install -m 0644 "$bootstrap_temporary" \
  "$output_directory/bootstrap.raw.json"
install -m 0644 "$genesis_temporary" \
  "$output_directory/beacon-genesis.raw.json"
install -m 0644 "$spec_temporary" \
  "$output_directory/beacon-spec.raw.json"
install -m 0644 "$artifact_temporary" "$output"
(
  cd "$output_directory"
  sha256sum "$(basename -- "$output")" >initial-trust-sha256.txt
)

printf 'Finalized Beacon root: %s\n' "${trusted_beacon_root,,}"
printf 'SourceProfile ID: %s\n' "$source_profile_id"
printf 'Sync committee size: %s\n' "$sync_committee_size"
printf 'Initial trust artifact: %s\n' "$output"
printf 'SHA-256 file: %s\n' "$output_directory/initial-trust-sha256.txt"
