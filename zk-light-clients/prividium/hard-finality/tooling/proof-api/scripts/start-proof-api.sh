#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

proof_api_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
repo_root=$(cd -- "$proof_api_root/../.." && pwd)

usage() {
  echo "usage: $0 /absolute/path/operator.env" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
env_file=$1
[[ "$env_file" = /* ]] || {
  echo "operator environment file path must be absolute" >&2
  exit 2
}
[[ -f "$env_file" && ! -L "$env_file" ]] || {
  echo "operator environment file must be a regular, non-symlink file: $env_file" >&2
  exit 2
}
[[ $(stat -c '%u' "$env_file") == "$(id -u)" ]] || {
  echo "operator environment file must be owned by the current user: $env_file" >&2
  exit 2
}
if [[ -n $(find "$env_file" -prune -perm /077 -print) ]]; then
  echo "operator environment file must not be accessible by group or other users: $env_file" >&2
  exit 2
fi

# The protected operator file is trusted shell input and may contain quoted
# URLs and paths. Container mode fixes release-artifact and runtime paths so a
# mounted file cannot redirect the entrypoint to an unrelated binary.
container_mode=${PRIVIDIUM_CONTAINER_MODE:-false}
# shellcheck disable=SC1090
source "$env_file"

default() {
  local name=$1
  local value=$2
  if [[ -z ${!name:-} ]]; then
    printf -v "$name" '%s' "$value"
  fi
}

default PRIVIDIUM_BUILD_OPERATOR true
default PRIVIDIUM_CONFIG_PATH "$proof_api_root/config.json"
default PRIVIDIUM_PROOF_API_BINARY "$proof_api_root/target/release/prividium-proof-api"
default PRIVIDIUM_COUNTERPARTY_MERKLE_PREFIX_JSON '["0x"]'
default PRIVIDIUM_SP1_PROOF_TIMEOUT_SECONDS 3600
default PRIVIDIUM_L2_RPC_MAX_RESPONSE_BYTES 16777216
default PRIVIDIUM_L2_RPC_MAX_BATCH_LOOKBACK 2048
default PRIVIDIUM_L1_RPC_MAX_RESPONSE_BYTES 16777216
default PRIVIDIUM_DESTINATION_RPC_MAX_RESPONSE_BYTES 16777216
default PRIVIDIUM_BEACON_MAX_RESPONSE_BYTES 16777216
default PRIVIDIUM_IBC_SUPPORTED_PATH_SHAPE_ID ibc-eureka-v2-terminal-path-v1
default PRIVIDIUM_IBC_STORAGE_PROFILE_ID cosmos-solidity-ibc-eureka-erc7201-v1
default PRIVIDIUM_IBC_MAPPING_BASE_SLOT 0x1260944489272988d9df285149b5aa1b0f48f2136d6f416159f840a3e0747600
default PRIVIDIUM_MAX_CLIENT_ID_BYTES 128
default PRIVIDIUM_ABSENCE_PROFILE_ID 1
default PRIVIDIUM_SLOTS_PER_EPOCH 32
default PRIVIDIUM_EPOCHS_PER_SYNC_COMMITTEE_PERIOD 256
default PRIVIDIUM_TRUST_UPDATE_RECEIPT_TIMEOUT_SECONDS 120
default PRIVIDIUM_TRUST_UPDATE_RECEIPT_POLL_MILLISECONDS 1000
default PRIVIDIUM_TRUST_UPDATE_MAX_GAS 8000000
default PRIVIDIUM_REQUEST_TIMEOUT_SECONDS 1800
default PRIVIDIUM_MAX_CONCURRENT_REQUESTS 4
default PRIVIDIUM_MAX_QUEUED_REQUESTS 16
default PRIVIDIUM_MAX_CONCURRENT_HEIGHT_REQUESTS 16
default PRIVIDIUM_MAX_AUTOMATIC_TRUST_UPDATES 8

[[ $container_mode == true || $container_mode == false ]] || {
  echo "PRIVIDIUM_CONTAINER_MODE must be true or false" >&2
  exit 2
}
if [[ $container_mode == true ]]; then
  PRIVIDIUM_SOURCE_PROFILE=/opt/prividium/source-profile.json
  PRIVIDIUM_SP1_ELF_DIR=/opt/prividium/elfs
  PRIVIDIUM_PROGRAM_VKEYS=/opt/prividium/program-vkeys.json
  PRIVIDIUM_INITIAL_TRUST_PATH=/opt/prividium/initial-trust.json
  PRIVIDIUM_BUILD_OPERATOR=false
  PRIVIDIUM_PROOF_API_BINARY=/usr/local/bin/prividium-proof-api
  PRIVIDIUM_CONFIG_PATH=/var/lib/prividium-proof-api/config.json
fi

required=(
  PRIVIDIUM_SOURCE_PROFILE
  PRIVIDIUM_SP1_ELF_DIR
  PRIVIDIUM_PROGRAM_VKEYS
  PRIVIDIUM_INITIAL_TRUST_PATH
  PRIVIDIUM_BIND_ADDRESS
  PRIVIDIUM_CLIENT_CHAIN_ID
  PRIVIDIUM_CLIENT_ID
  PRIVIDIUM_COUNTERPARTY_CLIENT_ID
  PRIVIDIUM_SP1_NETWORK_RPC_URL
  PRIVIDIUM_SP1_NETWORK_PRIVATE_KEY
  PRIVIDIUM_L2_RPC_URL
  PRIVIDIUM_L2_CHAIN_ID
  PRIVIDIUM_L1_RPC_URL
  PRIVIDIUM_L1_CHAIN_ID
  PRIVIDIUM_BEACON_URL
  PRIVIDIUM_FINALIZED_CHECKPOINT_ROOT
  PRIVIDIUM_SOURCE_PROFILE_ID
  PRIVIDIUM_SYNC_COMMITTEE_SIZE
  PRIVIDIUM_IBC_STORE_ADDRESS
  PRIVIDIUM_IBC_NATIVE_ROOT_PROBE_SLOT
  PRIVIDIUM_DESTINATION_RPC_URL
  PRIVIDIUM_DESTINATION_CHAIN_ID
  PRIVIDIUM_DESTINATION_ROUTER_ADDRESS
  PRIVIDIUM_DESTINATION_VERIFIER_ADDRESS
  PRIVIDIUM_TRUST_UPDATE_REGISTRAR_PRIVATE_KEY
  PRIVIDIUM_SETTLEMENT_DIAMOND_PROXY_ADDRESS
  PRIVIDIUM_SETTLEMENT_STORED_BATCH_HASH_MAPPING_BASE_SLOT
  PRIVIDIUM_SETTLEMENT_TOTAL_BATCHES_EXECUTED_SLOT
)
for name in "${required[@]}"; do
  [[ -n ${!name:-} ]] || {
    echo "required environment variable is empty: $name" >&2
    exit 2
  }
done

for command in jq sha256sum; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 2
  }
done
if [[ $PRIVIDIUM_BUILD_OPERATOR == true ]]; then
  command -v cargo >/dev/null || {
    echo "cargo is required when PRIVIDIUM_BUILD_OPERATOR=true" >&2
    exit 2
  }
fi

for name in \
  PRIVIDIUM_SOURCE_PROFILE \
  PRIVIDIUM_SP1_ELF_DIR \
  PRIVIDIUM_PROGRAM_VKEYS \
  PRIVIDIUM_INITIAL_TRUST_PATH \
  PRIVIDIUM_CONFIG_PATH \
  PRIVIDIUM_PROOF_API_BINARY; do
  [[ ${!name} = /* ]] || {
    echo "$name must be an absolute path" >&2
    exit 2
  }
done
[[ $PRIVIDIUM_BUILD_OPERATOR == true || $PRIVIDIUM_BUILD_OPERATOR == false ]] || {
  echo "PRIVIDIUM_BUILD_OPERATOR must be true or false" >&2
  exit 2
}

require_regular_file() {
  local label=$1
  local path=$2
  [[ -f "$path" && ! -L "$path" ]] || {
    echo "$label must be a regular, non-symlink file: $path" >&2
    exit 2
  }
}

require_regular_file "SourceProfile" "$PRIVIDIUM_SOURCE_PROFILE"
require_regular_file "VKey manifest" "$PRIVIDIUM_PROGRAM_VKEYS"
require_regular_file "initial trust artifact" "$PRIVIDIUM_INITIAL_TRUST_PATH"
[[ -d "$PRIVIDIUM_SP1_ELF_DIR" ]] || {
  echo "ELF directory does not exist: $PRIVIDIUM_SP1_ELF_DIR" >&2
  exit 2
}

jq -e --arg profile_id "${PRIVIDIUM_SOURCE_PROFILE_ID,,}" '
  . as $manifest
  | type == "object"
    and (keys | sort == ["membership", "non-membership", "settlement-update", "trust-update"])
    and (["trust-update", "settlement-update", "membership", "non-membership"] | all(.[];
      . as $name
      | ($manifest[$name].sourceProfileId == $profile_id)
        and ($manifest[$name].elfSha256 | type == "string" and test("^0x[0-9a-f]{64}$"))
        and ($manifest[$name].programVKey | type == "string" and test("^0x[0-9a-f]{64}$"))
    ))
' "$PRIVIDIUM_PROGRAM_VKEYS" >/dev/null || {
  echo "VKey manifest must contain four valid programs built from the configured SourceProfile" >&2
  exit 2
}

check_elf() {
  local manifest_name=$1
  local program=$2
  local path="$PRIVIDIUM_SP1_ELF_DIR/$program"
  require_regular_file "$manifest_name ELF" "$path"
  local expected
  expected=$(jq -er --arg name "$manifest_name" '.[$name].elfSha256' "$PRIVIDIUM_PROGRAM_VKEYS")
  expected=${expected#0x}
  local actual
  actual=$(sha256sum "$path")
  actual=${actual%% *}
  [[ "$actual" == "$expected" ]] || {
    echo "ELF hash mismatch for $program" >&2
    exit 2
  }
}

check_elf trust-update prividium-trust-update-program
check_elf settlement-update prividium-settlement-update-program
check_elf membership prividium-membership-program
check_elf non-membership prividium-non-membership-program

trust_vkey=$(jq -er '.["trust-update"].programVKey' "$PRIVIDIUM_PROGRAM_VKEYS")
settlement_vkey=$(jq -er '.["settlement-update"].programVKey' "$PRIVIDIUM_PROGRAM_VKEYS")
membership_vkey=$(jq -er '.membership.programVKey' "$PRIVIDIUM_PROGRAM_VKEYS")
non_membership_vkey=$(jq -er '.["non-membership"].programVKey' "$PRIVIDIUM_PROGRAM_VKEYS")
source_profile_sha256=$(sha256sum "$PRIVIDIUM_SOURCE_PROFILE")
source_profile_sha256=${source_profile_sha256%% *}
initial_trust_sha256=$(sha256sum "$PRIVIDIUM_INITIAL_TRUST_PATH")
initial_trust_sha256=${initial_trust_sha256%% *}

jq -e '
  type == "array"
  and length > 0
  and all(.[]; type == "string" and test("^0x(?:[0-9a-f]{2})*$"))
' <<<"$PRIVIDIUM_COUNTERPARTY_MERKLE_PREFIX_JSON" >/dev/null || {
  echo "PRIVIDIUM_COUNTERPARTY_MERKLE_PREFIX_JSON must be a nonempty JSON array of lowercase 0x-prefixed byte strings" >&2
  exit 2
}

install -d -m 700 "$(dirname -- "$PRIVIDIUM_CONFIG_PATH")"
temporary_config=$(mktemp "$(dirname -- "$PRIVIDIUM_CONFIG_PATH")/.prividium-l1-config.XXXXXX")
cleanup() {
  rm -f -- "$temporary_config"
}
trap cleanup EXIT
chmod 600 "$temporary_config"

token_env_name() {
  local value_name=$1
  local output_name=$2
  if [[ -n ${!value_name:-} ]]; then
    printf -v "$output_name" '%s' "$value_name"
  else
    printf -v "$output_name" '%s' ""
  fi
}

token_env_name PRIVIDIUM_L2_RPC_TOKEN l2_token_env
token_env_name PRIVIDIUM_L1_RPC_TOKEN l1_token_env
token_env_name PRIVIDIUM_BEACON_TOKEN beacon_token_env
token_env_name PRIVIDIUM_DESTINATION_RPC_TOKEN destination_token_env
token_env_name PRIVIDIUM_PROOF_API_TOKEN api_token_env

jq -n \
  --arg source_profile_path "$PRIVIDIUM_SOURCE_PROFILE" \
  --arg source_profile_sha256 "$source_profile_sha256" \
  --arg bind_address "$PRIVIDIUM_BIND_ADDRESS" \
  --arg client_chain_id "$PRIVIDIUM_CLIENT_CHAIN_ID" \
  --arg client_id "$PRIVIDIUM_CLIENT_ID" \
  --arg counterparty_client_id "$PRIVIDIUM_COUNTERPARTY_CLIENT_ID" \
  --argjson counterparty_prefix "$PRIVIDIUM_COUNTERPARTY_MERKLE_PREFIX_JSON" \
  --arg prover_url "$PRIVIDIUM_SP1_NETWORK_RPC_URL" \
  --argjson proof_timeout "$PRIVIDIUM_SP1_PROOF_TIMEOUT_SECONDS" \
  --arg l2_url "$PRIVIDIUM_L2_RPC_URL" \
  --argjson l2_chain_id "$PRIVIDIUM_L2_CHAIN_ID" \
  --arg l2_token_env "$l2_token_env" \
  --argjson l2_max_response "$PRIVIDIUM_L2_RPC_MAX_RESPONSE_BYTES" \
  --argjson l2_lookback "$PRIVIDIUM_L2_RPC_MAX_BATCH_LOOKBACK" \
  --arg l1_url "$PRIVIDIUM_L1_RPC_URL" \
  --argjson l1_chain_id "$PRIVIDIUM_L1_CHAIN_ID" \
  --arg l1_token_env "$l1_token_env" \
  --argjson l1_max_response "$PRIVIDIUM_L1_RPC_MAX_RESPONSE_BYTES" \
  --arg beacon_url "$PRIVIDIUM_BEACON_URL" \
  --arg beacon_token_env "$beacon_token_env" \
  --arg checkpoint_root "$PRIVIDIUM_FINALIZED_CHECKPOINT_ROOT" \
  --arg source_profile_id "$PRIVIDIUM_SOURCE_PROFILE_ID" \
  --arg initial_trust_path "$PRIVIDIUM_INITIAL_TRUST_PATH" \
  --arg initial_trust_sha256 "$initial_trust_sha256" \
  --argjson sync_committee_size "$PRIVIDIUM_SYNC_COMMITTEE_SIZE" \
  --argjson slots_per_epoch "$PRIVIDIUM_SLOTS_PER_EPOCH" \
  --argjson epochs_per_period "$PRIVIDIUM_EPOCHS_PER_SYNC_COMMITTEE_PERIOD" \
  --argjson beacon_max_response "$PRIVIDIUM_BEACON_MAX_RESPONSE_BYTES" \
  --arg path_shape "$PRIVIDIUM_IBC_SUPPORTED_PATH_SHAPE_ID" \
  --arg storage_profile "$PRIVIDIUM_IBC_STORAGE_PROFILE_ID" \
  --arg store "$PRIVIDIUM_IBC_STORE_ADDRESS" \
  --arg mapping_slot "$PRIVIDIUM_IBC_MAPPING_BASE_SLOT" \
  --arg native_root_slot "$PRIVIDIUM_IBC_NATIVE_ROOT_PROBE_SLOT" \
  --argjson absence_profile "$PRIVIDIUM_ABSENCE_PROFILE_ID" \
  --argjson max_client_id "$PRIVIDIUM_MAX_CLIENT_ID_BYTES" \
  --arg destination_url "$PRIVIDIUM_DESTINATION_RPC_URL" \
  --argjson destination_chain_id "$PRIVIDIUM_DESTINATION_CHAIN_ID" \
  --arg destination_token_env "$destination_token_env" \
  --argjson destination_max_response "$PRIVIDIUM_DESTINATION_RPC_MAX_RESPONSE_BYTES" \
  --arg destination_router "$PRIVIDIUM_DESTINATION_ROUTER_ADDRESS" \
  --arg destination_verifier "$PRIVIDIUM_DESTINATION_VERIFIER_ADDRESS" \
  --arg trust_vkey "$trust_vkey" \
  --arg settlement_vkey "$settlement_vkey" \
  --arg membership_vkey "$membership_vkey" \
  --arg non_membership_vkey "$non_membership_vkey" \
  --argjson receipt_timeout "$PRIVIDIUM_TRUST_UPDATE_RECEIPT_TIMEOUT_SECONDS" \
  --argjson receipt_poll "$PRIVIDIUM_TRUST_UPDATE_RECEIPT_POLL_MILLISECONDS" \
  --argjson max_gas "$PRIVIDIUM_TRUST_UPDATE_MAX_GAS" \
  --arg diamond "$PRIVIDIUM_SETTLEMENT_DIAMOND_PROXY_ADDRESS" \
  --arg stored_batch_slot "$PRIVIDIUM_SETTLEMENT_STORED_BATCH_HASH_MAPPING_BASE_SLOT" \
  --arg total_batches_executed_slot "$PRIVIDIUM_SETTLEMENT_TOTAL_BATCHES_EXECUTED_SLOT" \
  --arg api_token_env "$api_token_env" \
  --argjson request_timeout "$PRIVIDIUM_REQUEST_TIMEOUT_SECONDS" \
  --argjson concurrent_requests "$PRIVIDIUM_MAX_CONCURRENT_REQUESTS" \
  --argjson queued_requests "$PRIVIDIUM_MAX_QUEUED_REQUESTS" \
  --argjson concurrent_height "$PRIVIDIUM_MAX_CONCURRENT_HEIGHT_REQUESTS" \
  --argjson automatic_trust "$PRIVIDIUM_MAX_AUTOMATIC_TRUST_UPDATES" '
  def optional_token($name): if $name == "" then {} else {tokenEnv: $name} end;
  {
    sourceProfilePath: $source_profile_path,
    sourceProfileSha256: $source_profile_sha256,
    bindAddress: $bind_address,
    client: {
      chainId: $client_chain_id,
      clientId: $client_id,
      counterpartyClientId: $counterparty_client_id,
      counterpartyMerklePrefix: $counterparty_prefix
    },
    prover: {
      networkRpcUrl: $prover_url,
      networkPrivateKeyEnv: "PRIVIDIUM_SP1_NETWORK_PRIVATE_KEY",
      proofTimeoutSeconds: $proof_timeout
    },
    l2Rpc: ({
      url: $l2_url,
      chainId: $l2_chain_id,
      maxResponseBytes: $l2_max_response,
      maxBatchLookback: $l2_lookback
    } + optional_token($l2_token_env)),
    ibcStorage: {
      supportedPathShapeId: $path_shape,
      storageProfileId: $storage_profile,
      storeAddress: $store,
      mappingBaseSlot: $mapping_slot,
      maxClientIdBytes: $max_client_id,
      nativeRootProbeSlot: $native_root_slot,
      absenceProfileId: $absence_profile
    },
    bootstrap: ({
      beaconUrl: $beacon_url,
      finalizedCheckpointRoot: $checkpoint_root,
      sourceProfileId: $source_profile_id,
      initialTrustPath: $initial_trust_path,
      initialTrustSha256: $initial_trust_sha256,
      syncCommitteeSize: $sync_committee_size,
      slotsPerEpoch: $slots_per_epoch,
      epochsPerSyncCommitteePeriod: $epochs_per_period,
      maxResponseBytes: $beacon_max_response
    } + optional_token($beacon_token_env)),
    apiTokenEnv: (if $api_token_env == "" then null else $api_token_env end),
    requestTimeoutSeconds: $request_timeout,
    maxConcurrentRequests: $concurrent_requests,
    maxQueuedRequests: $queued_requests,
    maxConcurrentHeightRequests: $concurrent_height,
    maxAutomaticTrustUpdates: $automatic_trust,
    l1Rpc: ({
      url: $l1_url,
      chainId: $l1_chain_id,
      maxResponseBytes: $l1_max_response
    } + optional_token($l1_token_env)),
    destination: {
      rpc: ({
        url: $destination_url,
        chainId: $destination_chain_id,
        maxResponseBytes: $destination_max_response
      } + optional_token($destination_token_env)),
      routerAddress: $destination_router,
      verifierAddress: $destination_verifier,
      trustUpdateVkey: $trust_vkey,
      settlementUpdateVkey: $settlement_vkey,
      membershipVkey: $membership_vkey,
      nonMembershipVkey: $non_membership_vkey,
      trustUpdateRegistrar: {
        privateKeyEnv: "PRIVIDIUM_TRUST_UPDATE_REGISTRAR_PRIVATE_KEY",
        chainId: $destination_chain_id,
        receiptTimeoutSeconds: $receipt_timeout,
        receiptPollMilliseconds: $receipt_poll,
        maxGas: $max_gas
      }
    },
    settlement: {
      diamondProxyAddress: $diamond,
      storedBatchHashMappingBaseSlot: $stored_batch_slot,
      totalBatchesExecutedSlot: $total_batches_executed_slot
    }
  }
' >"$temporary_config"

mv -- "$temporary_config" "$PRIVIDIUM_CONFIG_PATH"
trap - EXIT

if [[ $PRIVIDIUM_BUILD_OPERATOR == true ]]; then
  echo "Building hard-finality Proof API with the reviewed SourceProfile and four SP1 ELFs"
  (
    cd "$repo_root"
    env \
      -u PRIVIDIUM_SP1_NETWORK_PRIVATE_KEY \
      -u PRIVIDIUM_TRUST_UPDATE_REGISTRAR_PRIVATE_KEY \
      -u PRIVIDIUM_L2_RPC_TOKEN \
      -u PRIVIDIUM_L1_RPC_TOKEN \
      -u PRIVIDIUM_BEACON_TOKEN \
      -u PRIVIDIUM_DESTINATION_RPC_TOKEN \
      -u PRIVIDIUM_PROOF_API_TOKEN \
      PRIVIDIUM_SOURCE_PROFILE="$PRIVIDIUM_SOURCE_PROFILE" \
      PRIVIDIUM_SP1_ELF_DIR="$PRIVIDIUM_SP1_ELF_DIR" \
      cargo build --manifest-path tooling/proof-api/Cargo.toml \
        --release --locked --features sp1
  )
  PRIVIDIUM_PROOF_API_BINARY="$proof_api_root/target/release/prividium-proof-api"
fi

[[ -x "$PRIVIDIUM_PROOF_API_BINARY" ]] || {
  echo "Proof API binary is not executable: $PRIVIDIUM_PROOF_API_BINARY" >&2
  exit 2
}

export PRIVIDIUM_SP1_NETWORK_PRIVATE_KEY
export PRIVIDIUM_TRUST_UPDATE_REGISTRAR_PRIVATE_KEY
for name in \
  PRIVIDIUM_L2_RPC_TOKEN \
  PRIVIDIUM_L1_RPC_TOKEN \
  PRIVIDIUM_BEACON_TOKEN \
  PRIVIDIUM_DESTINATION_RPC_TOKEN \
  PRIVIDIUM_PROOF_API_TOKEN; do
  if [[ -n ${!name:-} ]]; then
    export "$name"
  fi
done

echo "ELF hashes match the reviewed VKey manifest"
echo "SourceProfile and initial-trust checksums written to the generated configuration"
echo "Starting hard-finality Proof API with configuration: $PRIVIDIUM_CONFIG_PATH"
exec "$PRIVIDIUM_PROOF_API_BINARY" --config "$PRIVIDIUM_CONFIG_PATH"
