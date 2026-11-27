#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <genesis.raw.json> <spec.raw.json> <ibc-store-address> <ibc-contracts-commit> <source-profile.json>" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
genesis=$1
spec=$2
ibc_store=$3
ibc_contracts_commit=$4
output=$5
[[ "$ibc_contracts_commit" =~ ^[0-9a-fA-F]{40}$ ]] || {
    echo "invalid IBC contracts commit: $ibc_contracts_commit" >&2
    exit 2
}

[[ "$ibc_store" =~ ^0x[0-9a-fA-F]{40}$ ]] || {
    echo "invalid IBC store address: $ibc_store" >&2
    exit 2
}

jq -n \
    --slurpfile genesis "$genesis" \
    --slurpfile spec "$spec" \
    --slurpfile base "$repo_root/profiles/example.synthetic.json" \
    --arg ibc_store "$ibc_store" \
    --arg ibc_contracts_commit "$ibc_contracts_commit" '
  ($genesis[0].data) as $g |
  ($spec[0].data) as $s |
  ($base[0]) as $base |
  $base
  | .profileName = "local-connected-v0208-one-validator-fulu"
  | .consensus = {
      genesisValidatorsRoot: $g.genesis_validators_root,
      genesisTime: ($g.genesis_time | tonumber),
      secondsPerSlot: ($s.SECONDS_PER_SLOT | tonumber),
      slotsPerEpoch: ($s.SLOTS_PER_EPOCH | tonumber),
      epochsPerSyncCommitteePeriod:
        ($s.EPOCHS_PER_SYNC_COMMITTEE_PERIOD | tonumber),
      syncCommitteeSize: ($s.SYNC_COMMITTEE_SIZE | tonumber),
      forkSchedule: [{
        forkId: "fulu",
        activationEpoch: ($s.FULU_FORK_EPOCH | tonumber),
        forkVersion: $s.FULU_FORK_VERSION
      }],
      supportedLightClientHeaderSchemas: ["fulu-compatibility-v1"],
      supportedExecutionPayloadHeaderSchemas: ["fulu-compatibility-v1"],
      forkSpecificFinalityGindices: [{forkId: "fulu", generalizedIndex: 169}],
      forkSpecificNextCommitteeGindices: [{forkId: "fulu", generalizedIndex: 87}],
      forkSpecificExecutionGindices: [{forkId: "fulu", generalizedIndex: 25}]
    }
  | .settlement = {
      diamondProxyAddress: "0x18f438bc08d755e164a7ae7c077e2ea93b0179ef",
      diamondSourceCommit: "9ddc915c85d1f44c79b5d55e160d384138ed5105",
      settlementStorageProfileId: "era-contracts-zkos-v0.30.2-zk-chain-storage-v1",
      acceptedLifecycleRuleId: "zksync-v30.2-executed-batch-v1",
      nativeRootBindingRuleId: "zksync-os-v0.20.8-stored-batch-info-v1",
      storedBatchHashMappingBaseSlot:
        "0x000000000000000000000000000000000000000000000000000000000000000e",
      totalBatchesExecutedSlot:
        "0x000000000000000000000000000000000000000000000000000000000000000b"
    }
  | .prividiumL2.ibcStoreAddress = $ibc_store
  | .prividiumL2.ibcStorageProfileId = "local-direct-word-test-store-v1"
  | .prividiumL2.ibcMappingBaseSlot =
      "0x0000000000000000000000000000000000000000000000000000000000000000"
  | .ibc.ibcContractsCommit = $ibc_contracts_commit
  | .ibc.supportedPathShapeId = "local-poc-terminal-path-v1"
' > "$output"

echo "Generated connected LOCAL-E2E SourceProfile: $output"
echo "This profile pins the exact v30.2 local Diamond; it is not a production deployment profile."
