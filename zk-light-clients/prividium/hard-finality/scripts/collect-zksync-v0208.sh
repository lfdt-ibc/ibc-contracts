#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
  echo "usage: $0 RPC_URL L2_BLOCK ADDRESS STORAGE_SLOT OUTPUT_DIR" >&2
  exit 2
}

[[ $# -eq 5 ]] || usage

rpc_url=$1
l2_block=$2
address=$3
storage_slot=$4
output_dir=$5

[[ $l2_block =~ ^[0-9]+$ ]] || { echo "L2_BLOCK must be a decimal u64" >&2; exit 2; }
[[ $address =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "ADDRESS must be exactly 20 bytes" >&2; exit 2; }
[[ $storage_slot =~ ^0x[0-9a-fA-F]{64}$ ]] || { echo "STORAGE_SLOT must be exactly 32 bytes" >&2; exit 2; }
if [[ -n ${RPC_BEARER_TOKEN:-} && ! $rpc_url =~ ^https:// && ! $rpc_url =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$) ]]; then
  echo "refusing to send RPC_BEARER_TOKEN over non-TLS, non-loopback HTTP" >&2
  exit 2
fi

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

mkdir -p "$output_dir"
for name in raw-batch-response.json raw-response.json normalized.json; do
  [[ ! -e "$output_dir/$name" ]] || {
    echo "refusing to overwrite $output_dir/$name" >&2
    exit 1
  }
done

request_dir=$(mktemp -d)
cleanup() { rm -rf -- "$request_dir"; }
trap cleanup EXIT

headers=(-H 'Content-Type: application/json')
if [[ -n ${RPC_BEARER_TOKEN:-} ]]; then
  headers+=(-H "Authorization: Bearer ${RPC_BEARER_TOKEN}")
fi

jq -nc --argjson block "$l2_block" \
  '{jsonrpc:"2.0",id:1,method:"unstable_getBatchByBlockNumber",params:[$block]}' \
  >"$request_dir/batch-request.json"
curl --fail-with-body --silent --show-error "${headers[@]}" \
  --data-binary @"$request_dir/batch-request.json" "$rpc_url" \
  >"$request_dir/raw-batch-response.json"
jq -e '.jsonrpc == "2.0" and (.error | not) and (.result != null)' \
  "$request_dir/raw-batch-response.json" >/dev/null

l1_batch=$(jq -er '.result.batch_info.batch_number | select(type == "number")' \
  "$request_dir/raw-batch-response.json")
[[ $l1_batch =~ ^[0-9]+$ ]] || { echo "batch number is not a decimal u64" >&2; exit 1; }

jq -nc \
  --arg address "$address" \
  --arg slot "$storage_slot" \
  --argjson batch "$l1_batch" \
  '{jsonrpc:"2.0",id:2,method:"zks_getProof",params:[$address,[$slot],$batch]}' \
  >"$request_dir/proof-request.json"
curl --fail-with-body --silent --show-error "${headers[@]}" \
  --data-binary @"$request_dir/proof-request.json" "$rpc_url" \
  >"$request_dir/raw-response.json"
jq -e '.jsonrpc == "2.0" and (.error | not) and (.result != null)' \
  "$request_dir/raw-response.json" >/dev/null

jq -n \
  --arg serverVersion 'v0.20.8' \
  --arg serverCommit 'dbb5c03d4a94ceb1acea9f79242590f354660239' \
  --arg zksyncOsCommit 'b4193659af83b6c71419ddda3f57e0302c61eb8d' \
  --argjson l2Block "$l2_block" \
  --argjson l1Batch "$l1_batch" \
  --arg address "$address" \
  --arg slot "$storage_slot" \
  --slurpfile response "$request_dir/raw-response.json" \
  '{serverVersion:$serverVersion,serverCommit:$serverCommit,zksyncOsCommit:$zksyncOsCommit,l2Block:$l2Block,l1Batch:$l1Batch,address:$address,slot:$slot,proofType:$response[0].result.storageProofs[0].proof.type}' \
  >"$request_dir/normalized.json"

mv "$request_dir/raw-batch-response.json" "$output_dir/raw-batch-response.json"
mv "$request_dir/raw-response.json" "$output_dir/raw-response.json"
mv "$request_dir/normalized.json" "$output_dir/normalized.json"

echo "captured pinned-format responses in $output_dir"
