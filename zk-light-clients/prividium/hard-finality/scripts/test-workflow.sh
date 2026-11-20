#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
forge_bin=${FORGE_BIN:-forge}
: "${PRIVIDIUM_SOURCE_PROFILE:?set PRIVIDIUM_SOURCE_PROFILE explicitly; use profiles/example.synthetic.json for local tests}"
export PRIVIDIUM_SOURCE_PROFILE

usage() {
  cat <<'EOF'
Usage: scripts/test-workflow.sh [ACTION] [ACTION_ARGUMENTS...]

Actions:
  all          Run formatting/lints, Rust tests, Proof API tests, contracts, and Router E2E
  fast         Run everything in all except the external-checkout Router E2E suite
  check        Run Rust/Solidity formatting and Clippy
  rust         Run the core workspace tests
  proof-api    Run the standalone Proof API tests
  contracts    Run the Prividium contract tests
  router-e2e   Run the real-ICS26-Router deterministic E2E suite
  coverage     Delegate to scripts/coverage.sh
  release      Delegate to scripts/release-workflow.sh

The router-e2e and all actions require IBC_CONTRACTS_DIR. See e2e/README.md.
EOF
}

require_forge() {
  command -v "$forge_bin" >/dev/null 2>&1 || {
    echo "forge is required (or set FORGE_BIN to its absolute path)" >&2
    exit 1
  }
}

run_action() {
  local action=$1
  shift
  case "$action" in
    all)
      run_action check
      run_action rust
      run_action proof-api
      run_action contracts
      run_action router-e2e
      ;;
    fast)
      run_action check
      run_action rust
      run_action proof-api
      run_action contracts
      ;;
    check)
      require_forge
      cargo fmt --manifest-path "$repo_root/Cargo.toml" --all -- --check
      cargo clippy --manifest-path "$repo_root/Cargo.toml" \
        --workspace --all-targets --locked -- -D warnings
      (
        cd "$repo_root/tooling/proof-api"
        cargo fmt --all -- --check
        cargo clippy --all-targets --locked --no-default-features -- -D warnings
      )
      (
        cd "$repo_root/contracts"
        "$forge_bin" fmt --check
      )
      (
        cd "$repo_root/e2e/solidity"
        "$forge_bin" fmt --check test/PrividiumRouterE2E.t.sol
      )
      ;;
    rust)
      cargo test --manifest-path "$repo_root/Cargo.toml" --workspace --locked
      ;;
    proof-api)
      (
        cd "$repo_root/tooling/proof-api"
        cargo test --all-targets --locked --no-default-features
      )
      ;;
    contracts)
      require_forge
      "$repo_root/scripts/install-contract-deps.sh"
      (
        cd "$repo_root/contracts"
        "$forge_bin" test -vvv
      )
      ;;
    router-e2e)
      require_forge
      FORGE_BIN="$forge_bin" "$repo_root/e2e/scripts/run-router-e2e.sh"
      ;;
    coverage)
      "$repo_root/scripts/coverage.sh" "${@:-all}"
      ;;
    release)
      "$repo_root/scripts/release-workflow.sh" "$@"
      ;;
    -h | --help | help)
      usage
      ;;
    *)
      echo "unknown test workflow action: $action" >&2
      usage >&2
      return 2
      ;;
  esac
}

action=${1:-all}
if [[ $# -gt 0 ]]; then
  shift
fi
run_action "$action" "$@"
