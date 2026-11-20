#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
coverage_root=${COVERAGE_DIR:-"$repo_root/target/coverage"}
forge_bin=${FORGE_BIN:-forge}
: "${PRIVIDIUM_SOURCE_PROFILE:?set PRIVIDIUM_SOURCE_PROFILE explicitly; use profiles/example.synthetic.json for local coverage}"
export PRIVIDIUM_SOURCE_PROFILE
coverage_cleanup_manifest=
coverage_cleanup_directory=

usage() {
  cat <<'EOF'
Usage: scripts/coverage.sh [all|core|proof-api|contracts]

Environment:
  COVERAGE_DIR  Output root (default: target/coverage)
  FORGE_BIN     Forge executable (default: forge)
  HTML=1        Also generate Rust HTML reports
  KEEP_COVERAGE_BUILD=1  Retain instrumented Cargo build caches after reporting
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command is unavailable: $1" >&2
    exit 1
  }
}

cleanup_coverage_build() {
  if [[ -n $coverage_cleanup_manifest && -n $coverage_cleanup_directory \
      && ${KEEP_COVERAGE_BUILD:-0} != 1 ]]; then
    cargo clean --manifest-path "$coverage_cleanup_manifest" \
      --target-dir "$coverage_cleanup_directory" >/dev/null 2>&1
  fi
}

rust_report() {
  local manifest=$1
  local output_dir=$2
  shift 2
  mkdir -p "$output_dir"
  coverage_cleanup_manifest=$manifest
  coverage_cleanup_directory="$output_dir/build"
  trap cleanup_coverage_build EXIT
  cargo clean --manifest-path "$manifest" \
    --target-dir "$coverage_cleanup_directory" >/dev/null 2>&1
  CARGO_LLVM_COV_TARGET_DIR="$coverage_cleanup_directory" \
    CARGO_LLVM_COV_BUILD_DIR="$coverage_cleanup_directory" \
    cargo llvm-cov --manifest-path "$manifest" "$@" \
    --lcov --output-path "$output_dir/lcov.info"
  CARGO_LLVM_COV_TARGET_DIR="$coverage_cleanup_directory" \
    CARGO_LLVM_COV_BUILD_DIR="$coverage_cleanup_directory" \
    cargo llvm-cov report --manifest-path "$manifest" \
    | tee "$output_dir/summary.txt"
  if [[ ${HTML:-0} == 1 ]]; then
    CARGO_LLVM_COV_TARGET_DIR="$coverage_cleanup_directory" \
      CARGO_LLVM_COV_BUILD_DIR="$coverage_cleanup_directory" \
      cargo llvm-cov report --manifest-path "$manifest" \
      --html --output-dir "$output_dir/html"
  fi
  cleanup_coverage_build
  coverage_cleanup_manifest=
  coverage_cleanup_directory=
  trap - EXIT
}

run_action() {
  case "$1" in
    all)
      run_action core
      run_action proof-api
      run_action contracts
      ;;
    core)
      require_command cargo-llvm-cov
      rust_report "$repo_root/Cargo.toml" "$coverage_root/core" \
        --workspace --all-targets --locked
      ;;
    proof-api)
      require_command cargo-llvm-cov
      rust_report "$repo_root/tooling/proof-api/Cargo.toml" "$coverage_root/proof-api" \
        --all-targets --locked --no-default-features
      ;;
    contracts)
      require_command "$forge_bin"
      "$repo_root/scripts/install-contract-deps.sh"
      mkdir -p "$coverage_root/contracts"
      (
        cd "$repo_root/contracts"
        "$forge_bin" coverage --report lcov \
          --report-file "$coverage_root/contracts/lcov.info"
        "$forge_bin" coverage --report summary \
          | tee "$coverage_root/contracts/summary.txt"
      )
      ;;
    -h | --help | help)
      usage
      ;;
    *)
      echo "unknown coverage action: $1" >&2
      usage >&2
      return 2
      ;;
  esac
}

run_action "${1:-all}"
