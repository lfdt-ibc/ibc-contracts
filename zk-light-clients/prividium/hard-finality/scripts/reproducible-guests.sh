#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
profile=${1:-profiles/example.synthetic.json}
profile=$(realpath -- "$profile")

git -C "$repo_root" diff --quiet
git -C "$repo_root" diff --cached --quiet
if [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]]; then
  echo "reproducibility must run from a clean committed tree" >&2
  exit 2
fi

relative_profile=$(realpath --relative-to="$repo_root" "$profile")
git -C "$repo_root" ls-files --error-unmatch "$relative_profile" >/dev/null

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

build_once() {
  local name=$1
  local checkout="$work/$name"
  mkdir -p -- "$checkout"
  git -C "$repo_root" archive --format=tar HEAD | tar -xf - -C "$checkout"
  (
    cd -- "$checkout"
    PRIVIDIUM_SOURCE_PROFILE="$checkout/$relative_profile" scripts/build-sp1.sh
  ) >"$work/$name.log"
  awk '{print $1}' "$work/$name.log" | tail -n 4 >"$work/$name.sha256"
  test "$(wc -l <"$work/$name.sha256")" -eq 4
}

build_once first
build_once second
diff -u "$work/first.sha256" "$work/second.sha256"

echo "PASS: all four guest ELF hashes are reproducible"
cat "$work/first.sha256"
