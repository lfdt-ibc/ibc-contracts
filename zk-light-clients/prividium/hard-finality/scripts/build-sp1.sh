#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091
source "$repo_root/scripts/sp1-container.env"

: "${PRIVIDIUM_SOURCE_PROFILE:?set PRIVIDIUM_SOURCE_PROFILE to an explicit SourceProfile JSON file}"
PRIVIDIUM_SOURCE_PROFILE=$(realpath -- "$PRIVIDIUM_SOURCE_PROFILE")
if [[ "$(realpath --relative-to="$repo_root" "$PRIVIDIUM_SOURCE_PROFILE")" == .. \
  || "$(realpath --relative-to="$repo_root" "$PRIVIDIUM_SOURCE_PROFILE")" == ../* ]]; then
  echo "PRIVIDIUM_SOURCE_PROFILE must be inside the repository" >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for the pinned SP1 guest build" >&2
  exit 1
}
"$repo_root/scripts/check-sp1-toolchain.sh"

docker pull "$SP1_CONTAINER_IMAGE" >/dev/null

image_revision=$(docker image inspect "$SP1_CONTAINER_IMAGE" \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
if [[ "$image_revision" != "$SP1_CONTAINER_REVISION" ]]; then
  echo "wrong SP1 container revision: expected $SP1_CONTAINER_REVISION, got $image_revision" >&2
  exit 1
fi

build_workspace=$(mktemp -d /tmp/prividium-sp1-build.XXXXXX)
cleanup() {
  if [[ -d "$build_workspace" && "$build_workspace" == /tmp/prividium-sp1-build.* ]]; then
    docker run --rm \
      --volume "$build_workspace:/work" \
      --entrypoint /bin/chown \
      "$SP1_CONTAINER_IMAGE" \
      --recursive "$(id -u):$(id -g)" /work >/dev/null 2>&1 || true
    rm -rf -- "$build_workspace"
  fi
}
trap cleanup EXIT

# cargo-prove's Docker mode intentionally forwards only its fixed compiler
# environment. Build in an isolated source snapshot and place the reviewed
# profile at a deterministic snapshot path and configure Cargo to expose that
# path to every guest build. No host-only path can affect the guest constants.
tar \
  --exclude=.git \
  --exclude=target \
  --exclude=.cache \
  -cf - \
  -C "$repo_root" . \
  | tar -xf - -C "$build_workspace"
install -m 0644 "$PRIVIDIUM_SOURCE_PROFILE" \
  "$build_workspace/profiles/source-profile.selected.json"
if [[ -e "$build_workspace/.cargo/config.toml" ]]; then
  echo "the isolated build unexpectedly contains .cargo/config.toml" >&2
  exit 1
fi
mkdir -p -- "$build_workspace/.cargo"
printf '%s\n' \
  '[env]' \
  'PRIVIDIUM_SOURCE_PROFILE = { value = "profiles/source-profile.selected.json", relative = true, force = true }' \
  >"$build_workspace/.cargo/config.toml"

elf_dir="$repo_root/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
mkdir -p -- "$elf_dir"
export SP1_DOCKER_IMAGE="$SP1_CONTAINER_IMAGE"

for program in trust-update settlement-update membership non-membership; do
  binary="prividium-$program-program"
  (
    cd "$build_workspace/programs/$program"
    cargo prove build \
      --docker \
      --locked \
      --workspace-directory "$build_workspace" \
      --output-directory "$elf_dir" \
      --elf-name "$binary"
  )
done

"$repo_root/scripts/hash-guests.sh"
