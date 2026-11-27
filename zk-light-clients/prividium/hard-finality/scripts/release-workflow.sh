#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
forge_bin=${FORGE_BIN:-forge}
cast_bin=${CAST_BIN:-cast}
contract_artifact="$repo_root/contracts/out/PrividiumZKLightClient.sol/PrividiumZKLightClient.json"
elf_dir="$repo_root/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"

# shellcheck disable=SC1091
source "$repo_root/scripts/sp1-container.env"

usage() {
  cat <<'EOF'
Usage:
  scripts/release-workflow.sh generate PROFILE.json VKEYS.json [MANIFEST.json]
  scripts/release-workflow.sh validate MANIFEST.json PROFILE.json VKEYS.json
  scripts/release-workflow.sh all PROFILE.json VKEYS.json [MANIFEST.json]

The default output for generate/all is release/manifest.json. Generation and
validation reject a dirty working tree. RELEASE_ALLOW_DIRTY=1 is available only
for development validation; a dirty manifest is not a production release.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command is unavailable: $1" >&2
    exit 1
  }
}

require_file() {
  if [[ ! -f $1 || -L $1 ]]; then
    echo "release input must be a regular, non-symlink file: $1" >&2
    exit 2
  fi
}

canonical_path() {
  realpath -- "$1"
}

display_path() {
  local path=$1
  if [[ $path == "$repo_root/"* ]]; then
    printf '%s\n' "${path#"$repo_root/"}"
  else
    basename -- "$path"
  fi
}

tree_dirty() {
  local ignored_path=${1:-}
  if [[ -n $ignored_path && $ignored_path == "$repo_root/"* ]]; then
    local relative=${ignored_path#"$repo_root/"}
    [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal \
      -- . ":(exclude)$relative") ]]
  else
    [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]]
  fi
}

check_tree_policy() {
  local ignored_path=${1:-}
  if tree_dirty "$ignored_path" && [[ ${RELEASE_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "release workflow requires a clean working tree" >&2
    echo "commit or stash changes; RELEASE_ALLOW_DIRTY=1 is development-only" >&2
    exit 1
  fi
}

validate_vkeys_and_elfs() {
  local vkeys=$1
  jq -e '
    (keys | sort) == ["membership", "non-membership", "settlement-update", "trust-update"]
    and all(.[];
      (.sourceProfileId | type == "string" and test("^0x[0-9a-f]{64}$"))
      and
      (.elfSha256 | type == "string" and test("^0x[0-9a-f]{64}$"))
      and (.programVKey | type == "string" and test("^0x[0-9a-f]{64}$"))
      and .programVKey != ("0x" + ("0" * 64)))
    and ([.[].programVKey] | unique | length) == 4
    and ([.[].sourceProfileId] | unique | length) == 1
  ' "$vkeys" >/dev/null || {
    echo "VKey manifest is malformed or does not contain four distinct programs" >&2
    exit 1
  }

  local program
  for program in trust-update settlement-update membership non-membership; do
    local elf="$elf_dir/prividium-$program-program"
    if [[ ! -f $elf || -L $elf ]]; then
      echo "missing reviewed ELF: $elf" >&2
      exit 1
    fi
    local expected
    local actual
    expected=$(jq -er --arg program "$program" '.[$program].elfSha256' "$vkeys")
    actual="0x$(sha256sum "$elf" | awk '{print $1}')"
    if [[ $actual != "$expected" ]]; then
      echo "$program ELF hash does not match the VKey manifest" >&2
      exit 1
    fi
  done
}

compile_profile_id() {
  local profile=$1
  local temporary_directory
  temporary_directory=$(mktemp -d /tmp/prividium-release-profile.XXXXXX)
  local profile_output
  profile_output=$(
    cargo run --quiet --locked --offline \
      --manifest-path "$repo_root/Cargo.toml" \
      -p prividium-source-profile --bin profilec -- \
      "$profile" "$temporary_directory/generated-source-profile.rs"
  )
  rm -rf -- "$temporary_directory"
  local profile_id=${profile_output#SOURCE_PROFILE_ID=}
  if [[ ! $profile_id =~ ^0x[0-9a-f]{64}$ ]]; then
    echo "profile compiler returned an invalid SourceProfile ID" >&2
    exit 1
  fi
  printf '%s\n' "$profile_id"
}

prepare_contract_artifact() {
  "$repo_root/scripts/install-contract-deps.sh"
  "$forge_bin" build --root "$repo_root/contracts" >/dev/null
  require_file "$contract_artifact"
}

artifact_metadata() {
  local field=$1
  case "$field" in
    abi)
      local canonical_abi
      canonical_abi=$(jq -cS '.abi' "$contract_artifact")
      printf '%s' "$canonical_abi" | sha256sum | awk '{print "0x" $1}'
      ;;
    creation)
      "$cast_bin" keccak "$(jq -er '.bytecode.object | select(startswith("0x") and length > 2)' "$contract_artifact")"
      ;;
    deployed)
      "$cast_bin" keccak "$(jq -er '.deployedBytecode.object | select(startswith("0x") and length > 2)' "$contract_artifact")"
      ;;
    *)
      echo "unknown artifact metadata field: $field" >&2
      return 2
      ;;
  esac
}

common_checks() {
  local profile=$1
  local vkeys=$2
  local ignored_path=${3:-}
  for command in git jq sha256sum awk realpath cargo "$forge_bin" "$cast_bin"; do
    require_command "$command"
  done
  require_file "$profile"
  require_file "$vkeys"
  check_tree_policy "$ignored_path"
  validate_vkeys_and_elfs "$vkeys"
  local profile_id
  profile_id=$(compile_profile_id "$profile")
  jq -e --arg profile_id "$profile_id" \
    'all(.[]; .sourceProfileId == $profile_id)' "$vkeys" >/dev/null || {
    echo "VKey manifest SourceProfile ID does not match the selected SourceProfile" >&2
    exit 1
  }
  prepare_contract_artifact
  if [[ -n $(git -C "$repo_root/contracts/lib/sp1-contracts" status --porcelain) ]]; then
    echo "sp1-contracts dependency checkout is dirty" >&2
    exit 1
  fi
}

generate_manifest() {
  local profile
  local vkeys
  profile=$(canonical_path "$1")
  vkeys=$(canonical_path "$2")
  local output=${3:-"$repo_root/release/manifest.json"}
  mkdir -p -- "$(dirname -- "$output")"
  output=$(realpath -m -- "$output")

  common_checks "$profile" "$vkeys"

  local dirty=false
  if tree_dirty; then
    dirty=true
  fi
  local profile_id
  profile_id=$(compile_profile_id "$profile")
  local profile_sha="0x$(sha256sum "$profile" | awk '{print $1}')"
  local vkeys_sha="0x$(sha256sum "$vkeys" | awk '{print $1}')"
  local repository_commit
  repository_commit=$(git -C "$repo_root" rev-parse HEAD)
  local sp1_contracts_commit
  sp1_contracts_commit=$(git -C "$repo_root/contracts/lib/sp1-contracts" rev-parse HEAD)
  local rust_channel
  rust_channel=$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$repo_root/rust-toolchain.toml")
  local foundry_version
  foundry_version=$($forge_bin --version | sed -n '1p')
  local abi_sha
  local creation_hash
  local deployed_hash
  abi_sha=$(artifact_metadata abi)
  creation_hash=$(artifact_metadata creation)
  deployed_hash=$(artifact_metadata deployed)
  local generated_at
  generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  local temporary
  temporary=$(mktemp "$(dirname -- "$output")/.manifest.XXXXXX")
  jq -nS \
    --arg generatedAt "$generated_at" \
    --arg repositoryGitCommit "$repository_commit" \
    --argjson repositoryDirty "$dirty" \
    --arg profilePath "$(display_path "$profile")" \
    --arg profileSha256 "$profile_sha" \
    --arg sourceProfileId "$profile_id" \
    --arg vkeysPath "$(display_path "$vkeys")" \
    --arg vkeysSha256 "$vkeys_sha" \
    --arg rust "$rust_channel" \
    --arg sp1Sdk "$SP1_SDK_VERSION" \
    --arg sp1Revision "$SP1_CONTAINER_REVISION" \
    --arg sp1Container "$SP1_CONTAINER_IMAGE" \
    --arg circuit "$SP1_CIRCUIT_VERSION" \
    --arg verifierHash "$SP1_GROTH16_VERIFIER_HASH" \
    --arg solidity "0.8.28" \
    --arg foundry "$foundry_version" \
    --arg sp1ContractsCommit "$sp1_contracts_commit" \
    --arg abiSha256 "$abi_sha" \
    --arg creationBytecodeKeccak256 "$creation_hash" \
    --arg deployedBytecodeKeccak256 "$deployed_hash" \
    --slurpfile programs "$vkeys" '
    {
      schemaVersion: 1,
      project: "prividium-sp1-settlement-backed-light-client",
      generatedAt: $generatedAt,
      repository: {gitCommit: $repositoryGitCommit, dirty: $repositoryDirty},
      sourceProfile: {
        path: $profilePath,
        sha256: $profileSha256,
        sourceProfileId: $sourceProfileId
      },
      vkeyManifest: {path: $vkeysPath, sha256: $vkeysSha256},
      toolchains: {
        rust: $rust,
        sp1Sdk: $sp1Sdk,
        sp1ContainerRevision: $sp1Revision,
        sp1ContainerImage: $sp1Container,
        sp1Circuit: $circuit,
        groth16VerifierHash: $verifierHash,
        solidity: $solidity,
        foundry: $foundry
      },
      dependencies: {sp1ContractsGitCommit: $sp1ContractsCommit},
      programs: $programs[0],
      contract: {
        name: "PrividiumZKLightClient",
        abiCanonicalJsonSha256: $abiSha256,
        creationBytecodeKeccak256: $creationBytecodeKeccak256,
        deployedBytecodeKeccak256: $deployedBytecodeKeccak256
      },
      generationCommand: "scripts/release-workflow.sh all PROFILE.json VKEYS.json MANIFEST.json"
    }
  ' >"$temporary"
  mv -- "$temporary" "$output"
  echo "wrote release manifest to $output"
}

validate_manifest() {
  local manifest
  local profile
  local vkeys
  manifest=$(canonical_path "$1")
  profile=$(canonical_path "$2")
  vkeys=$(canonical_path "$3")
  require_file "$manifest"
  common_checks "$profile" "$vkeys" "$manifest"

  local dirty=false
  if tree_dirty "$manifest"; then
    dirty=true
  fi
  local profile_id
  profile_id=$(compile_profile_id "$profile")
  local profile_sha="0x$(sha256sum "$profile" | awk '{print $1}')"
  local vkeys_sha="0x$(sha256sum "$vkeys" | awk '{print $1}')"
  local repository_commit
  repository_commit=$(git -C "$repo_root" rev-parse HEAD)
  local sp1_contracts_commit
  sp1_contracts_commit=$(git -C "$repo_root/contracts/lib/sp1-contracts" rev-parse HEAD)
  local rust_channel
  rust_channel=$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$repo_root/rust-toolchain.toml")
  local foundry_version
  foundry_version=$($forge_bin --version | sed -n '1p')
  local abi_sha
  local creation_hash
  local deployed_hash
  abi_sha=$(artifact_metadata abi)
  creation_hash=$(artifact_metadata creation)
  deployed_hash=$(artifact_metadata deployed)

  jq -e \
    --arg repositoryCommit "$repository_commit" \
    --argjson repositoryDirty "$dirty" \
    --arg profileSha "$profile_sha" \
    --arg profileId "$profile_id" \
    --arg vkeysSha "$vkeys_sha" \
    --arg rust "$rust_channel" \
    --arg foundry "$foundry_version" \
    --arg sp1Sdk "$SP1_SDK_VERSION" \
    --arg sp1Revision "$SP1_CONTAINER_REVISION" \
    --arg sp1Container "$SP1_CONTAINER_IMAGE" \
    --arg circuit "$SP1_CIRCUIT_VERSION" \
    --arg verifierHash "$SP1_GROTH16_VERIFIER_HASH" \
    --arg sp1ContractsCommit "$sp1_contracts_commit" \
    --arg abiSha "$abi_sha" \
    --arg creationHash "$creation_hash" \
    --arg deployedHash "$deployed_hash" \
    --slurpfile expectedPrograms "$vkeys" '
      .schemaVersion == 1
      and .project == "prividium-sp1-settlement-backed-light-client"
      and (.generatedAt | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
      and .repository.gitCommit == $repositoryCommit
      and .repository.dirty == $repositoryDirty
      and .sourceProfile.sha256 == $profileSha
      and .sourceProfile.sourceProfileId == $profileId
      and .vkeyManifest.sha256 == $vkeysSha
      and .toolchains.rust == $rust
      and .toolchains.sp1Sdk == $sp1Sdk
      and .toolchains.sp1ContainerRevision == $sp1Revision
      and .toolchains.sp1ContainerImage == $sp1Container
      and .toolchains.sp1Circuit == $circuit
      and .toolchains.groth16VerifierHash == $verifierHash
      and .toolchains.solidity == "0.8.28"
      and .toolchains.foundry == $foundry
      and .dependencies.sp1ContractsGitCommit == $sp1ContractsCommit
      and .programs == $expectedPrograms[0]
      and .contract.name == "PrividiumZKLightClient"
      and .contract.abiCanonicalJsonSha256 == $abiSha
      and .contract.creationBytecodeKeccak256 == $creationHash
      and .contract.deployedBytecodeKeccak256 == $deployedHash
      and ([.programs[].programVKey] | unique | length) == 4
    ' "$manifest" >/dev/null || {
    echo "release manifest does not match the current reviewed inputs and artifacts" >&2
    exit 1
  }
  echo "release manifest validation passed"
}

action=${1:-}
case "$action" in
  generate)
    [[ $# -ge 3 && $# -le 4 ]] || { usage >&2; exit 2; }
    generate_manifest "$2" "$3" "${4:-$repo_root/release/manifest.json}"
    ;;
  validate)
    [[ $# -eq 4 ]] || { usage >&2; exit 2; }
    validate_manifest "$2" "$3" "$4"
    ;;
  all)
    [[ $# -ge 3 && $# -le 4 ]] || { usage >&2; exit 2; }
    manifest=${4:-"$repo_root/release/manifest.json"}
    generate_manifest "$2" "$3" "$manifest"
    validate_manifest "$manifest" "$2" "$3"
    ;;
  -h | --help | help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
