# SPDX-License-Identifier: Apache-2.0
#
# Daml SDK (`dpm`, damlc, daml-script, Canton sandbox) from the upstream SDK tarball.
#
# The tarball is a `dpm` binary plus an offline OCI registry holding every SDK component, so
# `dpm bootstrap` installs from it without network access.
#
# Only the platforms listed in `sources` are packaged. To add one, add its hash:
#   nix store prefetch-file https://get.digitalasset.com/install/dpm-sdk/dpm-<version>-<os>-<arch>.tar.gz
{
  lib,
  stdenv,
  fetchurl,
  makeWrapper,
  jdk17,
}: let
  version = "3.7.4";
  sources = {
    aarch64-darwin = {
      platform = "darwin-arm64";
      hash = "sha256-T1sET/wnd4rgOkqdJnidM87puoW+JTcvCymMEbhx11A=";
    };
  };
  source =
    sources.${stdenv.hostPlatform.system}
    or (throw "daml-sdk: no pinned tarball for ${stdenv.hostPlatform.system}");
in
  stdenv.mkDerivation {
    pname = "daml-sdk";
    inherit version;

    src = fetchurl {
      url = "https://get.digitalasset.com/install/dpm-sdk/dpm-${version}-${source.platform}.tar.gz";
      inherit (source) hash;
    };

    nativeBuildInputs = [makeWrapper];

    dontConfigure = true;
    dontBuild = true;
    dontStrip = true;
    dontFixup = true;

    installPhase = ''
      runHook preInstall
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME" "$out/dpm-home"
      DPM_HOME="$out/dpm-home" ./bin/dpm bootstrap "$PWD"
      makeWrapper "$out/dpm-home/bin/dpm" "$out/bin/dpm" \
        --set DPM_HOME "$out/dpm-home" \
        --set-default JAVA_HOME "${jdk17.home}" \
        --prefix PATH : "${jdk17}/bin"
      runHook postInstall
    '';

    meta = {
      description = "Daml SDK and Digital Asset Package Manager";
      homepage = "https://docs.canton.network/sdks-tools/cli-tools/dpm";
      license = lib.licenses.asl20;
      platforms = builtins.attrNames sources;
      mainProgram = "dpm";
    };
  }
