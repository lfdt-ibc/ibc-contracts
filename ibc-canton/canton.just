# SPDX-License-Identifier: Apache-2.0

# Recipes for the Canton (Daml) IBC implementation. Invoked from the repository
# root justfile as the `canton` module; recipes run with `ibc-canton/`
# as the working directory. Needs `dpm`, provided by `nix develop .#canton`.

# List the recipes exposed by this module.
default:
  just --list canton

# Build all Daml packages into DARs
[group('canton')]
build:
  cd daml && dpm build --all

# Run the Daml Script tests
[group('canton')]
test: build
  cd daml/ibc-test && dpm test
