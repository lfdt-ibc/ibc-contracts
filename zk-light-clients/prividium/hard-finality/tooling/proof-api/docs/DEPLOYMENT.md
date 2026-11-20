# Proof API deployment

This guide starts the settlement-backed hard-finality Proof API. It covers the
service only. Deploy the light client, register or migrate the Router client,
and start the SP1 network and relayer through their own deployment procedures.

## Before starting

Collect one reviewed release bundle:

- the repository commit;
- `source-profile.json` and its SourceProfile ID;
- the Trust Update, Settlement Update, Membership and Non-Membership ELFs;
- `program-vkeys.json` generated from those four ELFs;
- `initial-trust.json` captured for the same Beacon network;
- the source L2, L1 execution and Beacon endpoints;
- the destination endpoint, Router and SP1 verifier gateway addresses;
- the destination client ID and counterparty metadata;
- the source IBC store, settlement Diamond and storage slots; and
- SP1 gateway credentials and the destination trust-update signer key.

The profile, ELFs, VKeys, initial trust, deployed client and Proof API binary
must belong to the same release. This mode does not use an attestor key.

Capture `initial-trust.json` with
`scripts/capture-beacon-bootstrap.sh` from the repository root and deploy the
client with `scripts/deploy-light-client.sh`. The equivalent manual commands
and all contract inputs are documented in
[`../../../docs/DEPLOYMENT.md`](../../../docs/DEPLOYMENT.md). Complete the
contract deployment and Router registration before starting this service.

Before opening traffic, confirm that `Router.getClient(clientId)` resolves the
new hard-finality client. The trust-update signer needs Router `updateClient`
permission because the Proof API may submit earlier Trust Updates while
catching up. Membership requires no separate signer or registration
transaction. Fund the trust-update signer only when the destination reports a
nonzero gas price.

## Docker Compose deployment

Run these commands from `tooling/proof-api`.

### 1. Prepare the release directory

```bash
export RELEASE_DIR=/opt/prividium-l1-release
export RUNTIME_DIR=/var/lib/prividium-l1-proof-api
export RUN_UID="$(id -u)"
export RUN_GID="$(id -g)"

install -d -m 700 "$RELEASE_DIR" "$RUNTIME_DIR"
install -d -m 755 "$RELEASE_DIR/elfs" "$RELEASE_DIR/source-profile-context"
```

Copy the four reviewed ELF files to `$RELEASE_DIR/elfs`. Keep their exact
program names:

```text
prividium-trust-update-program
prividium-settlement-update-program
prividium-membership-program
prividium-non-membership-program
```

Copy the remaining reviewed files:

```bash
install -m 644 /reviewed/path/program-vkeys.json \
  "$RELEASE_DIR/program-vkeys.json"
install -m 644 /reviewed/path/source-profile.json \
  "$RELEASE_DIR/source-profile-context/source-profile.json"
install -m 644 /reviewed/path/initial-trust.json \
  "$RELEASE_DIR/initial-trust.json"
```

### 2. Complete the protected operator file

```bash
install -m 600 config/operator.env.example "$RELEASE_DIR/operator.env"
${EDITOR:-vi} "$RELEASE_DIR/operator.env"
```

Replace every placeholder. The file contains private keys and tokens and is
trusted shell input, so it must remain owned by the container user and have
mode `0600`. Quote URLs and secrets that contain shell characters such as
`&`, `?`, `#`, spaces or `$`:

```bash
chown "$RUN_UID:$RUN_GID" "$RELEASE_DIR/operator.env"
chmod 600 "$RELEASE_DIR/operator.env"
```

Container mode replaces the artifact, binary and generated-config paths in
this file with fixed container paths. All chain IDs, RPCs, addresses, storage
slots, bootstrap values, client metadata, credentials, timeouts and admission
limits still come from this file.

### 3. Complete the Compose environment

```bash
install -m 600 config/compose.env.example "$RELEASE_DIR/compose.env"
${EDITOR:-vi} "$RELEASE_DIR/compose.env"
```

Use these host paths:

```text
PRIVIDIUM_CIRCUIT_ELF_DIR=/opt/prividium-l1-release/elfs
PRIVIDIUM_SOURCE_PROFILE_CONTEXT=/opt/prividium-l1-release/source-profile-context
PRIVIDIUM_PROGRAM_VKEYS_FILE=/opt/prividium-l1-release/program-vkeys.json
PRIVIDIUM_INITIAL_TRUST_FILE=/opt/prividium-l1-release/initial-trust.json
PRIVIDIUM_OPERATOR_ENV_FILE=/opt/prividium-l1-release/operator.env
PRIVIDIUM_STATE_DIRECTORY=/var/lib/prividium-l1-proof-api
```

Set `PRIVIDIUM_RUN_UID` and `PRIVIDIUM_RUN_GID` to the values used above.
Make the writable state directory accessible to that identity:

```bash
chown "$RUN_UID:$RUN_GID" "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
```

### 4. Validate and build

```bash
docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml config --quiet

docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml build --pull
```

The image build embeds the reviewed four ELFs and SourceProfile in the binary.
The runtime mounts the same release files. Startup fails if an ELF hash does
not match `program-vkeys.json` or if the binary, profile, VKeys, destination
client, verifier or storage binding is inconsistent.

### 5. Start and inspect the service

```bash
docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml up -d

docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml ps

docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml logs --tail 200 -f proof-api-hard-finality
```

The container is ready only after startup validation and the SP1 gateway check
finish. A TCP health check confirms that the configured listener is open; use
the startup logs and a relayer `LatestProvableHeight` call for full readiness.

The Compose file uses host networking so loopback RPC proxies and a relayer on
the same host remain reachable. If the relayer is on another host, set
`PRIVIDIUM_BIND_ADDRESS` to an authorized reachable address, configure a bearer
token, and apply the deployment network policy before changing this topology.

### 6. Stop or update

```bash
docker compose --env-file "$RELEASE_DIR/compose.env" \
  -f compose.yaml stop proof-api-hard-finality
```

To update, prepare a new release directory, build a new immutable image tag,
validate it, drain relayer work, and then replace the container. Do not modify
ELFs, VKeys, the profile or initial trust underneath a running release.

## Host deployment with the launcher

The same launcher can build and run directly on a host:

```bash
install -d -m 700 /etc/prividium-l1-proof-api
install -m 600 config/operator.env.example \
  /etc/prividium-l1-proof-api/operator.env
${EDITOR:-vi} /etc/prividium-l1-proof-api/operator.env

scripts/start-proof-api.sh \
  /etc/prividium-l1-proof-api/operator.env
```

For host mode, set the artifact and generated-config paths in `operator.env` to
absolute host paths. Leave `PRIVIDIUM_BUILD_OPERATOR=true` to bind the binary
to the reviewed profile and four ELFs before starting. The process remains in
the foreground; use the site's process supervisor if Docker is not used.

The launcher performs the following work:

1. validates ownership and permissions of `operator.env`;
2. verifies the four ELF hashes against `program-vkeys.json`;
3. hashes the SourceProfile and initial trust artifact;
4. writes the exact hard-finality JSON configuration;
5. optionally builds the four-ELF-bound Proof API binary; and
6. starts the service with the generated configuration.

It does not deploy contracts or start the SP1 gateway, workers, RPC proxies or
relayer.
