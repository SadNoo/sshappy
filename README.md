# sshappy 4.6

`sshappy` is a Go implementation of a Shadowsocks 2022 node with an SSPanel-compatible runtime. This repository keeps the upstream `shadowsocks-go` server and domain-set converter, and adds `sstest`, which loads node/user policy from MySQL, enforces runtime limits, reports traffic and online state, and persists unreported traffic locally for retry.

Version 4.6 is based on 4.5, which was based directly on immutable `v4.3.1` and intentionally did not inherit the `v4.4.0` or `v4.4.1` release lines. Preserve `sadno/sstest:4.5` as the immediate rollback image. The traffic-outbox JSON remains byte-shape compatible with 4.5, 4.3.1 and 4.2 for both its single- and multi-batch forms.

## 4.6 panel speed limits

- The existing `ss_node.node_speedlimit` value limits aggregate node traffic, shared by all users and both TCP and UDP.
- The existing `user.node_speedlimit` value limits that user's aggregate traffic on the node, shared by all of the user's TCP connections and UDP sessions.
- Upload and download use independent buckets. When both node and user limits are non-zero, the stricter available rate wins. Zero remains unlimited.
- Limits are refreshed with the existing user synchronization cycle without restarting the service. Unchanged token buckets are preserved across refreshes.
- Active TCP transfers and UDP sessions refresh their existing alive-IP observation while traffic continues.

## 4.5 database resilience

- Traffic-accounting database failures no longer stop the relay while the durable local outbox remains writable. Database recovery replays the same idempotent batches.
- Authorization refresh remains fail-closed, but its default stale-snapshot grace is one hour for nodes connected over unreliable networks.
- MySQL advisory-lock waits are capped below the socket I/O timeout, fast stale-connection failures receive one fresh-connection retry, and transaction errors identify the failed accounting stage.
- The default MySQL TLS mode is `disabled`, so deployments using the expected plaintext database do not need an extra environment variable. Keep that connection on a trusted private or encrypted network.
- Idle pooled MySQL connections expire after 30 seconds to reduce reuse of stale WAN/NAT connections.

## Inherited 4.3.1 hardening

- User target restrictions are compiled strictly. An invalid `forbidden_ip`, `forbidden_port` or `disconnect_ip` rule rejects only its owning user instead of being silently ignored or interrupting unrelated users.
- TCP and UDP domain targets are checked again against `forbidden_ip` after resolution, using the final IP selected for the outbound connection. UDP sessions pin up to 64 resolved domains locally, preventing per-packet DNS amplification and DNS rebinding within a session.
- Removing a user, changing its key or tightening its security policy cancels that user's existing TCP and UDP sessions at the next successful policy synchronization.
- When the database backlog cannot be flushed, newly captured traffic is appended to the durable outbox before the reporting cycle returns an error, reducing the hard-stop loss window.
- UDP decryption failures are counted and emitted as periodic aggregates instead of producing one warning per rejected packet.
- The release workflow addresses GitHub explicitly and refuses to overwrite existing release assets.

## Requirements

- Go 1.26 or the exact version declared by `go.mod`.
- A compatible SSPanel MySQL schema.
- An `ss_node` record whose `sort` is `14` and whose `server` value follows `host;port;base64-server-key`.
- A writable, persistent data directory for the credential snapshot and traffic outbox. The defaults use `/var/lib/sshappy`.

## Build

```sh
go mod download
go build -trimpath -o sstest ./cmd/sstest
```

The upstream commands can also be built directly:

```sh
go build -trimpath ./cmd/shadowsocks-go
go build -trimpath ./cmd/shadowsocks-go-domain-set-converter
```

## Run

Do not commit real database passwords, node keys or user credentials. Supply them through the process environment or a secret manager.

```sh
NODE_ID=116 \
MYSQL_HOST=127.0.0.1 \
MYSQL_DB=sspanel \
MYSQL_USER=sshappy \
MYSQL_PASS='replace-with-a-secret' \
./sstest
```

MySQL TLS is disabled by default for this deployment. This sends database credentials and queries in plaintext; use it only on a trusted private network, an encrypted tunnel such as WireGuard, and firewall rules that prevent public access. Deployments with database TLS can still opt into `MYSQL_TLS_MODE=verify` with a trusted CA.

See [configuration](docs/configuration.md) for all environment variables and [operations](docs/operations.md) for data durability, shutdown and rollback guidance.
See the [4.6 release notes](docs/4.6-release-notes.md), the inherited [4.5 release notes](docs/4.5-release-notes.md), and the inherited [4.3.1 remaining work](docs/4.3.1-remaining-work.md).

Automatic traffic-marker cleanup is disabled by default. Do not enable it without first reading the single-instance and recovery-window requirements in the operations guide.

Downstream Go integrations that provide a custom `stats.Collector` must add the explicit `CollectTCPSessionStart` and `CollectUDPSessionStart` methods introduced in 4.3. Traffic-delta calls no longer double as session-start events.

## Test

```sh
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./internal/panel ./service ./api/... ./cred ./dns ./direct ./conn ./stats
go test -race -count=1 ./ss2022 -run '^(TestShadowStreamConnConcurrentReadsAndWrites|TestShadowStreamBulkCopyWrappedReaderDoesNotDeadlock|TestPSKLengthErrorRedactsPSK|TestCipherConfigsCloneKeyInputsAndSliceOutputs)$'
```

The MySQL integration test requires a disposable database/schema and is intentionally opt-in:

```sh
SSHAPPY_TEST_MYSQL_DSN='user:password@tcp(127.0.0.1:3306)/disposable_database?parseTime=true' \
go test -count=1 -v ./internal/panel -run '^TestMySQL'
```

Never point this integration test at production: it creates fixed table names.

## Repository layout

- `cmd/sstest`: SSPanel-managed node process.
- `internal/panel`: MySQL adapter, policy, accounting, outbox and operational reporting.
- `service`: TCP/UDP relay lifecycle and limits.
- `ss2022`: Shadowsocks 2022 crypto and protocol implementation.
- `cred`: dynamic user credential manager.
- `dns`, `router`, `direct`: name resolution and outbound routing.
- `api`, `stats`: management API and traffic statistics.
- `.github/workflows`: build, test and release validation.

## Docker image

The reviewed container build is intentionally limited to `linux/amd64`. It uses a minimal Debian 12 distroless/static runtime and is intended for Docker Engine on Debian 11 and newer Linux hosts:

```sh
docker buildx build \
  --platform linux/amd64 \
  --build-arg VERSION=4.6 \
  --build-arg COMMIT="$(git rev-parse --short=12 HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --load -f Dockerfile.sstest \
  -t sadno/sstest:4.6 .
```

See [Docker deployment](docs/docker.md) for persistent state, privileged relay ports, optional non-root execution, TCP/UDP publication, MySQL and shutdown requirements.

## Security

Please report suspected vulnerabilities privately to the repository owner. Logs and bug reports must redact MySQL DSNs, passwords, PSKs, user credential files and traffic outbox contents.
