# sshappy 4.3.1

`sshappy` is a Go implementation of a Shadowsocks 2022 node with an SSPanel-compatible runtime. This repository keeps the upstream `shadowsocks-go` server and domain-set converter, and adds `sstest`, which loads node/user policy from MySQL, enforces runtime limits, reports traffic and online state, and persists unreported traffic locally for retry.

Version 4.3.1 is developed on the `4.3.1` branch from the immutable `v4.3.0` baseline. The `4.3` branch, the `v4.3.0` Git tag, and the `sadno/sstest:4.3` and `sadno/sstest:4.3.0` images are frozen rollback references and must not be moved, rebuilt or overwritten. The traffic-outbox JSON remains byte-shape compatible with 4.2 for both its single- and multi-batch forms; as in 4.2, a recovered batch uses the node ID and traffic rate current when it is flushed.

## 4.3.1 hardening

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
MYSQL_TLS_MODE=disabled \
./sstest
```

The database used by this deployment cannot negotiate TLS, so its examples explicitly set `MYSQL_TLS_MODE=disabled`. This sends database credentials and queries in plaintext; use it only on a trusted private network with firewall rules that prevent public access. The application default remains `auto` for other deployments.

See [configuration](docs/configuration.md) for all environment variables and [operations](docs/operations.md) for data durability, shutdown and rollback guidance.
Known items that require a product contract, schema migration or further deployment work are tracked in [4.3.1 remaining work](docs/4.3.1-remaining-work.md).

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
  --build-arg VERSION=4.3.1 \
  --build-arg COMMIT="$(git rev-parse --short=12 HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --load -f Dockerfile.sstest \
  -t sadno/sstest:4.3.1 .
```

See [Docker deployment](docs/docker.md) for persistent state, privileged relay ports, optional non-root execution, TCP/UDP publication, MySQL and shutdown requirements.

## Security

Please report suspected vulnerabilities privately to the repository owner. Logs and bug reports must redact MySQL DSNs, passwords, PSKs, user credential files and traffic outbox contents.
