# sshappy 4.4.0

`sshappy` is a Go implementation of a Shadowsocks 2022 node with an SSPanel-compatible runtime. The repository keeps the upstream `shadowsocks-go` server and domain-set converter, and adds `sstest`, which loads node/user policy from MySQL, enforces runtime restrictions, reports traffic and online state, and durably retries unreported traffic.

Version 4.4.0 is developed on the `4.4` branch from the immutable 4.3.1 rollback baseline. Preserve the `4.3.1` branch, `v4.3.1` tag and `sadno/sstest:4.3.1` image; do not move the tag or rebuild/overwrite that image tag.

## 4.4 changes

- The traffic outbox is now a transactional SQLite WAL queue instead of a whole-file JSON rewrite. Each batch freezes the node ID and traffic rate at capture time and carries a canonical SHA-256 payload check.
- A legacy 4.3.1 JSON outbox is never overwritten or silently converted. Startup preserves a non-SQLite file and fails with a reconciliation error.
- A private process lock prevents two 4.4 writers from opening one outbox. Existing state with permissive modes, symlinks or hard links is rejected without changing it, and interrupted first-time initialization is recovered through an atomic marker.
- MySQL schema setup is an explicit, versioned migration. The runtime validates the migration record, table engine, columns and indexes at startup and no longer performs DDL.
- Runtime MySQL operations have explicit deadlines. Normal accounting cycles replay at most 64 durable batches before returning to other work, final shutdown captures new counters before replay, and billing arithmetic rejects integer overflow instead of wrapping.
- Release archives and the container image include the exact MySQL migration used by this version.
- The strict target-policy parsing, resolved-IP checks, active-session revocation and bounded UDP domain cache from 4.3.1 remain in place.

Quota enforcement during accounting outages and node/user speed limiting are intentionally not implemented in 4.4. Their units, scope, multi-node coordination, burst behavior and update semantics require an explicit product contract before a safe implementation can be chosen. See [4.4 release notes](docs/4.4-release-notes.md).

## Requirements

- Go 1.26 or the exact version declared by `go.mod`.
- A compatible SSPanel MySQL schema with [the 4.4 migration](docs/mysql-migration.md) applied before startup.
- An `ss_node` record whose `sort` is `14` and whose `server` value follows `host;port;base64-server-key`.
- A private, writable and persistent data directory for the credential snapshot and SQLite outbox. Defaults use `/var/lib/sshappy`.

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

## Migrate and run

Stop 4.3.1 and completely drain and back up its JSON outbox before starting 4.4. Never run both versions against the same state directory. Apply the migration with a separate DDL-capable account; the password is prompted rather than placed on the command line:

```sh
mysql \
  --protocol=TCP \
  --host=127.0.0.1 \
  --port=3306 \
  --user=sshappy_migrator \
  --password \
  --ssl-mode=DISABLED \
  sspanel < migrations/mysql/0001_traffic_batch.sql
```

The database used by this deployment cannot negotiate TLS, so the migration uses `--ssl-mode=DISABLED` and the runtime uses `MYSQL_TLS_MODE=disabled`. Both connections are plaintext: keep them on a trusted private network and prevent public access to MySQL.

Do not commit real database passwords, node keys or user credentials. Supply them through the process environment or a secret manager:

```sh
NODE_ID=116 \
MYSQL_HOST=127.0.0.1 \
MYSQL_DB=sspanel \
MYSQL_USER=sshappy \
MYSQL_PASS='replace-with-a-secret' \
MYSQL_TLS_MODE=disabled \
TRAFFIC_OUTBOX_PATH=/var/lib/sshappy/traffic-outbox.sqlite3 \
./sstest
```

See [configuration](docs/configuration.md), [MySQL migration](docs/mysql-migration.md), [operations and rollback](docs/operations.md), and [Docker deployment](docs/docker.md).

Automatic traffic-marker cleanup remains disabled by default. Do not enable it until the single-writer and recovery-window conditions in the operations guide are satisfied.

Downstream Go integrations that provide a custom `stats.Collector` must implement the explicit `CollectTCPSessionStart` and `CollectUDPSessionStart` methods introduced in 4.3. Traffic-delta calls do not double as session-start events.

## Test

```sh
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./internal/panel ./service ./api/... ./cred ./dns ./direct ./conn ./stats
go test -race -count=1 ./ss2022 -run '^(TestShadowStreamConnConcurrentReadsAndWrites|TestShadowStreamBulkCopyWrappedReaderDoesNotDeadlock|TestPSKLengthErrorRedactsPSK|TestCipherConfigsCloneKeyInputsAndSliceOutputs)$'
```

The MySQL integration test requires a disposable database/schema and is intentionally opt-in. It applies the repository migration itself:

```sh
SSHAPPY_TEST_MYSQL_DSN='user:password@tcp(127.0.0.1:3306)/disposable_database?parseTime=true' \
go test -count=1 -v ./internal/panel -run '^TestMySQL'
```

Never point this integration test at production: it creates fixed table names.

## Repository layout

- `cmd/sstest`: SSPanel-managed node process.
- `internal/panel`: MySQL adapter, policy, accounting, SQLite outbox and operational reporting.
- `migrations/mysql`: versioned MySQL migrations applied before runtime startup.
- `service`: TCP/UDP relay lifecycle and limits.
- `ss2022`: Shadowsocks 2022 crypto and protocol implementation.
- `cred`: dynamic user credential manager.
- `dns`, `router`, `direct`: name resolution and outbound routing.
- `api`, `stats`: management API and traffic statistics.
- `.github/workflows`: build, test and release validation.

## Docker image

The reviewed image is intentionally `linux/amd64`, uses Debian 12 distroless/static userland and is intended for Docker Engine on Debian 11 and newer Linux hosts. A real Debian 11 amd64 host has not yet completed production acceptance certification.

```sh
docker buildx build \
  --platform linux/amd64 \
  --build-arg VERSION=4.4.0 \
  --build-arg COMMIT="$(git rev-parse --short=12 HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --load -f Dockerfile.sstest \
  -t sadno/sstest:4.4.0 \
  -t sadno/sstest:4.4 .
```

The default root user permits panel-managed relay ports below 1024; `sstest` does not impose a low-port restriction. Deployment examples use TCP and UDP port 1023.

## Security

Please report suspected vulnerabilities privately to the repository owner. Logs and bug reports must redact MySQL DSNs, passwords, PSKs, user credential files and all outbox contents. The release image and archives contain schema-only migration SQL, never deployment credentials.
