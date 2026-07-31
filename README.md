# sshappy 4.3

`sshappy` is a Go implementation of a Shadowsocks 2022 node with an SSPanel-compatible runtime. This repository keeps the upstream `shadowsocks-go` server and domain-set converter, and adds `sstest`, which loads node/user policy from MySQL, enforces runtime limits, reports traffic and online state, and persists unreported traffic locally for retry.

Version 4.3 is developed on the `4.3` branch created from the immutable `4.2` baseline. Switching a deployment back to the `4.2` branch or its pinned commit provides the rollback path. The traffic-outbox JSON remains byte-shape compatible with 4.2 for both its single- and multi-batch forms; as in 4.2, a recovered batch uses the node ID and traffic rate current when it is flushed.

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

For a remote database, the default TLS mode is `auto`; use `MYSQL_TLS_MODE=verify` together with `MYSQL_TLS_CA=/path/to/ca.pem` when certificate verification is required.

See [configuration](docs/configuration.md) for all environment variables and [operations](docs/operations.md) for data durability, shutdown and rollback guidance.
Known items that require a product contract, schema migration or a later container phase are tracked in [4.3 remaining work](docs/4.3-remaining-work.md).

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

## Security

Please report suspected vulnerabilities privately to the repository owner. Logs and bug reports must redact MySQL DSNs, passwords, PSKs, user credential files and traffic outbox contents.

The Docker image workflow is deliberately not part of the 4.3 branch-completion step; image creation and publication should only happen after this branch is reviewed and approved.
