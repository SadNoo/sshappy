# Docker image for Debian 11+ hosts

The 4.4 Dockerfile intentionally builds one platform: `linux/amd64`. Its runtime is Debian 12 distroless/static userland and is intended for supported Docker Engine installations on Debian 11 and newer Linux hosts. An OCI image cannot enforce the host distribution or version, and a real Debian 11 amd64 host has not yet completed production acceptance certification.

The image does not contain a shell, package manager, database credentials, node keys, user credentials or a MySQL CA. It includes the schema-only migration at `/usr/share/doc/sshappy/migrations/mysql/0001_traffic_batch.sql` with read-only permissions.

## Build and tags

Run this from the 4.4 repository root:

```sh
docker buildx build \
  --platform linux/amd64 \
  --pull \
  --build-arg VERSION=4.4.0 \
  --build-arg COMMIT="$(git rev-parse --short=12 HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --load \
  -f Dockerfile.sstest \
  -t sadno/sstest:4.4.0 \
  -t sadno/sstest:4.4 .
```

The base images are pinned by digest. Updating either digest is a reviewed dependency change, not an automatic tag refresh. Publish `sadno/sstest:4.4.0` and `sadno/sstest:4.4` from the same tested image and verify that both registry tags resolve to the same OCI digest. Do not publish `latest`; after publication, never overwrite the version-specific `4.4.0` tag.

The immutable rollback baseline is the `4.3.1` branch, `v4.3.1` Git tag and `sadno/sstest:4.3.1` image. Its recorded OCI digest is `sha256:fd8a3091597a3aff699ea51e254477781f6927493f38cf3814b6067aff09dfe6`; pin the digest rather than relying only on a tag. Do not move, rebuild or overwrite that baseline.

## Apply the migration first

The runtime validates schema version 1 and performs no DDL. Apply the migration before starting 4.4. Use the copy in the repository, any 4.4 release archive, or extract the read-only copy from the image. This plaintext example prompts for the migration password:

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

Use a dedicated migration account with DDL privileges, then run the container with a narrower runtime account. `--ssl-mode=DISABLED` and `MYSQL_TLS_MODE=disabled` send credentials and queries in plaintext; keep both connections on a trusted private network and block public access to MySQL. Full migration and verification steps are in [MySQL migration](mysql-migration.md).

## Runtime state, user and secrets

Mount the entire `/var/lib/sshappy` directory read-write. SQLite WAL uses the main `traffic-outbox.sqlite3` file plus `-wal`/`-shm` sidecars, a possible recovery journal, a persistent `.lock` file and a transient crash-recovery `.init` marker. It relies on an authoritative lifetime lock on the state-directory inode, the visible file lock, atomic rename and sync behavior. Use one local Docker volume per node/outbox and one active writer; a second 4.4 process is rejected even if the visible `.lock` path was moved. Do not move or delete that file while running. Do not use a shared/network filesystem unless that exact storage has been certified for SQLite WAL and its locks, and never let 4.3.1 and 4.4 write the same state directory concurrently.

New state uses private modes (`0700` directory, `0600` files). Existing permissive paths are rejected and left unchanged rather than automatically `chmod`-modified, so prepare bind-mount ownership and modes before starting the container.

The image runs as root by default so panel-managed relay ports in the `1`–`1023` range work without an image-level restriction. `sstest` accepts valid listener ports throughout `1`–`65535`; the image does not impose a minimum such as 1024. The distroless base also contains UID/GID `65532:65532` for deployments whose host permissions and chosen port allow non-root execution.

A Docker named volume inherits the image directory ownership on first use:

```sh
docker volume create sshappy-node-44
```

For a bind mount used with UID/GID 65532, create the host directory with that ownership and mode `0700`. Keep the environment file outside the source tree, owned by the deployment administrator and mode `0600`. Docker environment variables remain visible to principals with Docker API access, so restrict daemon access too.

If `MYSQL_TLS_MODE=verify` uses a private CA in another deployment, mount that file read-only and set `MYSQL_TLS_CA` to its container path. Do not copy a private CA or password into the image. For this plaintext-only database, set `MYSQL_TLS_MODE=disabled` explicitly.

## Upgrade state before running

The 4.3.1 JSON outbox and 4.4 SQLite outbox are intentionally different files and formats. Before starting this container:

1. Keep 4.3.1 running until its JSON outbox is completely empty.
2. Stop 4.3.1 gracefully, verify it is no longer running, and back up its complete state directory.
3. Preserve `traffic-outbox.json`; do not rename it over the SQLite path.
4. Set `TRAFFIC_OUTBOX_PATH=/var/lib/sshappy/traffic-outbox.sqlite3` for 4.4.
5. Apply the MySQL migration, then start exactly one 4.4 writer.

If a non-SQLite file already exists at the configured 4.4 path, startup fails and preserves it. There is no automatic JSON conversion. See [operations and rollback](operations.md) before upgrading or downgrading.

## Run on port 1023

The relay port comes from `ss_node.server`, so the image does not declare a fixed `EXPOSE`. The example deliberately publishes privileged port 1023 over both protocols; replace it with the valid port configured in the database:

```sh
docker run -d \
  --name sshappy-44 \
  --platform linux/amd64 \
  --restart unless-stopped \
  --stop-timeout 120 \
  --env-file /secure/path/sshappy.env \
  --env MYSQL_TLS_MODE=disabled \
  --env TRAFFIC_OUTBOX_PATH=/var/lib/sshappy/traffic-outbox.sqlite3 \
  --mount type=volume,src=sshappy-node-44,dst=/var/lib/sshappy \
  -p 1023:1023/tcp \
  -p 1023:1023/udp \
  sadno/sstest:4.4.0
```

The default root user supports the low port without `--privileged`, `NET_ADMIN` or `NET_RAW`. A deployment may reduce capabilities while retaining a privileged port with `--cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true` if validated with its Docker configuration.

With bridge networking, `MYSQL_HOST=127.0.0.1` points to the container itself. Use a database service name on a shared Docker network, a host-gateway address, or Linux host networking where its broader exposure is acceptable.

The application handles `SIGTERM`, durably captures final counters before remote replay, and checkpoints/closes its SQLite outbox during shutdown. MySQL replay is bounded by `MYSQL_IO_TIMEOUT_SECONDS`; a timeout leaves pending batches for the next start. Keep at least a 120-second stop timeout and avoid `SIGKILL`.

## Verification

```sh
docker image inspect sadno/sstest:4.4.0 \
  --format 'platform={{.Os}}/{{.Architecture}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}} version={{index .Config.Labels "org.opencontainers.image.version"}}'

docker buildx imagetools inspect sadno/sstest:4.4.0
docker buildx imagetools inspect sadno/sstest:4.4
```

The expected platform is `linux/amd64`, default user `0:0`, entrypoint `/usr/local/bin/sstest`, and version label `4.4.0`. Distroless intentionally has no `/bin/sh`; inspect logs, image metadata and exported files instead of opening a shell.

There is no fixed unauthenticated health endpoint. A synthetic `kill -0 1` check adds no information beyond container state, while probing the relay port creates invalid Shadowsocks handshakes. Use process status/restart policy plus external SS2022 authentication, panel heartbeat, MySQL schema validation and outbox monitoring.
