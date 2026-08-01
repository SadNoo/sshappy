# Operations, upgrade and rollback

## Durable state

The credential snapshot and traffic outbox are runtime state, not temporary cache. Put `/var/lib/sshappy` (or configured paths) on persistent local storage that survives process and container replacement.

Version 4.4 uses a SQLite WAL outbox. Its main file, `-wal` and `-shm` sidecars form one state unit; a rollback journal may also appear during recovery. A lifetime lock on the stable state-directory inode is authoritative, while the adjacent persistent `.lock` file is also locked and provides a visible per-outbox ownership marker. A short-lived `.init` marker authenticates only an interrupted first-time initialization and is atomically created and removed after validation. The queue uses transactional writes, `synchronous=FULL`, foreign-key checks, an explicit schema/application ID and a canonical SHA-256 payload check. It freezes the node ID and traffic rate when traffic is captured, so replay does not silently adopt a later billing context.

The state directory must be private and must provide reliable local locking, atomic rename and sync semantics. One active 4.4 process owns the whole state directory; place only one node/outbox in it. A second process is rejected by a nonblocking directory lock even if the visible `.lock` is moved, and the active writer then fails closed when it detects that marker replacement. Operators must never move, delete, copy, edit or replace outbox/lock files while `sstest` is running. Never run two `sstest` processes—including 4.3.1 and 4.4—against the same state directory. A shared/network filesystem is unsupported unless the exact platform has been certified for SQLite WAL and its process locks.

If an outbox is malformed, corrupt, replaced, symlinked or has an unsupported schema, startup/operation fails closed and preserves the state for offline reconciliation. Do not work around the check by deleting a queue with unknown pending traffic. Back it up with restrictive permissions and reconcile it without publishing its contents.

On supported Unix systems, newly created outbox directories use mode `0700` and files use `0600`. Existing state with broader permissions is rejected and left unchanged; 4.4 never silently tightens permissions on an operator-owned file. Credential files are also owner-only. Version 4.4 refuses to start on Windows, Plan 9, JavaScript/WASM and WASI because its required single-writer outbox lock is unavailable there.

Monitor:

- pending outbox batches, users, records, bytes and oldest age;
- total size of the SQLite main/WAL/shared-memory/rollback-journal files;
- free bytes on the outbox filesystem;
- database operation health and latency;
- rejected TCP handshakes/connections and UDP sessions;
- node heartbeat freshness.

`OUTBOX_MIN_FREE_BYTES` remains an operational warning threshold rather than a complete admission-control policy. A local outbox persistence or integrity failure stops service immediately.

Every runtime MySQL call uses the configured connect/I/O deadline. A normal traffic cycle replays at most 64 durable batches before returning to authorization and status work. Shutdown first commits the newest in-memory counters to SQLite, then replays until the I/O deadline; a remote timeout leaves those batches durable for the next start. Checked accounting arithmetic rejects raw, rated, aggregate or duplicate-user totals that would exceed `int64` instead of wrapping them.

## Database safety and migration

Version 4.4 performs no runtime DDL. Apply `migrations/mysql/0001_traffic_batch.sql` before startup with a dedicated migration account. Startup validates schema version 1, the migration name, InnoDB engines, required columns, primary keys and the `node_created_at` index. `CREATE TABLE IF NOT EXISTS` does not repair an incompatible pre-existing table; if validation rejects one, preserve it and perform a reviewed compatibility migration rather than altering production ad hoc.

The database used by this deployment cannot negotiate TLS. The migration client must use `--ssl-mode=DISABLED` and the runtime must use `MYSQL_TLS_MODE=disabled`. These transmit credentials and queries in plaintext; keep the database on a trusted private network and deny public ingress. Do not put a DSN or password in command-line arguments, logs, issue reports or committed files. Detailed commands and verification are in [MySQL migration](mysql-migration.md).

The version 1 migration is additive: it preserves a compatible `sshappy_traffic_batch` table created by 4.3.1 and adds the migration record table. Leave both tables in place during rollback; 4.3.1 ignores the migration record table and continues to use the traffic marker table.

Automatic idempotency-marker cleanup is disabled by default. Enable it only when exactly one active reporter owns the node and the retention period exceeds the oldest possible outbox, backup and disaster-recovery replay. Cleanup is not coordinated with another host's old queue. If those conditions cannot be guaranteed, leave `TRAFFIC_BATCH_RETENTION_DAYS=0` and use an externally coordinated archival procedure.

## Graceful shutdown

Stop with `SIGTERM` or `SIGINT`. Allow enough time for relay shutdown, final traffic capture/replay and the SQLite WAL checkpoint/close. Avoid `SIGKILL`, which prevents graceful accounting and database close. Container deployments should retain a stop timeout of at least 120 seconds.

Before replacing or downgrading a node, require the outbox pending-batch count to reach zero. A persistent queue makes restart safe; it does not make a downgrade to an incompatible queue format safe.

`AUTH_STALE_GRACE_SECONDS` bounds how long the last successful authorization snapshot may remain active after a transient node/user/credential refresh or traffic-accounting error. A successful refresh clears only that refresh failure, and a successful traffic flush clears the accounting failure. An authoritative node deletion, bandwidth-limit breach, invalid node type, invalid server/key configuration, or local durability failure stops service immediately.

## Upgrade from 4.3.1 to 4.4.0

The 4.3.1 JSON queue and 4.4 SQLite queue are not interchangeable. There is deliberately no automatic converter.

1. Pin the current deployment and rollback materials to the immutable `4.3.1` branch, `v4.3.1` tag and `sadno/sstest:4.3.1@sha256:fd8a3091597a3aff699ea51e254477781f6927493f38cf3814b6067aff09dfe6` image.
2. While 4.3.1 is still the only writer, restore database connectivity and wait until its JSON outbox reports zero pending batches. Do not continue while any traffic remains queued.
3. Stop 4.3.1 gracefully. Confirm that its process/container has exited and no second writer uses the state directory.
4. Back up the complete state directory, the drained JSON outbox if it still exists, the configuration and the MySQL schema. Keep permissions restrictive.
5. Apply `migrations/mysql/0001_traffic_batch.sql` with `mysql --ssl-mode=DISABLED`, then verify migration version 1.
6. Change `TRAFFIC_OUTBOX_PATH` from the legacy JSON name to `/var/lib/sshappy/traffic-outbox.sqlite3`. Preserve the JSON backup; never rename or copy it over the new path.
7. Deploy `sadno/sstest:4.4.0` (or its recorded digest) to one canary node. Ensure `MYSQL_TLS_MODE=disabled` is explicit.
8. On TCP and UDP port 1023, verify authentication, forbidden-target enforcement, resolved-IP checks, session revocation, accounting replay, online state and graceful restart.
9. Expand gradually while watching MySQL validation, outbox age/size, traffic totals and database failures.

If the configured SQLite path contains the old JSON file, 4.4 fails startup without overwriting it. Correct the path only after confirming the old queue was drained and backed up.

## Roll back from 4.4.0 to 4.3.1

1. Keep 4.4 running as the sole writer until its SQLite outbox reports zero pending batches. If the database is unavailable or the queue cannot drain, stop the rollback: preserve the SQLite files and reconcile them before changing versions.
2. Stop 4.4 gracefully and confirm it has exited. Back up the SQLite main file and any remaining sidecars together with the state directory.
3. Keep the version 1 MySQL migration tables; they are backward compatible with 4.3.1.
4. Restore the 4.3.1 configuration, including its JSON outbox path. Use only the previously drained/archived JSON state; never point 4.3.1 at the SQLite file.
5. Start the immutable `sadno/sstest:4.3.1` image pinned by the recorded digest. Do not let it overlap with a 4.4 writer.
6. Verify heartbeat, user synchronization, TCP/UDP port 1023 and traffic reporting before returning to full load.

There is no supported downgrade that carries pending SQLite batches into 4.3.1. Draining first is mandatory; manual database reconciliation is required if drain is impossible.

## Earlier rollback chain

The 4.3.1 baseline retains its documented sequential rollback to `v4.3.0` and then 4.2 because those versions share the legacy JSON format. Complete the 4.4-to-4.3.1 procedure first, with an empty SQLite queue, then follow the documentation shipped with the chosen older release. Never skip directly from a pending 4.4 SQLite queue to a JSON-only version.

## Explicitly deferred behavior

Version 4.4 does not claim real-time quota reservation or speed-limit enforcement. Correct behavior depends on unresolved product choices: global versus per-node quota, raw versus rated bytes, reset/top-up behavior, outage overshoot, multi-node fencing, rate units, burst size, direction sharing, drop/queue policy and hot updates. Until those semantics and their database contract are approved, authorization continues to use committed SSPanel counters plus the configured fail-closed accounting window.
