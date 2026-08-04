# Operations and rollback

## Durable state

The credential snapshot and traffic outbox are runtime state, not temporary cache. Place `/var/lib/sshappy` (or the configured paths) on storage that survives process replacement and host/container upgrades.

Back up the directory with restrictive permissions. Never edit the outbox while `sstest` is running. If it cannot be decoded, the process leaves the file unchanged, reports its path and refuses every restart. Preserve it for offline diagnosis without publishing its contents; back it up and explicitly reconcile, repair or manually move it before restarting. The process never treats an invalid accounting queue as an empty queue.

On Unix, credential files are normalized to owner-only mode before loading. On Windows and other non-Unix systems, provision a private parent-directory and file ACL explicitly; POSIX mode `0600` is not a substitute for a restrictive DACL.

Monitor:

- outbox batch count, file size and oldest batch age;
- free bytes on the outbox filesystem;
- database operation health and latency;
- rejected TCP handshakes/connections and UDP sessions;
- node heartbeat freshness.

## Database safety

Use a dedicated MySQL account. TLS is disabled by default, so keep plaintext database traffic on a trusted private network or encrypted tunnel protected from public access. Deployments that can use TLS should prefer `MYSQL_TLS_MODE=verify` with a trusted CA. Do not put a full DSN or password in command-line arguments, logs, issue reports or committed files.

Database schema changes should be applied before starting a new binary and remain backward compatible until rollback is no longer required. A production runtime account should not be relied upon to perform arbitrary DDL.

## Graceful shutdown

Stop the process with `SIGTERM` or `SIGINT`. Allow enough time for relay shutdown, long-connection accounting and final outbox persistence. Avoid `SIGKILL` unless the process cannot make progress; it prevents graceful accounting and log flush.

Before replacing a node, check that the outbox is either empty or stored on persistent media that the replacement process will reuse.

`AUTH_STALE_GRACE_SECONDS` bounds how long the last successful node/user/credential snapshot may remain active after a transient refresh failure. Once the first authorization failure is observed, an independent timer cancels the relay at the deadline even if another database operation is still running. Traffic-accounting database failures do not cancel the relay while each new interval can still be persisted to the local outbox. An authoritative node deletion, bandwidth-limit breach, invalid node type, invalid server/key configuration, or any local outbox write/remove failure stops service immediately.

Automatic idempotency-marker cleanup is disabled by default. It is safe to enable only when exactly one active reporter owns the node and the configured retention exceeds the oldest outbox, backup and disaster-recovery image that could ever be replayed. Cleanup is not protected by the per-batch advisory lock against another host's old outbox. If those conditions cannot be guaranteed, leave `TRAFFIC_BATCH_RETENTION_DAYS=0` and manage marker archival with an externally coordinated procedure.

## 4.5 rollout

1. Preserve the existing `v4.3.1` deployment, image digest and configuration as the direct rollback target.
2. Back up the durable state directory and database schema.
3. Deploy `sadno/sstest:4.5` to a canary node with the same schema but an isolated node ID when possible.
4. On port 1023, verify authentication, strict forbidden-target parsing, final resolved-IP checks, active TCP/UDP session revocation, durable accounting during a database backlog, aggregated UDP rejection logs, online state and graceful restart.
5. Expand gradually while watching outbox age, traffic totals and database errors.

## Rollback to the 4.3.1 baseline

1. Stop 4.5 gracefully and ensure it is the only writer using the state directory.
2. Preserve the state directory, then start the image recorded for `sadno/sstest:4.3.1` or the binary from `v4.3.1`.
3. Reuse the durable outbox only after 4.5 has fully stopped. Its JSON shape and flush-time billing rule remain compatible.
4. Verify heartbeat, user synchronization, TCP/UDP relay and traffic replay before restoring full load.

The `v4.3.1` tag and `sadno/sstest:4.3.1` image are immutable rollback references. Never move or overwrite them.

## Older rollback to 4.2

1. Stop 4.5 gracefully and preserve its state directory.
2. Reuse the preserved outbox only after the 4.5 process has stopped. 4.5 intentionally writes the exact 4.3.1/4.2 single-/multi-batch JSON formats, so no outbox conversion is required. All versions apply the node/rate current at flush time.
3. Start the binary built from branch `4.2` (baseline commit `39a795f`) with the preserved pre-upgrade configuration.
4. Verify heartbeat, user synchronization and traffic reporting before returning the node to full load.

If a schema migration is not backward compatible, use its documented rollback migration or restore the pre-upgrade backup before starting 4.2.
