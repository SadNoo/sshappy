# Configuration

`sstest` reads configuration from environment variables. Invalid values fail startup; they must not silently fall back to a default.

## Required identity and database settings

| Variable | Default | Description |
| --- | --- | --- |
| `NODE_ID` | none | Positive SSPanel node ID. The legacy alias `node_id` is also accepted. |
| `MYSQL_HOST` | `127.0.0.1` | MySQL host. Legacy alias: `MYSQLHOST`. |
| `MYSQL_PORT` | `3306` | MySQL port. Legacy alias: `MYSQLPORT`. |
| `MYSQL_DB` | `sspanel` | Database/schema name. Legacy alias: `MYSQLDBNAME`. |
| `MYSQL_USER` | `root` | Database user. Legacy alias: `MYSQLUSR`. |
| `MYSQL_PASS` | empty | Database password. Legacy alias: `MYSQLPASSWD`. |
| `MYSQL_TLS_MODE` | `auto` | `auto`, `disabled`, `preferred`, `required`, or `verify`. |
| `MYSQL_TLS_CA` | empty | PEM CA file; required when TLS mode is `verify`. |
| `MYSQL_CONNECT_TIMEOUT_SECONDS` | `10` | Positive connection timeout. |
| `MYSQL_IO_TIMEOUT_SECONDS` | `30` | Positive read/write timeout. |

`auto` disables TLS only for loopback/localhost and otherwise requires an encrypted connection. `verify` additionally validates the server certificate against `MYSQL_TLS_CA` and the configured host name.
`disabled` permits plaintext authentication and queries; use it only when the database cannot support TLS and the connection stays on a trusted private network.

The database used by this deployment cannot negotiate TLS, so its 4.4 environment example explicitly sets `MYSQL_TLS_MODE=disabled`. Do not expose that database connection to the public Internet; restrict it to the node and database hosts on a trusted private network. The separate migration command must likewise use `mysql --ssl-mode=DISABLED`; see [MySQL migration](mysql-migration.md).

If both a standard name and its legacy alias are present, keep their values identical. Legacy aliases are retained for compatibility and should be removed from new deployments.

## Listener and synchronization settings

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_HOST` | `0.0.0.0` | TCP/UDP bind host; IPv4 and IPv6 literals are supported. |
| `ENABLE_TCP` | `true` | Enable TCP relay. |
| `ENABLE_UDP` | `true` | Enable UDP relay. At least one relay must be enabled. |
| `SYNC_INTERVAL_SECONDS` | `60` | Node and user policy refresh interval. |
| `AUTH_STALE_GRACE_SECONDS` | `300` | Hard deadline after the first node/user/credential refresh or traffic-accounting failure. The relay is canceled at the deadline even while the runner is busy. Zero fails closed on the first failure. |
| `TRAFFIC_REPORT_SECONDS` | `60` | Traffic capture/report interval. |
| `NODE_REPORT_SECONDS` | `60` | Heartbeat and online-count interval. |
| `ALIVE_IP_REPORT_SECONDS` | `60` | Alive-IP report interval. |
| `RESOURCE_REPORT_SECONDS` | `60` | Operational metrics log interval; minimum 10. |

## TCP settings

| Variable | Default | Description |
| --- | --- | --- |
| `TCP_MAX_CONCURRENT_HANDSHAKES` | `1024` | Maximum simultaneous handshakes. |
| `TCP_MAX_CONNECTIONS_PER_USER` | `800` | Per-user connection cap; zero disables this cap. |
| `TCP_MAX_ESTABLISHED_TOTAL` | `0` | Total established-connection cap; zero disables it. |
| `TCP_TRAFFIC_FLUSH_SECONDS` | `30` | Interval for moving long-connection traffic into accounting. |

## UDP settings

| Variable | Default | Description |
| --- | --- | --- |
| `UDP_MTU` | `1496` | MTU, accepted range 1280–65535. |
| `UDP_RELAY_BATCH_SIZE` | `8` | Relay batch size, accepted range 1–1024. |
| `UDP_SERVER_RECV_BATCH_SIZE` | `64` | Server receive batch, accepted range 1–1024. |
| `UDP_SEND_CHANNEL_CAPACITY` | `1024` | Per-session send queue; minimum 64. |
| `UDP_NAT_TIMEOUT_SECONDS` | `60` | Session idle timeout; minimum 60 for SS2022. |
| `UDP_MAX_SESSIONS` | `2048` | Maximum concurrent sessions. |
| `UDP_MAX_SESSIONS_PER_USER` | `128` | Per-user session maximum, no greater than the global maximum. |

## Durable state and accounting

| Variable | Default | Description |
| --- | --- | --- |
| `UPSK_STORE_PATH` | `/var/lib/sshappy/users.json` | Credential snapshot used by the managed relay. |
| `TRAFFIC_OUTBOX_PATH` | `/var/lib/sshappy/traffic-outbox.sqlite3` | SQLite WAL queue for unreported traffic. Must be on persistent local storage. |
| `TRAFFIC_BATCH_RETENTION_DAYS` | `0` | Database idempotency-marker retention; zero disables automatic cleanup and is the safe default. |
| `OUTBOX_MIN_FREE_BYTES` | `268435456` | Minimum desired free space near the outbox. |

The process account needs read/write access to the credential file, SQLite main file, WAL/shared-memory sidecars, persistent `.lock` file and their parent directory. On supported Unix systems, newly created outbox directories use `0700` and files use `0600`. Existing directories/files with broader permissions are rejected without an automatic `chmod`; symlinks, multiple hard links and non-regular files are also rejected. Version 4.4 refuses to start on platforms where its process-level single-writer lock is unsupported. Do not expose any state file through a web server, support bundle or source-control checkout.

Version 4.4 does not reuse the 4.3.1 JSON queue. Before upgrading, completely drain and back up `/var/lib/sshappy/traffic-outbox.json`, stop 4.3.1, and change the configured path to `/var/lib/sshappy/traffic-outbox.sqlite3`. If 4.4 encounters JSON or any other non-SQLite content at its configured path, it preserves the file and fails startup; it never overwrites or silently converts the old queue.

Each 4.4 batch freezes its node ID and canonical traffic-rate text at capture time, stores user deltas transactionally, and validates a canonical SHA-256 payload before replay. A later node/rate change therefore does not rebill already captured traffic. Billing addition/rate conversion is checked and refuses values that would overflow `int64`. Normal report cycles replay at most 64 batches and every runtime MySQL operation is bounded by its configured context deadline, keeping policy refresh and shutdown responsive while the remaining queue stays durable. Local outbox corruption, replacement or persistence failure remains immediately fatal. Never run two processes or versions against the same state directory, and do not place the WAL queue on storage that lacks reliable local filesystem locks and durability semantics.

Set `TRAFFIC_BATCH_RETENTION_DAYS` above zero only for a single active reporter for that node and only when the retention period exceeds every possible outbox, backup and disaster-recovery replay window. Cleanup is not coordinated with another host's outbox.

## SSPanel data contract

The node must be an SS single-port node (`sort=14`). Its `server` field is parsed as:

```text
host;port;base64-server-key
```

The server and user keys must decode to 32 bytes for `2022-blake3-aes-256-gcm`. The adapter reads users, node limits and restrictions, and writes traffic, heartbeat, online-user, alive-IP and resource information. Run schema changes through a controlled migration and grant the runtime account only the permissions required by the deployed schema.

Version 4.4 retains the 4.3.1 behavior that compiles `forbidden_ip`, `forbidden_port` and `disconnect_ip` rules before installing a refreshed user policy. Invalid IPs, CIDRs, ports or ranges reject only the affected user; the user is removed from the runtime policy and credential snapshot until corrected, while unrelated valid users remain available. For domain targets, both TCP and UDP validate the final resolved address selected for the outbound connection, so a domain cannot bypass an IP or CIDR restriction merely by being supplied in name form. Each UDP session pins the first resolved IP for at most 64 distinct domains; later packets recheck the pinned literal IP against the current policy without another DNS lookup, and additional new domains are rejected until a new session is created. User removal, a newly invalid policy, a security-policy change or a key/password change also cancels that user's registered TCP and UDP sessions after the successful refresh.

The runtime account does not perform DDL in 4.4. Apply `migrations/mysql/0001_traffic_batch.sql` before startup with a separate migration account. Startup rejects a missing migration record or incompatible table engine, column or index and reports the required migration path. The migration is additive and leaves the 4.3.1 traffic marker table compatible for rollback.

The `Node.SpeedLimit` and `User.NodeSpeedLimit` fields are still loaded but not enforced. Likewise, pending outbox traffic is not a distributed quota reservation. Speed units, burst/drop behavior, hierarchy, quota scope, reset rules and multi-node coordination remain deliberately undefined; 4.4 does not invent those product semantics.
