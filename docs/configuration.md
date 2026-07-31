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
| `TRAFFIC_OUTBOX_PATH` | `/var/lib/sshappy/traffic-outbox.json` | Unreported traffic queue. Must be on persistent storage. |
| `TRAFFIC_BATCH_RETENTION_DAYS` | `0` | Database idempotency-marker retention; zero disables automatic cleanup and is the safe default. |
| `OUTBOX_MIN_FREE_BYTES` | `268435456` | Minimum desired free space near the outbox. |

The process account needs read/write access to the two state files and their parent directory. Do not expose either file through a web server, support bundle or source-control checkout.

The 4.3 outbox deliberately uses the exact 4.2 JSON fields and wrapper version so the same durable state can be reused after a sequential rollback. Billing also keeps the 4.2 rule: the node ID and traffic rate are read from the current node when a batch is flushed, not when it is captured. A rate change while traffic is pending therefore applies the new rate to the recovered batch. Back up the state directory before upgrading, and do not move one node's outbox to a different node.

Set `TRAFFIC_BATCH_RETENTION_DAYS` above zero only for a single active reporter for that node and only when the retention period exceeds every possible outbox, backup and disaster-recovery replay window. Cleanup is not coordinated with another host's outbox.

## SSPanel data contract

The node must be an SS single-port node (`sort=14`). Its `server` field is parsed as:

```text
host;port;base64-server-key
```

The server and user keys must decode to 32 bytes for `2022-blake3-aes-256-gcm`. The adapter reads users, node limits and restrictions, and writes traffic, heartbeat, online-user, alive-IP and resource information. Run schema changes through a controlled migration and grant the runtime account only the permissions required by the deployed schema.
