# sshappy

SSPanel-Uim `sort=14` SS2022 single-port backend.

This backend implements the SS2022 TCP server path directly so it can identify
the real SSPanel user from the SS2022 EIH user key and bill traffic to that
user. It does not store secrets in the repository; all production values are
provided by environment variables.

## Supported panel format

`ss_node.server` for `sort=14`:

```text
host;port;server_key
```

The panel subscription password must be:

```text
server_key:user_key
```

`user_key` is derived exactly like the panel code:

```text
base64(sha256(user.id + "|" + user.passwd + "|2022-blake3-aes-256-gcm|" + node.id + "|" + server_key))
```

## Run

```bash
docker run -d --name=sscodex \
  -e MYSQLHOST="database-host" \
  -e MYSQLPORT=3306 \
  -e MYSQLDBNAME="sspanel" \
  -e MYSQLUSR="sspanel_user" \
  -e MYSQLPASSWD="database-password" \
  -e node_id=14 \
  --network=host \
  --restart=always \
  sadno/sscodex:1.0
```

Optional environment variables:

```text
LISTEN_HOST=0.0.0.0
SYNC_INTERVAL_SECONDS=60
TRAFFIC_REPORT_SECONDS=60
NODE_REPORT_SECONDS=60
ALIVE_IP_REPORT_SECONDS=60
LOG_LEVEL=INFO
TCP_CONNECT_TIMEOUT=10
TCP_IDLE_TIMEOUT=300
```

## Scope of version 1.0

- Reads `sort=14` node from `ss_node`.
- Parses `host;port;server_key`.
- Reads eligible users from `user`.
- Accepts SS2022 `2022-blake3-aes-256-gcm` TCP connections with EIH.
- Maps EIH user key to SSPanel `user.id`.
- Relays TCP traffic and bills per real user.
- Writes `user.u`, `user.d`, `user.t`, `user_traffic_log`, `alive_ip`,
  `ss_node_online_log`, `ss_node_info`, `ss_node.node_heartbeat`, and
  `ss_node.node_bandwidth`.

UDP is intentionally not enabled in 1.0 until it passes interoperability tests
with real clients.

