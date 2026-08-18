# sshappy 4.6 Docker image for Debian 11+ hosts

The 4.6 Dockerfile intentionally builds one platform: `linux/amd64`. Its runtime is Debian 12 distroless/static, which can run on supported Docker Engine installations on Debian 11 and newer hosts.

The image does not contain a shell, package manager, database credentials, node keys, user credentials or a MySQL CA. It retains the Debian CA bundle and timezone data needed by a static Go service.

## Build

Run this from the 4.6 repository root:

```sh
docker buildx build \
  --platform linux/amd64 \
  --pull \
  --build-arg VERSION=4.6 \
  --build-arg COMMIT="$(git rev-parse --short=12 HEAD)" \
  --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --load \
  -f Dockerfile.sstest \
  -t sadno/sstest:4.6 .
```

The base images are pinned by digest. Updating either digest is a reviewed dependency change, not an automatic tag refresh.

Version 4.6 is based directly on 4.5, whose base remains `v4.3.1` and does not inherit either `v4.4.x` tag. Preserve `sadno/sstest:4.5` as the immediate rollback image and record the 4.6 registry digest before deployment.

## Runtime state, user and secrets

The image runs as root by default so a panel-managed relay port in the `1`–`1023` range works without an image-level restriction. The distroless base also contains an optional UID/GID `65532:65532` account for deployments that use only unprivileged ports.

Mount the entire `/var/lib/sshappy` directory read-write because credential and traffic-outbox updates use temporary files plus atomic rename in that directory. Use one volume per node and one active writer; never share the same outbox between replicas.

A Docker named volume inherits the image directory ownership on first use:

```sh
docker volume create sshappy-node
```

For a bind mount used with the optional non-root account, create the host directory as UID/GID 65532 with mode `0700`. Keep the environment file outside the source tree, owned by the deployment administrator and mode `0600`. Docker environment variables remain visible to principals with Docker API access, so access to the daemon must also be restricted.

If `MYSQL_TLS_MODE=verify` uses a private CA, mount that file read-only and set `MYSQL_TLS_CA` to its container path. Do not copy the CA or password into the image.

MySQL TLS is disabled by default and does not need an environment argument. Plaintext exposes database credentials and queries to the network; keep the connection on a trusted private network or encrypted tunnel and block public access to MySQL.

## Run on a privileged relay port

The relay port comes from `ss_node.server`, so the image cannot declare a fixed `EXPOSE`. The example deliberately uses privileged port `1023`; replace it with the port configured in the database and publish both protocols:

```sh
docker run -d \
  --name sshappy \
  --platform linux/amd64 \
  --restart unless-stopped \
  --stop-timeout 120 \
  --env-file /secure/path/sshappy.env \
  --mount type=volume,src=sshappy-node,dst=/var/lib/sshappy \
  -p 1023:1023/tcp \
  -p 1023:1023/udp \
  sadno/sstest:4.6
```

The default root user already supports ports below 1024; the image does not require `--privileged`, `NET_ADMIN` or `NET_RAW`. A deployment may optionally reduce capabilities while retaining a privileged port with `--cap-drop ALL --cap-add NET_BIND_SERVICE --security-opt no-new-privileges:true`. If it uses only ports 1024 or higher, it may instead add `--user 65532:65532`.

With bridge networking, `MYSQL_HOST=127.0.0.1` points to the container itself. Use a database service name on a shared Docker network, a host-gateway address, or Linux host networking where its broader network exposure is acceptable.

The application handles `SIGTERM` and persists/retries final accounting during shutdown. Keep at least a 120-second stop timeout and avoid `SIGKILL`.

## Verification

```sh
docker image inspect sadno/sstest:4.6 \
  --format 'platform={{.Os}}/{{.Architecture}} user={{.Config.User}} entrypoint={{json .Config.Entrypoint}}'
```

The expected platform is `linux/amd64`, the default user is `0:0`, and the entrypoint is `/usr/local/bin/sstest`. Distroless intentionally has no `/bin/sh`; inspect logs and image metadata instead of opening a shell. To use the optional non-root mode, add `--user 65532:65532` and use a volume writable by that UID/GID.

There is no fixed unauthenticated health endpoint. A synthetic `kill -0 1` check adds no information beyond the container state, while probing the relay port creates invalid Shadowsocks handshakes. Use the process exit status/restart policy plus external SS2022 authentication, panel heartbeat and outbox monitoring.
