# Flysky ssbad 集成说明

本目录是 SadNoo/sshappy 的独立 Git worktree。每个候选必须从 clean、精确的 Git commit
构建；分支名不是发布身份，运行镜像必须记录完整 revision、OCI config digest 与归档 SHA-256。

## 责任

- 保留 sshappy 4.2 的 SS2022 TCP/UDP、单端口多用户和运行保护。
- 适配 Flysky /api/node/v1。
- 以快照和增量游标替换 MySQL 用户同步。
- 以幂等批量报告替换逐用户数据库更新。
- 保留本地 Outbox 和断网恢复。

## 不负责

- VMess 或其他代理协议。
- Flysky 账号、支付、订单、Web 和客户端配置生成。
- 继续扩展旧 MySQL 面板功能。

## 开工门槛

先固定 Panel OpenAPI 的 capabilities、snapshot、changes 和 usage-reports。改造顺序与验收见：

- ../docs/00-workspace-layout.md
- ../docs/06-sshappy-adaptation.md
- ../docs/05-ss2022-contract.md

正式 Flysky 构建最终不得链接 MySQL 驱动。

## 当前适配进度

控制面客户端位于 `internal/flyskyapi`，已经覆盖：

- Node API capabilities、一次性注册、机器凭据轮换与状态心跳；
- SS2022 全量快照与游标增量变更；
- HTTPS 默认强制、认证请求禁止重定向、按端点区分的有界响应和脱敏 API 错误；
- 机器凭据与同步游标的 `0600` 原子本地持久化。
- `usage-reports` 与 `alive-ips` 上报，以及严格校验服务端回执。

第二阶段运行适配位于 `internal/flyskynode`，已经覆盖：

- Flysky 正式入口只接受 `SSBAD_MODE=flysky`（未设置时也进入 Flysky）；二进制不链接旧 MySQL Panel 适配；
- UUID 用户标识、订阅有效期、剩余额度和快照 TTL 的默认拒绝授权；
- 全量 snapshot 启动、`upsert_user`/`revoke_user` 热更新和 `410` 全量恢复；
- 先持久化每用户授权版本高水位，再更新凭据、运行时与快照，最后才推进已应用 cursor；任一提交失败立即清空运行时并要求进程重启；
- 节点端口或 server key 变化返回明确的 restart required，不进行危险的半热更新；
- HTTPS 容器补充系统 CA，注册令牌只从受限文件读取并在成功换取机器凭据后尝试删除。
- UUID 流量批次与在线 IP 汇总共用 `0600` 原子 Outbox；断网时保留原 report_id 和 sequence，只有收到匹配的 `202 accepted` 才删除。
- 在线 IP 默认只离开进程的是节点级 `online_ip_count`、`active_users` 和预留连接数，不上传原始客户端 IP。
- 显式 `unlimited` 字段区分无限套餐与额度耗尽，避免把合法的零值约定误判为无额度。
- IPv4、IPv6 和双栈监听统一使用标准地址拼接。默认 `LISTEN_HOST=0.0.0.0`，保证不受宿主机 `net.ipv6.bindv6only` 设置影响；明确验证双栈内核行为后才可改为 `::`。
- 检测到新的注册令牌文件时优先执行重新注册并原子替换旧机器凭据，避免旧凭据继续请求新节点而返回 `NODE_FORBIDDEN`；管理端安装命令仍必须为每个节点使用独立状态目录。

### 3.1 节点 DNS 候选

`sadno/flyskynode:3.1` 当前只作为待真机验收候选，不替换 Panel 默认的
`sadno/flyskynode:3.0`。候选增加 `node_dns_v1` 能力，并在启动时读取容器自己的
`/etc/resolv.conf`：

- 只把隧道内固定目标 `198.18.0.53:53` 映射到其中经过校验、去重且最多四个的 IPv4
  nameserver；UDP 和 TCP 都适用。
- UDP 只有在同一代理会话实际发送过该虚拟目标后，才把精确上游的回包源地址恢复为
  `198.18.0.53:53`；普通公开 DNS 流量不会仅因源地址相同而被改写。
- 直接访问 RFC1918、CGNAT、回环、metadata、控制面、节点网卡或管理员保护网段仍被
  consumer-node egress ACL 拒绝；该功能不会在公网监听 DNS，也不会把节点变成递归服务器。
- 容器没有可用 IPv4 nameserver 时拒绝启动。节点 DNS 最后一跳遵循节点系统配置，可能是
  普通 UDP/TCP 53；查询进入节点前仍由当前用户的 SS2022 会话加密。

3.1 只有在配套 iOS 候选、DNS 泄漏、节点切换、UDP/TCP DNS、网络切换和常用站点真机
Gate 全部通过后，才允许提交、推送或切换 Panel 默认镜像。

### 3.2 Fake-IP 域名出口解析候选

`sadno/flyskynode:3.2` 从 3.1 建立独立候选，不覆盖 3.1 回滚点。配套 iOS
候选使用 `198.19.0.0/16` Fake-IP 保存域名关联，TCP、UDP 与 QUIC 在进入
SS2022 前恢复域名；节点收到域名后通过共享、有界的出口解析缓存取得公网 IPv4，
逐个执行原有 ACL 校验后才允许拨号。节点自身域名仍由设备底层网络启动解析，业务
域名不允许回退到设备本地 DNS。

3.2 保留 3.1 的 `198.18.0.53` 节点 DNS 映射，供 TXT 等非地址查询和 Fake-IP
容量耗尽时的远端真实 A 查询安全回退。失效 Fake-IP、私网、metadata、控制面解析、
旧网络代际映射和无法验证的地址均失败关闭。3.2 必须与 iOS Build 3 配套完成真机
Gate 后才允许成为默认安装版本。

### 3.3 授权版本栅栏与 3.3.1 日志修复候选

`sadno/flyskynode:3.3` 在 3.2 数据面基础上增加 `resource_version_fence_v1`、
`serving_generation_ack_v1` 与 `stop_serving_ack_v1`。Snapshot
和 Changes 请求显式携带版本栅栏 Header；节点持久保存每用户最高授权版本（包括已撤销用户
的 tombstone），相等或更旧的 upsert/revoke 只推进 cursor，不得恢复旧密钥。提交顺序以栅栏
先落盘，任何凭据、运行时或快照提交失败均失败关闭；启动阶段的此类失败禁止回退旧缓存。
Snapshot 与 Changes 还必须携带同一个不可混淆的 `serving_generation`；节点只在快照或增量
完成校验、凭据激活、运行时替换、快照原子落盘后，才把已应用 generation/cursor 写入同步
状态并随 heartbeat 回报。抓取响应丢失、中途崩溃或最终状态写失败均不会产生新 ACK。

退役采用两阶段 stop-serving：Changes 的 `stop_serving` 或 full Snapshot 的
`stop_serving_generation` 会先建立独立持久 barrier，禁止启动/回退旧缓存；节点确认监听器与
会话停止后清空 runtime、凭据、快照和同步状态，才持续回报 exact-generation stopped ACK。
Panel 显式接受 ACK（或以专用 finalized 终态确认先前 200 响应丢失）后节点退出；generation
不匹配或普通 401/403 不会被误判为成功。barrier 使用 `FLYSKY_SYNC_STATE_PATH` 的
`.stop-serving` 同目录私有状态文件，并在 re-enroll/reactivate 完整安装新 generation 后清除。

默认响应上限按端点隔离：普通 Node API 为 1 MiB、Changes 为 2 MiB、Snapshot 为
16 MiB；本地同步状态为 8 MiB、快照为 16 MiB。30,000 用户夹具的快照约 8.9 MiB、
授权版本状态约 1.34 MiB，并额外限制单快照 50,000 用户、150,000 个授权版本栅栏和
单批 1,000 条增量，适合 512 MiB 节点并保留编码余量。

公开 `sadno/flyskynode:3.3` 后续暴露 closed UDP socket 永久错误 `WARN + continue` 的紧循环；
未采样 logger 与部署层缺少 Docker 日志轮转使该缺陷放大为磁盘耗尽事故。3.3 已 quarantine，
不得再拉取、安装、恢复或作为 Compose fallback。`3.3.1-canary.1` 是已在单个 Closure 节点
通过首轮人工验证的日志放大修复候选；`3.3.1-canary.2` 在同一修复上增加固定非 root
运行并已通过 Closure 人工验证；`3.3.1-canary.3` 继续加入 TCP/UDP 主 listener 运行时故障监督，
并保留 `65532:65532` 运行边界，仍然只允许同一 Closure 节点验证。永久/关闭/超时 socket 错误退出，
只有明确 temporary 错误才以 10 ms 至 1 s 指数退避；runtime logger 按 level/message 每分钟
最多保留 10 条；Docker `json-file` 固定 `max-size=10m`、`max-file=3`。候选必须从 clean 精确
提交构建并私有离线传输，不能覆盖或推送公开 3.3 标签。

### Flysky 联调配置

| 变量 | 用途 |
| --- | --- |
| `SSBAD_MODE=flysky` | 选择新 Node API 路径 |
| `FLYSKY_CONTROL_PLANE_URL` | Panel HTTPS 根地址 |
| `FLYSKY_ENROLLMENT_TOKEN_PATH` | 一次性注册令牌文件，默认 `/run/secrets/flysky-enrollment-token` |
| `UDP_MTU` | SS2022 UDP 路径预算；Flysky Node 默认 `1496`，避免默认值超过常见 1500 字节公网路径；仍可按已验证的实际链路显式覆盖 |
| `UDP_OUTER_FRAGMENTATION` | 对超出物理路径 MTU 的 SS2022 UDP 外层包允许由发送端分片；默认 `true`，保证大 UDP 回包不会静默丢失 |
| `FLYSKY_MACHINE_CREDENTIAL_PATH` | 机器凭据状态文件 |
| `FLYSKY_SNAPSHOT_PATH` | 最后有效快照缓存 |
| `FLYSKY_SYNC_STATE_PATH` | 授权栅栏与已原子应用的 serving generation/cursor 状态；同目录派生 `.stop-serving` 退役 barrier |
| `FLYSKY_REPORT_OUTBOX_PATH` | 流量与在线 IP 待确认报告，默认 `/var/lib/sshappy/flysky-reports.json` |
| `UPSK_STORE_PATH` | SS2022 用户凭据文件 |
| `FLYSKY_PROTECTED_EGRESS_PREFIXES` | 必填的逗号分隔禁止出口 IP/CIDR；必须包含节点实际公网地址，以及任何专用 Panel origin 地址，单个 IPv4 会规范为 `/32`。缺失或格式错误时节点拒绝启动，防止用户经代理回连节点自身；不要加入 Cloudflare 共享 Anycast 网段 |
| `FLYSKY_CHANGE_POLL_SECONDS` | 增量同步周期 |
| `FLYSKY_HEARTBEAT_SECONDS` | 状态心跳周期 |
| `FLYSKY_USAGE_REPORT_SECONDS` | 流量落盘与上报周期，默认 30 秒 |
| `FLYSKY_ALIVE_IP_REPORT_SECONDS` | 在线 IP 汇总周期，默认 60 秒 |
| `FLYSKY_SHUTDOWN_DRAIN_SECONDS` | 关机时等待会话完成最终计费的上限，默认 30 秒，允许 1–120 秒 |

原先的 `FLYSKY_INTEGRATION_MODE` 临时未计费 Gate 已移除。Flysky 路径现在必须成功打开持久 Outbox 才能启动；损坏、权限过宽或无法读取的 Outbox 会阻止启动，不能静默丢弃待计费数据。`FLYSKY_ALLOW_INSECURE_HTTP=true` 只允许本机回环联调，远程控制面始终要求 HTTPS。

### Debian 与容器验证

2026-07-23 已在 Debian 11 和 Debian 12 amd64 完成兼容验收：

- 静态二进制由 systemd 启动，SS2022 单端口 TCP/UDP 双栈监听正常；
- 官方 mihomo v1.19.28 完成 TCP、UDP DNS、计费与在线 IP 聚合验证；
- Panel 离线期间节点继续使用最后有效快照转发，`0600` Outbox 持久化报告，控制面恢复后自动补报并清空；
- Flysky 专用镜像以只读根文件系统、`cap_drop: ALL` 和 host 网络分别在 Debian 11/12 通过 TCP/UDP 回归；该次历史验收基线为 `sadno/flyskynode:3.0`。

Docker 部署模板位于 `deploy/compose.yaml`。首次部署前：

先在 `deploy/flysky-node.env` 中将 `FLYSKY_PROTECTED_EGRESS_PREFIXES` 的占位符替换为节点实际公网地址（例如 `203.0.113.10/32` 这一格式；请替换为真实地址）。这是所有部署的必填项；如果 Panel 有不与其他站点共享的专用 origin IP，也必须一并填写，并以英文逗号分隔。缺失或格式错误会让节点启动失败，避免静默失去出口保护。本机网卡地址、控制面精确主机名、私网、metadata、保留地址和首发 IPv6 会自动拒绝，无需重复填写。

控制面使用 Cloudflare 代理时，节点只自动拒绝 `FLYSKY_CONTROL_PLANE_URL` 中的精确主机名。Cloudflare 的公网 A/Anycast 地址由大量无关站点共享，因此不能把整段共享地址加入禁止出口网段，否则会误伤正常代理目标。若需要防止用户绕过主机名直连 Panel，请为 Panel origin 保留专用公网地址并加入 `FLYSKY_PROTECTED_EGRESS_PREFIXES`；没有专用 origin 时，这项共享 Anycast 风险必须作为部署取舍明确记录，不能用全局封禁 Cloudflare 地址替代。

下面的命令块只适用于**全新 Node UUID 的首次注册**，不得原样用于保留旧 machine state 的
Closure 原地迁移：

~~~bash
set -euo pipefail

NODE_UUID='<explicitly-approved-node-uuid>'
STATE_DIR="/var/lib/flysky/nodes/${NODE_UUID}/state"
SECRET_DIR="/etc/flysky/nodes/${NODE_UUID}/secrets"
ENV_FILE="/etc/flysky/nodes/${NODE_UUID}/flysky-node.env"
CANDIDATE_REVISION='<full-40-character-git-revision>'
CANDIDATE_TAG="3.3.1-canary.3-g${CANDIDATE_REVISION:0:12}"
CANDIDATE_VERSION="3.3.1-canary.3+g${CANDIDATE_REVISION:0:12}"
IMAGE="localhost/flysky-node-canary:${CANDIDATE_TAG}"
EXPECTED_ENGINE_IMAGE_ID='sha256:<docker-image-inspect-id-from-reviewed-offline-load>'
ARTIFACT_DIR='/path/to/reviewed-canary-artifacts'
PROJECT_NAME="flysky-closure-runtime-canary3-${NODE_UUID}"
RUNTIME_UID=65532
RUNTIME_GID=65532

install -d -o "$RUNTIME_UID" -g "$RUNTIME_GID" -m 0700 "$STATE_DIR" "$SECRET_DIR"
install -d -m 0700 "$(dirname "$ENV_FILE")"
install -m 0600 /path/to/reviewed-flysky-node.env "$ENV_FILE"
! grep -Eq 'panel\.example\.com|REPLACE_WITH_NODE_PUBLIC_IP' "$ENV_FILE"
! docker info --format '{{json .SecurityOptions}}' | grep -Eq 'name=(userns|rootless)'
test "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" -le 2343
(cd "$ARTIFACT_DIR" && sha256sum -c SHA256SUMS)
docker load -i "$ARTIFACT_DIR/flyskynode-3.3.1-canary.3-linux-amd64.docker.tar"
test "$(docker image inspect --format '{{.Id}}' "$IMAGE")" = "$EXPECTED_ENGINE_IMAGE_ID"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE")" = 'linux/amd64'
test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE")" = "$CANDIDATE_VERSION"
test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")" = "$CANDIDATE_REVISION"
test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$IMAGE")" = 'https://github.com/SadNoo/sshappy'
test "$(docker image inspect --format '{{.Config.User}}' "$IMAGE")" = "$RUNTIME_UID:$RUNTIME_GID"

SSBAD_IMAGE="$IMAGE" \
SSBAD_PROJECT_NAME="$PROJECT_NAME" \
SSBAD_PULL_POLICY=never \
SSBAD_RESTART_POLICY=no \
SSBAD_STATE_DIR="$STATE_DIR" \
SSBAD_SECRET_DIR="$SECRET_DIR" \
SSBAD_ENV_FILE="$ENV_FILE" \
docker compose -p "$PROJECT_NAME" -f deploy/compose.yaml create --pull never --no-build

CID="$(SSBAD_IMAGE="$IMAGE" SSBAD_PROJECT_NAME="$PROJECT_NAME" \
  SSBAD_PULL_POLICY=never SSBAD_RESTART_POLICY=no \
  SSBAD_STATE_DIR="$STATE_DIR" SSBAD_SECRET_DIR="$SECRET_DIR" SSBAD_ENV_FILE="$ENV_FILE" \
  docker compose -p "$PROJECT_NAME" -f deploy/compose.yaml ps --all --quiet ssbad)"
test -n "$CID"
test "$(docker inspect --format '{{.Image}}' "$CID")" = "$EXPECTED_ENGINE_IMAGE_ID"
test "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$CID")" = 'json-file'
test "$(docker inspect --format '{{index .HostConfig.LogConfig.Config "max-size"}}' "$CID")" = '10m'
test "$(docker inspect --format '{{index .HostConfig.LogConfig.Config "max-file"}}' "$CID")" = '3'
test "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$CID")" = 'no'
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CID")" = 'true'
test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$CID")" = 'host'
test "$(docker inspect --format '{{.Config.User}}' "$CID")" = "$RUNTIME_UID:$RUNTIME_GID"
install -o "$RUNTIME_UID" -g "$RUNTIME_GID" -m 0600 /path/to/enrollment-token "$SECRET_DIR/enrollment-token"
docker start "$CID"
~~~

注册令牌、机器凭据、快照、Outbox 和 SS2022 用户文件都来自宿主机挂载，不进入镜像。删除后重建的节点必须使用新 Node UUID 专属 project、state、secret 与 env 路径；严禁复用旧节点的 Compose project、`machine.json`、`snapshot.json`、`sync.json`、`reports.json` 或 `users.json`。部署模板没有镜像 fallback：必须显式传入已批准、已在本机 `docker load` 的不可变候选和唯一 project name，且默认 `pull_policy=never`、`restart=no`。未设置 `SSBAD_IMAGE` 或 `SSBAD_PROJECT_NAME` 时 Compose 必须失败关闭。先只 `create`，核对容器实际镜像 ID、日志轮转、restart、只读根和 host network 后才 `start`；不得使用 `--remove-orphans`。公开 3.3 已 quarantine；修复候选只有在 clean 提交 SHA 固定、离线 tar 与 SHA-256/OCI provenance 核验后，才允许进入一台已明确指定的 canary。

已有节点由 root canary 迁移到 non-root canary 时，可以复用同一 active Panel Node UUID 与其**当前 live state**，但不得执行上面的 enrollment-token 安装步骤。迁移必须从精确旧 container ID 的 `.Mounts` 按 `/var/lib/flysky` 与 `/run/secrets/flysky` 各唯一一次反查宿主 source，逐项与批准路径相等比较，并在停止旧容器前断言 secret source 内不存在 `enrollment-token`。新 Compose project 必须使用新的 nonroot-canary 名称，绝不能与保留的旧 project/container 重名。新容器只能先 `create`；旧容器仅在所有 inspect Gate 通过后停止，且不得删除。回滚必须用精确旧 container ID 重新启动，不能让 Compose 重新创建旧容器。

已部署 Panel 2.17 的历史安装命令会嵌入短期注册令牌，但该命令仍指向已 quarantine 的 3.3，禁止使用；本地修复源码已经把该入口设为 fail-closed。单 canary 的离线步骤必须把注册令牌单独写入新 Node UUID 专属 `0600` 外置文件，不能放入命令参数、Docker 环境变量或共享旧状态目录；容器成功注册并原子保存机器凭据后删除令牌文件。推荐运行边界为 host 网络、固定非 root `65532:65532`、只读根文件系统、临时 `/tmp`、`cap_drop: ALL` 和 `no-new-privileges`。state 与 secret 目录必须保持 `0700`，其中由运行时读取、替换或删除的文件必须保持 `0600` 并归该 UID/GID 所有；已有节点切换前必须先制作 root-only 状态副本，再只调整 live bind 的数值所有权。回滚必须先停止非 root canary，把**当前最新** live state 的所有权恢复为 `root:root` 并保持 `0700/0600`，再启动原样保留的旧 root 容器；不得用新 Compose 重建旧镜像，也不得默认覆盖成旧备份内容，只有确认当前 state 已损坏时才能受控恢复备份。

3.3 quarantine 期间不得执行管理后台仍可能显示的旧安装命令。单 canary 使用经过审核的离线安装步骤，令牌不得粘贴到聊天、Shell 历史、Docker 环境变量或仓库文件。只允许安装项目所有者明确指定的 `Flysky 3.2 Closure`，安装后必须停止 rollout，等待项目所有者真实客户端反馈；没有项目所有者明确“可以全量”授权时，不得触碰第二台节点。

事故前已部署管理后台的历史安装命令会使用发布记录中的节点域名或 IPv4，在目标主机上解析出当前 IPv4，并自动填入 `FLYSKY_PROTECTED_EGRESS_PREFIXES=<IPv4>/32`；但该历史命令仍指向已 quarantine 的 3.3，禁止执行。单 canary 必须在独立离线命令中保留相同的出口保护校验；解析失败时立即停止，绝不能启动缺少出口保护的容器。

下一阶段是固定源码提交与新镜像 digest，并建立与 4.2 的性能基线。旧 MySQL 代码仍留在上游基线，Flysky 正式 `cmd/sstest` 和镜像不再链接该适配；如确需旧面板兼容，必须从 4.2 建立独立的 `compat/legacy-mysql` 分支。
