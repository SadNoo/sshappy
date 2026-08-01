# Flysky ssbad 集成说明

本目录是 SadNoo/sshappy 的独立 Git worktree：

- 分支：integration/flysky-2.0
- 基线：origin/4.2
- 起点：39a795fd7b2b1e81143e222b2918d9526be89740

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
- HTTPS 默认强制、认证请求禁止重定向、响应大小上限和脱敏 API 错误；
- 机器凭据与同步游标的 `0600` 原子本地持久化。
- `usage-reports` 与 `alive-ips` 上报，以及严格校验服务端回执。

第二阶段运行适配位于 `internal/flyskynode`，已经覆盖：

- Flysky 正式入口只接受 `SSBAD_MODE=flysky`（未设置时也进入 Flysky）；二进制不链接旧 MySQL Panel 适配；
- UUID 用户标识、订阅有效期、剩余额度和快照 TTL 的默认拒绝授权；
- 全量 snapshot 启动、`upsert_user`/`revoke_user` 热更新和 `410` 全量恢复；
- 先原子更新凭据与快照，最后推进本地 cursor；重复拉取可幂等重放；
- 节点端口或 server key 变化返回明确的 restart required，不进行危险的半热更新；
- HTTPS 容器补充系统 CA，注册令牌只从受限文件读取并在成功换取机器凭据后尝试删除。
- UUID 流量批次与在线 IP 汇总共用 `0600` 原子 Outbox；断网时保留原 report_id 和 sequence，只有收到匹配的 `202 accepted` 才删除。
- 在线 IP 默认只离开进程的是节点级 `online_ip_count`、`active_users` 和预留连接数，不上传原始客户端 IP。
- 显式 `unlimited` 字段区分无限套餐与额度耗尽，避免把合法的零值约定误判为无额度。
- IPv4、IPv6 和双栈监听统一使用标准地址拼接。默认 `LISTEN_HOST=0.0.0.0`，保证不受宿主机 `net.ipv6.bindv6only` 设置影响；明确验证双栈内核行为后才可改为 `::`。
- 检测到新的注册令牌文件时优先执行重新注册并原子替换旧机器凭据，避免旧凭据继续请求新节点而返回 `NODE_FORBIDDEN`；管理端安装命令仍必须为每个节点使用独立状态目录。

### Flysky 联调配置

| 变量 | 用途 |
| --- | --- |
| `SSBAD_MODE=flysky` | 选择新 Node API 路径 |
| `FLYSKY_CONTROL_PLANE_URL` | Panel HTTPS 根地址 |
| `FLYSKY_ENROLLMENT_TOKEN_PATH` | 一次性注册令牌文件，默认 `/run/secrets/flysky-enrollment-token` |
| `UDP_MTU` | SS2022 外层 UDP 路径预算；Flysky Node 默认 `1600`，用于容纳普通 1500 字节公网路径上的最大数据报及协议头 |
| `UDP_OUTER_FRAGMENTATION` | 对超出物理路径 MTU 的 SS2022 UDP 外层包允许由发送端分片；默认 `true`，保证大 UDP 回包不会静默丢失 |
| `FLYSKY_MACHINE_CREDENTIAL_PATH` | 机器凭据状态文件 |
| `FLYSKY_SNAPSHOT_PATH` | 最后有效快照缓存 |
| `FLYSKY_SYNC_STATE_PATH` | cursor 与 config version 状态 |
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
- Flysky 专用镜像以只读根文件系统、`cap_drop: ALL` 和 host 网络分别在 Debian 11/12 通过 TCP/UDP 回归；当前发布名称为 `sadno/flyskynode:2.0`。

Docker 部署模板位于 `deploy/compose.yaml`。首次部署前：

先在 `deploy/flysky-node.env` 中将 `FLYSKY_PROTECTED_EGRESS_PREFIXES` 的占位符替换为节点实际公网地址（例如 `203.0.113.10/32` 这一格式；请替换为真实地址）。这是所有部署的必填项；如果 Panel 有不与其他站点共享的专用 origin IP，也必须一并填写，并以英文逗号分隔。缺失或格式错误会让节点启动失败，避免静默失去出口保护。本机网卡地址、控制面精确主机名、私网、metadata、保留地址和首发 IPv6 会自动拒绝，无需重复填写。

控制面使用 Cloudflare 代理时，节点只自动拒绝 `FLYSKY_CONTROL_PLANE_URL` 中的精确主机名。Cloudflare 的公网 A/Anycast 地址由大量无关站点共享，因此不能把整段共享地址加入禁止出口网段，否则会误伤正常代理目标。若需要防止用户绕过主机名直连 Panel，请为 Panel origin 保留专用公网地址并加入 `FLYSKY_PROTECTED_EGRESS_PREFIXES`；没有专用 origin 时，这项共享 Anycast 风险必须作为部署取舍明确记录，不能用全局封禁 Cloudflare 地址替代。

~~~bash
install -d -m 0700 /var/lib/flysky/ssbad /etc/flysky/ssbad/secrets
cp deploy/flysky-node.env.example deploy/flysky-node.env
chmod 0600 deploy/flysky-node.env
install -m 0600 /path/to/enrollment-token /etc/flysky/ssbad/secrets/enrollment-token
docker compose -f deploy/compose.yaml pull
docker compose -f deploy/compose.yaml up -d
~~~

注册令牌、机器凭据、快照、Outbox 和 SS2022 用户文件都来自宿主机挂载，不进入镜像。发布标签为 `sadno/flyskynode:2.0`；镜像重新构建后必须同步更新本文件、部署模板和 Flysky 的 `dependencies/ssbad.lock.yaml`。

管理后台生成的安装命令不会嵌入注册令牌。运维在节点终端以隐藏输入提供一次性令牌，命令在 `umask 077` 下写入外置状态目录；容器成功注册并原子保存机器凭据后删除令牌文件。推荐运行边界为 host 网络、只读根文件系统、临时 `/tmp`、`cap_drop: ALL` 和 `no-new-privileges`，示例：

~~~sh
install -d -m 0700 /var/lib/flysky/ssbad
read -rsp 'Flysky enrollment token: ' FLYSKY_ENROLLMENT_TOKEN
printf '\n'
umask 077
printf '%s\n' "$FLYSKY_ENROLLMENT_TOKEN" > /var/lib/flysky/ssbad/enrollment-token
unset FLYSKY_ENROLLMENT_TOKEN
docker pull sadno/flyskynode:2.0
~~~

完整 `docker run` 参数由管理后台按当前控制面地址生成。令牌不得粘贴到聊天、Shell 历史、Docker 环境变量或仓库文件。

当前管理后台安装命令尚不会自动探测并填入 NAT 公网地址，这是部署自动化的已知残余；在该自动化补齐前，运维必须保留上述 `FLYSKY_PROTECTED_EGRESS_PREFIXES` 设置。若节点公网地址变化，也必须先更新该值并重启容器。

下一阶段是固定源码提交与新镜像 digest，并建立与 4.2 的性能基线。旧 MySQL 代码仍留在上游基线，Flysky 正式 `cmd/sstest` 和镜像不再链接该适配；如确需旧面板兼容，必须从 4.2 建立独立的 `compat/legacy-mysql` 分支。
