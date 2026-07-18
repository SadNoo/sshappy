# Flysky ssbad 集成说明

本目录是 SadNoo/sshappy 的独立 Git worktree：

- 分支：integration/flysky
- 基线：origin/4.2
- 起点：73aa426ef5c1e4f9fd67639846836d0386cbe0e5

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
