# Wormhole

Wormhole 是一个 macOS SSH 隧道管理工具，基于 Tauri 2 和原生 TypeScript 构建。它提供桌面界面和菜单栏快捷面板，用来创建、启动、停止和监控 SSH 端口转发配置。

[English README](README.md)

## 功能特性

- 在本地桌面应用中管理可复用的 SSH 隧道配置。
- 支持 Local、Remote 和 SOCKS 三种隧道模式。
- 通过系统 OpenSSH `ssh` 命令启动和停止每个隧道。
- 将 SSH 密码和私钥 passphrase 存储到 macOS Keychain。
- 在界面中选择私钥文件，默认打开当前用户的 `~/.ssh` 目录。
- 显示隧道运行状态、本地客户端连接数和尽力而为的流量指标。
- 在 Overview 页面查看流量和客户端连接历史图表。
- 通过 macOS 菜单栏快捷面板快速控制隧道。
- 关闭主窗口后保持隧道继续运行。
- 退出应用时自动断开运行中的隧道。
- 主界面支持中英文切换。
- 支持通过 GitHub tag 触发 GitHub Actions 构建 macOS 发布包。

## 隧道类型

### Local Forwarding

Local 转发会在你的 Mac 上监听一个本地端口，并通过 SSH 将流量转发到 SSH 服务器可访问的目标主机和端口。

常见用途：

- 通过跳板机连接内网数据库。
- 访问没有公网暴露的内部 Web 服务。
- 将 `127.0.0.1:15432` 转发到 `db.internal:5432`。

### Remote Forwarding

Remote 转发会在 SSH 服务器上打开一个远程端口，并将进入该端口的流量转发回你的 Mac 或本地网络中的服务。

常见用途：

- 临时将本地开发服务暴露给远程机器。
- 让远程服务器回调本地测试接口。
- 将远程 `9000` 端口转发到本地 `127.0.0.1:3000`。

### SOCKS Proxy

SOCKS 模式会创建一个本地动态代理。支持 SOCKS 的应用可以通过该 SSH 连接访问网络，而不需要在隧道配置中指定固定目标地址。

常见用途：

- 让浏览器流量通过 SSH 服务器转发。
- 测试不同网络环境下的访问效果。
- 创建类似 `127.0.0.1:1080` 的本地 SOCKS 代理。

## 菜单栏快捷面板

Wormhole 会运行在 macOS 菜单栏中。点击菜单栏图标会打开一个小型快捷面板，可以：

- 查看已保存隧道及其当前状态。
- 启动或停止单个隧道。
- 打开完整配置窗口。
- 退出应用。

关闭主窗口只会隐藏窗口。应用会继续保留在菜单栏中，已经运行的隧道也会继续运行。从快捷面板退出应用时，Wormhole 会先停止正在运行的隧道，然后再退出。

## 运行状态指标

Overview 页面展示：

- 已保存隧道数量。
- 正在运行的隧道数量。
- 本地客户端连接数。
- 当前流量速率。
- 已采样总流量。
- 流量和连接数历史图表。

这些指标是尽力而为的运行状态参考。Wormhole 将隧道执行委托给 OpenSSH，并从 `ssh` 进程外部观察本机系统状态。

## 环境要求

- macOS。
- Node.js 20 或更新版本。
- Rust stable 工具链。
- `PATH` 中可用的 OpenSSH `ssh` 命令。
- 如需使用发布流程，需要安装 Git。

## 开发

安装依赖：

```sh
npm install
```

以开发模式运行应用：

```sh
npm run tauri dev
```

构建前端：

```sh
npm run build
```

只运行 Rust 检查：

```sh
cargo check --manifest-path src-tauri/Cargo.toml
```

运行完整测试命令：

```sh
npm test
```

`npm test` 会构建前端，并运行 Rust 测试套件。

## 发布

仓库中已经包含 GitHub Actions 工作流：`.github/workflows/release.yml`。

推送匹配 `v*` 的 tag 会触发发布构建：

```sh
git tag v0.1.0
git push origin v0.1.0
```

该工作流会在 macOS 环境中安装 Node.js 和 Rust，执行 `npm test`，构建 Tauri 应用，并创建一个包含 macOS 构建产物的 GitHub draft release。

当前仓库默认没有配置代码签名和 notarization。如果要发布生产版本，请先补充 Apple Developer 相关签名配置。

## 数据和凭据

隧道配置由应用保存在本地。敏感凭据会单独存储：

- SSH 密码存储在 macOS Keychain。
- 私钥 passphrase 存储在 macOS Keychain。
- 密码和 passphrase 认证通过应用生成的 askpass helper 提供给 OpenSSH。

Wormhole 不自行实现 SSH 协议。它会根据每个配置需要的隧道参数启动系统 `ssh` 命令。

## 注意事项和限制

- Wormhole 当前主要面向 macOS。
- OpenSSH 行为、host key 校验、SSH agent 行为和 SSH config 解析都来自系统 `ssh` 命令。
- 客户端连接数通过本机 Local 和 SOCKS 转发端口上的已建立 TCP 连接计算。
- Remote 转发的客户端连接发生在远程主机上，因此本地连接数统计不一定可见。
- 流量指标来自本机进程和网络信息采样，适合作为运行状态参考，不适合作为计费级别的精确统计。
- 如果隧道无法正常停止，Wormhole 会尝试清理对应的 `ssh` 进程。

## 项目结构

```text
.
|-- src/                 # 前端 TypeScript、界面渲染和样式
|-- src-tauri/           # Tauri/Rust 后端、SSH 进程管理和菜单栏集成
|-- .github/workflows/   # GitHub Actions 发布工作流
|-- package.json         # 前端和 Tauri 脚本
|-- README.md            # 英文文档
`-- README_zh.md         # 中文文档
```

## License

当前仓库还没有包含 license 文件。如果要公开分发项目，请先补充合适的开源许可证。
