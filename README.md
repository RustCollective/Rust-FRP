# Rust-FRP

用 Rust 实现的内网穿透工具，对标 [frp](https://github.com/fatedier/frp)。定位：**QUIC 原生传输、低内存占用、支持 HTTP/3**。

## 为什么再做一轮

frp 验证了产品形态，但存在三个结构性问题：

| 痛点 | frp 现状 | Rust-FRP 方案 |
|---|---|---|
| 内存 | 每连接一个 goroutine + GC 元数据，万级连接数百 MB | tokio task 数百字节，无 GC，同等连接数低一个数量级 |
| 传输层 | TCP + TLS + yamux 自制多路复用 + 连接池 | QUIC 原生多路复用，无连接池；0-RTT 断线重连、连接迁移 |
| HTTP/3 | 不支持。瓶颈不在证书在数据面：TCP 流装不下 QUIC 语义（连接迁移、无队头阻塞、独立丢包恢复），UDP 代理又只是会话级转发、无域名路由 | server 侧终止 H3（Cloudflare 同款模式），按 `:authority` 路由，ACME 自动证书 |

rathole 已验证"低内存"这条差异化路线成立，但不做 vhost/HTTP 层；Rust-FRP 同时切入传输层（QUIC）和应用层（H3 网关）两个方向。

## 架构

```
外部用户                      公网 server (frps)                    内网 client (frpc)
--------                      -----------------                    ----------------
   │  ┌─ TCP/UDP 访问 ────────►  用户端口监听                          │
   │  │                       ┌────────────────┐                    ┌──────────────┐
   │  └─ HTTP/3 访问 ────────►│ H3 网关(M3)     │                    │ 本地服务      │
   │                          │ :authority 路由 │                    │ 127.0.0.1:xx │
   │                          └───────┬────────┘                    └──────▲───────┘
   │                                  │  QUIC 连接(M2) / TCP 控制连接(M1)   │
   └──────────────────────────────────┴──────── 数据流（每用户连接一条）──────┘
```

- **控制通道**：client 与 server 之间一条长连接（M1 为 TCP + TLS，M2 起为 QUIC），承载认证、代理注册、连接调度
- **数据流**：M1 为按需建立的独立 TCP 连接（首帧标识归属）；M2 起为同一 QUIC 连接上的 bi-stream，无连接池
- **H3 网关（M3）**：server 终止 QUIC/TLS，按 `:authority` 匹配 vhost 后转发到对应 tunnel

## HTTP/3 的支持层级

证书不是瓶颈——QUIC 内嵌 TLS 1.3、无明文模式，证书是任何 H3 端点的准入门槛，frp 的 https2http 插件也一直在管证书。真正的瓶颈是 **TCP 数据面装不下 QUIC 语义**：

- 外层 TCP 四元组绑定，客户端换 IP 即断，内层连接迁移无从谈起
- TCP 强制保序，无队头阻塞与 packet 级独立丢包恢复归零
- QUIC 拥塞控制嵌套在 TCP 拥塞控制之内，两套 CC 互相干扰
- 隧道 RTT 叠加，0-RTT 优势被抵消

"支持 HTTP/3"因此分三层，成本与价值差异巨大：

| 层级 | 形态 | frp | Rust-FRP |
|---|---|---|---|
| A. UDP 裸转发 | 转发 UDP:443，无域名路由，浏览器 H3 发现不可靠（Chrome 尤其挑剔，frp#5049） | 勉强可用 | 不作为目标 |
| B. 边缘终止 H3 | frps 终止 QUIC/TLS，`:authority` 路由，隧道内传 HTTP 语义，origin 说 H1/H2 | 不支持 | **M3 默认形态** |
| C. 端到端 QUIC 透传 | frps 按 QUIC Initial 的 SNI 做 UDP 级路由，QUIC 语义端到端保留 | 不支持，需架构重构 | open question：M2 后经 QUIC datagram 中继（MASQUE 式），代价是嵌套 CC 与仅 SNI 粒度路由 |

关键判断：**H3 的收益集中在用户↔frps 这一跳**（公网、丢包、移动网络）；frps↔frpc↔origin 通常在稳定链路。边缘终止（B）拿走绝大部分收益，这也是 Cloudflare Tunnel 的工程选择；端到端（C）是隧道理想主义，边际收益低。

## Roadmap

- **M1 — TCP 隧道 MVP**：✅ TCP 控制连接 + 长度前缀帧协议，TCP 代理全链路（认证、注册、转发、断线重连）；✅ TLS 默认加密（rustls，自签 + fingerprint pinning，明文需显式声明）
- **M1.5 — 每用户授权模型**：✅ token 即身份（协议零改动），`[[users]]` 端口区间/vhost 通配授权；legacy 全局 token 向后兼容；临时端口区间（32768-60999）硬校验
- **M2 — QUIC 传输**：✅ quinn 单连接多路复用（数据隧道 = server 主动 open_bi，无回连无连接池）；0-RTT 断线重连（endpoint 复用 + early data，被拒自动降级 1-RTT）；与 TCP 传输共存，server `[quic]` / client `transport` 显式启用
- **M3 — HTTP/3 网关**：frps 终止 H3 + `:authority` vhost 路由 + ACME 自动证书（边缘终止模式，origin 无需支持 H3）；UDP 代理
- 之后：STCP/XTCP、metrics、热更新配置

## 协议设计

见 [docs/protocol.md](docs/protocol.md)。

## 横向对比

| | frp | rathole | Rust-FRP |
|---|---|---|---|
| 语言 | Go | Rust | Rust |
| 传输 | TCP + yamux | TCP | QUIC |
| 0-RTT 重连 | - | - | 计划 |
| vhost HTTP/HTTPS | HTTP/1.1, H2 | - | HTTP/1.1, H2, **H3**（边缘终止） |
| UDP 代理 | 支持 | 支持 | 计划 |
| 插件生态 | 丰富 | - | 计划 |

## 快速上手

```bash
cargo build --release
```

服务端 `rfps.toml`（推荐：每用户授权模式）：

```toml
bind_port = 7000

[[users]]
name = "alice"
token = "alice-独立token"     # token 即身份
ports = ["6000-6100", "6200"] # 允许注册的端口区间
vhosts = ["*.alice.dev"]      # 允许的域名（M3 vhost 路由用）

[[users]]
name = "bob"
token = "bob-token"
ports = ["6300-6400"]
vhosts = ["bob.example.com"]
```

也支持 legacy 全局 token（向后兼容，端口不受限但拒绝临时端口区间）：

```toml
bind_port = 7000
token = "secret"
```

```bash
./target/release/rfps -c rfps.toml
```

启动日志会打印证书 fingerprint（未配置证书时自动生成自签并落盘复用）：

```
TLS 就绪（client 配置 server_fingerprint = "603d904e..."）
```

客户端 `rfpc.toml`：

```toml
server_addr = "your.server.ip"
server_port = 7000
token = "secret"

[tls]
server_fingerprint = "603d904e..."   # rfps 启动日志里的 fingerprint

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
```

```bash
./target/release/rfpc -c rfpc.toml
# ssh -p 6022 user@your.server.ip
```

QUIC 传输（M2，可选）——server 的 `rfps.toml` 加：

```toml
[quic]
enabled = true          # UDP 监听，缺省复用 bind_port
# bind_port = 7000      # 也可单独指定 UDP 端口
```

client 的 `rfpc.toml` 加 `transport = "quic"`（其余配置不变，fingerprint 与 TCP 路径共用）。云服务器需在安全组放行对应 UDP 端口。

M2 现状：TCP 与 QUIC 双传输共存。**QUIC 传输**：server 配置 `[quic] enabled = true`（UDP 缺省复用 `bind_port`，云安全组需放行 UDP）、client 配置 `transport = "quic"` 即切换；帧协议与授权模型零改动，数据隧道由 server 在同一 QUIC 连接上开 bi-stream 下发，无 M1 的回连开销；rfpc 进程内断线重连走会话恢复（0-RTT 早发 Hello，被拒自动降级）。默认仍为 TCP（生产稳定优先），公网全面切换待 M2 验证期结束后。

## 开发

```bash
cargo test   # 单元测试 + 端到端测试（含真实转发链路）
```
