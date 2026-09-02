# RFP/1 协议设计草案

RFP（Rust-FRP Protocol）是 client（frpc）与 server（frps）之间的通信协议。状态：**草案**，随 M1 实现迭代。

## 设计原则

1. **传输无关**：帧格式不绑定 TCP 或 QUIC，M1→M2 只换承载层，不换消息语义
2. **调试优先**：控制消息用 JSON 编码，开发期可直接肉眼排查；预留切换到紧凑二进制（postcard）的空间
3. **连接即流**：M2 起每个用户连接对应一条 QUIC bi-stream，消灭 frp 的连接池/多路复用层
4. **默认加密**：没有明文模式，M1 起 TLS 必选，M2 起 QUIC 内建 TLS 1.3

## 术语

- **控制通道**：client↔server 之间的一条有序可靠长连接（M1: TCP+TLS；M2: QUIC bi-stream 0）
- **数据流**：承载单个用户连接转发载荷的通道
- **代理（proxy）**：client 的一项注册声明，将 server 上的端口/vhost 映射到本地服务

## 连接建立

```
frpc                                    frps
  │  TCP/QUIC + TLS 握手                  │
  │──────── Hello ────────────────────►│
  │◄─────────────── HelloAck ───────────│
  │──────── RegisterProxy(web) ──────►│   (可多次)
  │◄─────────────── RegisterProxyAck ────│
  │         …… 控制通道持续存活 ……
```

未通过 Hello 认证前，server 拒绝一切其他消息并关闭连接。

## 控制通道帧格式

```
+----------------+---------------------+
| length: u32 BE | payload: JSON bytes |
+----------------+---------------------+
```

- `length` 为 payload 字节数，上限 64 KiB（超出即协议错误，断开）
- payload 为 UTF-8 JSON 对象，必含 `type` 字段
- 未知字段忽略（向后兼容），未知 `type` 回 `Error(unknown_message)` 但不断开

### 消息类型

| type | 方向 | 字段 | 说明 |
|---|---|---|---|
| `hello` | C→S | `version`, `token`, `hostname`? | 认证。version 主次号，主号不匹配拒绝 |
| `hello_ack` | S→C | `version`, `session_id` | 认证通过 |
| `register_proxy` | C→S | `name`, `proxy_type`, `local_addr`, `remote_port`?, `vhost`? | `proxy_type`: `tcp` \| `udp`(M3) \| `http` \| `https`；tcp 需 `remote_port`，http/https 需 `vhost`（支持 `*.example.com` 通配） |
| `register_proxy_ack` | S→C | `name`, `ok`, `error`? | 端口/vhost 冲突在此报错 |
| `new_connection` | S→C | `conn_id`, `proxy_name` | 仅 M1：通知 client 即将有数据连接接入，`conn_id` 用于匹配 |
| `ping` | 双向 | `ts` | 仅用于延迟统计；连接活性由 TLS/QUIC 层 keepalive 负责 |
| `pong` | 双向 | `ts` | 回显 `ping.ts` |
| `error` | 双向 | `code`, `message` | 通用错误 |

`conn_id`: u64，由 server 全局自增分配：M1 经 `new_connection` 下发、`conn_init` 回显匹配；M2 由 stream 首帧携带，仅作日志关联。

## 数据流

### M1：独立 TCP 连接 + 首帧标识

```
frps                          frpc
  │ 用户连接到达，分配 conn_id   │
  │── new_connection ────────►│ (走控制通道)
  │◄── 新 TCP 连接（frpc 发起）──│
  │◄── ConnInit 首帧 ────────────│
  │        双向裸字节透传         │
```

- 首帧 `ConnInit`：与控制消息同格式（length + JSON），`type: "conn_init"`，字段 `conn_id`, `proxy_name`
- 首帧之后全部为透传字节，无任何包装
- 代价：每用户连接一次额外 TCP 握手（client 主动回连）。**连接池作为 M1 优化项后置**，不影响协议语义
- 超时：`new_connection` 发出后 5 秒内未收到对应 `conn_init`，server 关闭用户连接

### M2：QUIC bi-stream（已实现）

```
frpc                                    frps
  │  QUIC + TLS 1.3 握手（ALPN rfp/1）     │
  │── open_bi: 控制通道（首条）──────────►│
  │   Hello → …（帧格式不变）              │
  │                                       │ 用户连接到达
  │◄── server open_bi: 数据流 ───────────│ (同一条 QUIC 连接上)
  │◄── stream 首帧: conn_init ────────────│
  │        双向裸字节透传                   │
```

- client 打开的第一条 bi-stream 即控制通道，其后帧交互与 M1 完全一致（协议零改动）
- server 收到用户连接后，在既有 QUIC 连接上开 bi-stream，首帧仍为 `conn_init`（`conn_id` 仅作日志关联）
- FIN 映射：用户连接半关闭 ↔ stream 半关闭；QUIC 流取消（STOP_SENDING/RESET）映射为对端读关闭
- `new_connection` 控制消息在 QUIC 路径废弃，改由 stream 首帧携带调度信息
- 无需连接池：QUIC stream 建立零成本
- 0-RTT：client 复用 endpoint 保留会话票据，重连时 `into_0rtt` 携带 Hello 早发（early data）；被拒（server 重启/票据过期）自动降级为握手后的 1-RTT 流。Hello 走 early data 存在重放面：重复认证+注册会被端口冲突检查挡下，当前接受此权衡
- TLS：QUIC 内生 TLS 1.3（无明文模式），复用 M1 的证书与 fingerprint pinning 体系

## H3 网关（M3）

**模式：边缘终止（Cloudflare Tunnel 同款），不做端到端 H3 透传。**依据：

- H3 收益集中在用户↔frps 跳（公网丢包/移动网络）；frps↔frpc↔origin 多为稳定链路，边缘终止已拿走绝大部分收益
- 端到端透传要求全链路保留 QUIC 语义：若隧道是 TCP，连接迁移/无队头阻塞/独立丢包恢复全数失效，且嵌套拥塞控制互相干扰；若隧道是 QUIC datagram 中继（MASQUE 式），仍付嵌套 CC 代价，且路由只剩 SNI 粒度（QUIC Initial 虽加密但密钥公开可推导，路径设备可读 SNI），丧失 `:authority` 级 L7 路由
- 证书是 H3 准入门槛而非差异化点（QUIC 内嵌 TLS 1.3，无 h3c 明文模式）；ACME 自动化只是把门槛做成开箱即用

具体：

- server 以 quinn + [h3](https://github.com/hyperium/h3) 在 UDP :443 终止 HTTP/3（兼容 ALT-SVC 上的 H2 回退，TCP :443 由 https 代理类型覆盖）
- 路由：request 的 `:authority`（去端口后）精确/通配匹配已注册 `http` 代理的 `vhost`；未匹配返回 404
- 转发：将 request 的 method/path/headers 原样转为到 client 的数据流首部（`conn_init` 扩展 `http` 字段），client 侧还原为 HTTP/1.1 请求发给本地服务
- 附加头：`X-Forwarded-For`、`X-Forwarded-Proto`
- 证书：ACME 自动申请/续期（http-01 与 tls-alpn-01），challenge 流量由 server 自处理

## 安全

- **TLS（M1 已落地）**：rustls + TLS 1.3，默认开启，明文需 `[tls] enabled = false` 显式声明。控制连接与数据回连统一在传输层加密，帧格式与协议语义不变（TLS 在 RFP/1 之下）
  - server 侧：未配置 `tls.cert`/`tls.key` 时自动生成自签证书（CN=rust-frp）并落盘复用，启动日志打印证书 SHA256 fingerprint
  - client 侧：`tls.server_fingerprint` 固定指纹（自签场景，跳过链验证直接比对叶子证书 hash）；未配置时走系统根验证（真证书场景）
  - M2 起 QUIC 内建 TLS 1.3，同套证书/fingerprint 体系
- **认证**：`hello.token` 与 server 配置比对（常量时间比较），失败即断开，不区分"token 错"与"其他错误"（防探测）
- **失败语义**：认证失败 server 回 `error{auth_failed}` 后关闭，不做重试提示

## 认证与授权（M1.5）

**token 即身份**——协议零改动，server 按 token 查用户表：

- **用户模式**（配置了 `[[users]]`）：token → 具名用户，`register_proxy` 时校验
  - `remote_port` 必须落在用户 `ports` 授权区间（`"6000-6100"` 区间 / `"65533"` 单端口）
  - `vhost` 必须匹配用户 `vhosts`（精确或 `*.domain` 通配；通配匹配恰好一个左标签：`x.a.com` ✓、`a.com` ✗、`evil-a.com` ✗、`a.b.a.com` ✗）
- **legacy 模式**（仅全局 token）：端口不受限，但拒绝系统临时端口区间 32768-60999（该区间的端口会被 server 出站连接随机抢占）
- **Open 模式**（无 token 无用户表）：不认证，行为同 legacy（生产禁止）
- 授权失败发生在认证之后：`register_proxy_ack.ok = false` 并带明确原因（帮助用户配置），与认证失败的模糊语义区分开

## 版本策略

- `hello`/`hello_ack` 交换 `version`（如 `"1.0"`）；主号不同即拒绝，次号不同取双方交集行为
- 消息体演进只加字段不改语义；删字段/改语义必须升主号

## Open Questions

1. UDP 代理：QUIC datagram 帧统一承载 vs 每会话一条 uni-stream？前者省流控开销，后者可背压
2. 连接迁移（客户端换网）时，进行中的数据流如何跟随；是否需要会话恢复票据
3. 多 client 注册同名 proxy / 同 vhost 的冲突策略（拒绝后者 vs 抢占）
4. 端到端 H3 透传（层级 C）：M2 隧道 QUIC 化后，经 datagram 中继是否值得做？嵌套拥塞控制如何缓解；SNI 级路由（不解密 Initial）与边缘终止的边界在哪里
5. 控制消息从 JSON 切到 postcard 的触发时机（M2 稳定后？）
6. metrics/管理 API 的暴露形式（Prometheus / JSON over localhost）
