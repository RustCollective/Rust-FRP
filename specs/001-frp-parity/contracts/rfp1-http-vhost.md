# Contract: RFP/1 的 vhost HTTP/HTTPS 扩展（S1）

**Feature**: `001-frp-parity` | **Date**: 2026-10-11 | **消费者**: `rfpc`（客户端）、`rfps`（服务端）

本契约描述 S1 对 RFP/1 的**全部**改动。不变式：所有改动都是"加可选字段 / 加新变体"，
不删除、不改动既有字段语义，因此主号保持 `1.0`（`docs/protocol.md` 版本策略）。

## 1. 控制消息：`register_proxy`（C→S）

```jsonc
{
  "type": "register_proxy",
  "name": "web",
  "proxy_type": "http",              // 新增可用值：http | https
  "local_addr": "127.0.0.1:3000",
  "remote_port": null,               // http/https 必须为空
  "vhost": "app.example.com",        // 既有字段，语义不变（单域名）
  "vhosts": ["api.example.com"],     // 新增（可选）：多域名，与 vhost 取并集
  "subdomain": "app"                 // 新增（可选）：需服务端配置 subdomain_host
}
```

**字段规则**

| 字段 | 出现条件 | 约束 |
|---|---|---|
| `proxy_type` | 必填 | S1 接受 `tcp` \| `http` \| `https`；`udp` 在 S2 |
| `remote_port` | tcp 必填 | `http`/`https` 时必须缺省或为 `null` |
| `vhost` / `vhosts` / `subdomain` | http/https 至少一项非空 | 域名经归一化后各自通过授权检查 |
| `subdomain` | 可选 | 不含 `.`；服务端未配置 `subdomain_host` 时报错 |

**兼容性**：旧版客户端不会发送 `vhosts`/`subdomain`，服务端按缺省处理。旧版**服务端**收到
`proxy_type: "http"` 会回 `RegisterProxyAck{ok:false}`；新版客户端必须能展示该原因（不静默重试）。

## 2. 控制消息：`register_proxy_ack`（S→C）

```jsonc
{ "type": "register_proxy_ack", "name": "web", "ok": true }
{ "type": "register_proxy_ack", "name": "web", "ok": false,
  "error": "vhost `app.example.com` 已被会话 s-3 注册" }
```

**失败原因 MUST 可区分**（FR-007、FR-024）：

| 场景 | `error` 内容要点 |
|---|---|
| 服务端未配置 vhost 监听端口 | 指明缺哪个监听端口（明文 / TLS） |
| 域名不在授权范围 | 复用既有 `authorize_vhost()` 的措辞 |
| 域名已被占用 | 指明冲突的域名 |
| `subdomain` 但服务端无 `subdomain_host` | 指明缺配置项 |
| `remote_port` 非空（http/https） | 指明该类型不占用端口 |

## 3. 数据流上的 HTTP 元数据

### 3.1 请求元数据（S→C）

**M2（QUIC）**：数据流首帧，与既有 `conn_init` 同一帧：

```jsonc
{ "type": "conn_init", "conn_id": 42, "proxy_name": "web",
  "http": {
    "method": "GET",
    "path": "/dash?tab=1",
    "version": "HTTP/1.1",
    "headers": [["host", "app.example.com"], ["accept", "*/*"],
                ["x-forwarded-for", "203.0.113.7"], ["x-forwarded-proto", "https"]]
  } }
```

**M1（TCP）**：控制通道的 `new_connection`，扩展同一 `http` 字段：

```jsonc
{ "type": "new_connection", "conn_id": 42, "proxy_name": "web", "http": { /* 同上 */ } }
```

### 3.2 响应元数据（C→S）

数据流上 **client 方向的第一条消息**：

```jsonc
{ "type": "http_response_meta", "conn_id": 42,
  "status": 200,
  "headers": [["content-type", "text/html"], ["content-length", "1234"]] }
```

> ⚠️ **本节的"半关闭表达体结束"约定已被证明有缺陷，待修订。**
> 2026-10-12 真实链路验收：大响应会被静默截断（8 MiB 只到 7.8 MiB，64 MiB 只到
> 63.5 MiB），原因是服务端过早半关闭，客户端关闭 socket 时仍有在途数据而被内核
> RST。完整证据与建议修法（改为显式分帧 + 零长度 EOB 帧）见
> [research.md D11](./../research.md)。修订前，本节的"半关闭"约定**不要**作为
> 实现依据。

### 3.3 数据流时序

```text
M2（QUIC，server 开 bi-stream）        M1（TCP，client 回连后）

  server ──conn_init{http}──► client   server ──new_connection{http}──► client  （控制通道）
  server ──request body ────► client   client ──conn_init{conn_id}────► server  （新数据连接）
                                        server ──request body ───────► client
  ── 半关闭（request body EOF）──

  client ──http_response_meta─► server
  client ──response body ────► server
  ── 半关闭（response body EOF）──
```

**硬性约束**

- 元数据帧 MUST 是该方向在数据流上的**第一条消息**；其后全部是裸字节，直到该方向半关闭。
- 请求体 / 响应体的流式转发 MUST NOT 整体缓冲（FR-011）。
- 元数据帧超过 64 KiB 上限时：服务端回 `4xx` 响应并**正常结束本次转发**，
  MUST NOT 断开控制通道、MUST NOT 影响同一会话的其他代理。

## 4. 头字段处置（FR-004、FR-005）

**剥离（逐跳，两个方向都做）**：`connection`、`keep-alive`、`proxy-authenticate`、
`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade`，
以及 `connection` 头中列出的自定义扩展头。

**追加（仅请求方向，S→C）**：

| 头 | 值 |
|---|---|
| `x-forwarded-for` | 在既有值后**追加**访客地址（已有值用 `, ` 分隔）；不存在则新建 |
| `x-forwarded-proto` | `http`（明文监听入口）或 `https`（TLS 监听入口） |

**响应方向**：剥离同样的逐跳头，不追加转发头。

## 5. 路由与错误响应（FR-006）

| 情形 | 响应 |
|---|---|
| 域名命中 `exact` 表 | 转发 |
| 域名命中 `wildcard` 表且恰好一层左标签 | 转发 |
| 域名未命中任何表 | `404`，不回落其他代理 |
| 命中但 `kind` 与监听端口不匹配（`http` 代理在 TLS 端口被访问） | `404` |
| 元数据帧超限 | `4xx` |
| 客户端本地服务拒绝连接 | `502` |

**Normative**: 归一化函数 `normalize_host()` 必须在注册侧与请求侧共用同一实现
（小写、去 `:port`、去末尾 `.`）。两侧不一致会导致"注册成功但访问 404"的隐性缺陷。

## 6. 不在本契约内

- UDP（S2）、压缩/限速/PROXY 协议/健康检查/负载均衡/路径路由（S3）、stcp/sudp/xtcp（S4）、
  管理接口与热重载（S5）。
- HTTP/3 网关（M3）：它复用本契约 §5 的路由语义，但监听与终止方式另立规格。
