# Phase 1 Data Model: frp 功能对等

**Feature**: `001-frp-parity` | **Date**: 2026-10-11
**来源**: spec.md 的 Key Entities 与 FR-001~036；承载方式见 [research.md](./research.md)

模型分两层：**线上模型**（穿过隧道的 `Message` 变体，受宪法原则 IV 约束）与**进程内模型**
（服务端/客户端的内存状态）。本阶段（S1）只实例化与 US1 相关的部分，其余实体标注引入期。

## 1. 实体总览

| 实体 | 层 | 引入期 | 权威需求 | 现状 |
|---|---|---|---|---|
| `Proxy` | 线上 + 进程内 | S1 | FR-001、FR-003、FR-012 | 线上已有，需扩展字段 |
| `HttpInit` | 线上 | S1 | FR-002、FR-004、FR-005 | 新增 |
| `HttpResponseMeta` | 线上 | S1 | FR-004 | 新增 |
| `VhostRoute` | 进程内 | S1 | FR-006~009 | 新增 |
| `CertificateEntry` | 进程内 | S1 | FR-003 | 新增 |
| `Session` / `Identity` | 进程内 | M1 已有 | FR-007、FR-009 | 复用，不改 |
| `UdpSession` | 进程内 | S2 | FR-013、FR-014 | 新增 |
| `LoadBalancerGroup` | 进程内 | S3 | FR-022 | 新增 |
| `HealthState` | 进程内 | S3 | FR-020、FR-021 | 新增 |
| `MetricsSnapshot` | 进程内 | S5 | FR-032 | 新增 |

## 2. Proxy（代理）

客户端注册声明在服务端的投影。沿用既有 `Message::RegisterProxy` 并扩展。

| 字段 | 类型 | S1 变化 | 校验规则 |
|---|---|---|---|
| `name` | String | 不变 | 会话内唯一；跨会话冲突按 FR-024 的策略处置 |
| `proxy_type` | ProxyType | `Http` / `Https` 从"被拒绝"变为"被接受" | S1 接受 `Tcp`/`Http`/`Https`；`Udp` 在 S2 打开 |
| `local_addr` | String | 不变 | 客户端侧解析，服务端不校验 |
| `remote_port` | Option\<u16\> | 不变 | **`Http`/`Https` 类型必须为空**——域名型代理不占用公网端口（FR-001） |
| `vhost` | Option\<String\> | 语义扩展 | 单域名。`Http`/`Https` 类型下与 `vhosts` 至少其一非空 |
| `vhosts` | Vec\<String\> | **新增** | 多个自定义域名；与 `vhost` 并存时取并集 |
| `subdomain` | Option\<String\> | **新增** | 需服务端配置了 `subdomain_host`（FR-008）；值为单个标签，不含点 |

**不变量**:

- `Http`/`Https` 类型：`remote_port` 为空 且（`vhost` 或 `vhosts` 或 `subdomain` 至少一项非空）。
- 每个域名经归一化后必须通过 FR-009 的 vhost 授权检查。
- 服务端未配置对应 vhost 监听端口时，注册**必须失败**（spec 边界情形）。

**状态流转**（服务端侧）：

```text
收到 register_proxy
  → 类型支持检查 ──失败──► RegisterProxyAck{ok:false, error}
  → vhost 授权检查 ──失败──► 同上
  → 监听端口已配置检查 ──失败──► 同上
  → 逐域名冲突检查 ──冲突──► 同上（FR-007，不影响先注册者）
  → 原子登记（registry.by_name + by_vhost）
  → RegisterProxyAck{ok:true}
会话结束 → cleanup_session 按会话 id 清理 by_name/by_port/**by_vhost**
```

## 3. VhostRoute（域名映射，进程内）

服务端路由表项。挂在既有 `Registry` 上，与 `by_name`/`by_port` 同级、共用同一把锁。

| 字段 | 类型 | 说明 |
|---|---|---|
| `host` | String | **归一化后**的域名（小写、去端口、去末尾点） |
| `is_wildcard` | bool | 是否来自 `*.domain` 形态的注册 |
| `session` | Arc\<SessionHandle\> | 归属会话，用于清理与策略 |
| `proxy_name` | String | 反查代理 |
| `kind` | `Http` \| `Https` | 决定它在哪个监听端口命中 |

**结构**: 两张表 `exact: HashMap<String, VhostRoute>` 与
`wildcard: HashMap<String, VhostRoute>`（键为去掉 `*.` 的后缀）。查询先 exact 后 wildcard。

**归一化函数**: 注册与查询**必须**调用同一个 `normalize_host()`。规则：ASCII 小写、剥离
`:` 之后的部分、剥离末尾 `.`。这是本模块最容易出隐性 bug 的点，需单元测试锁定。

**匹配语义**:

- `exact` 命中 → 转发。
- `wildcard` 命中要求：请求 host 以 `<label>.<后缀>` 结尾，且 `<label>` 非空、不含点。
- 两级都未命中 → 404，且**不回落到任何其他代理**（FR-006）。

## 4. HttpInit / HttpResponseMeta（线上模型）

`Message` 枚举的新增内容，遵循既有约定：JSON 编码、`type` 判别、未知字段忽略。

### 4.1 `HttpInit`（S→C，请求元数据）

| 字段 | 类型 | 说明 |
|---|---|---|
| `method` | String | 原样透传 |
| `path` | String | 含 query string |
| `version` | String | `HTTP/1.1` 或 `HTTP/2`，供客户端决定是否降级 |
| `headers` | Vec\<(String, String)\> | **有序**，保留重复头；已剥离逐跳头并追加转发头（research D3/D7） |

### 4.2 `HttpResponseMeta`（C→S，响应元数据）

| 字段 | 类型 | 说明 |
|---|---|---|
| `status` | u16 | 原样透传 |
| `headers` | Vec\<(String, String)\> | 有序；已剥离逐跳头 |

### 4.3 承载位置

| 承载 | 请求元数据 | 响应元数据 |
|---|---|---|
| M1（TCP 隧道） | 控制通道 `new_connection` 的扩展字段 | 数据流上 client 方向第一条消息 |
| M2（QUIC 隧道） | 数据流首帧（与既有 `conn_init` 同帧） | 同上 |

**不变量**:

- 元数据帧 **MUST** 是该方向在数据流上的第一条消息；其后全部为裸字节。
- 元数据帧长度受既有 64 KiB 帧上限约束；超限时服务端回 4xx 且**不断开控制通道**（research D3）。
- `HttpInit`/`HttpResponseMeta` 只用于 `Http`/`Https` 类型代理；`Tcp`/`Udp` 路径上不得出现。
- 旧版客户端收到 `Http`/`Https` 类型的注册请求应被服务端在**注册阶段**拒绝，而非运行时静默失败。

## 5. CertificateEntry（证书，进程内）

| 字段 | 类型 | 说明 |
|---|---|---|
| `domain` | String | 归一化域名，作为 SNI 查表键 |
| `cert_chain` | Vec\<CertificateDer\> | PEM 解析结果 |
| `private_key` | PrivateKeyDer | 与证书一并加载，启动期校验配对 |

**不变量**:

- 启动时加载并校验；证书与私钥不配对 → 启动失败并给出明确错误（不静默跳过该域名）。
- SNI 未命中 → **拒绝握手**，不回落默认证书（research D4）。
- 通配域名证书（`*.example.com`）按 rustls 的 SNI 匹配语义处理，与 `VhostRoute` 的通配规则
  **相互独立**——路由通配与证书通配是两件事，不得互相推导。

## 6. Session / Identity（复用，不改）

M1.5 已确立：`token` 即身份，`AuthIdentity::{Legacy, User}`，端口与 vhost 授权各自独立检查。
S1 只**新增调用点**——注册 `Http`/`Https` 时走既有的 `authorize_vhost()`，不新增授权逻辑。

**不变量**：授权失败发生在认证之后，`RegisterProxyAck.ok=false` 且带明确原因（与认证失败的模糊
语义区分开）。该语义在 S1 保持不变。

## 7. 后续实体（S2–S5，此处只固定形态约束）

| 实体 | 关键约束 |
|---|---|
| `UdpSession` | 键为"外部源地址 + 源端口"；带 `last_active` 与可配置空闲阈值；回收后同源端口可重建（FR-013/014） |
| `LoadBalancerGroup` | 键为（proxy 名 + group key）；组内成员必须同类型、同入口标识（FR-022） |
| `HealthState` | 每代理的连续失败计数与当前可用位；探针流量不受该代理的压缩/限速/PROXY 头影响（FR-021） |
| `MetricsSnapshot` | 只读聚合：连接数、字节数、会话数、代理状态；不得反向影响数据面（FR-032） |

## 8. 与现有代码的映射

| 现有位置 | S1 动作 |
|---|---|
| `common/src/msg.rs` `ProxyType` | 打开 `Http`/`Https`（枚举本身已存在，不改定义） |
| `common/src/msg.rs` `Message::RegisterProxy` | 新增 `vhosts` / `subdomain` 字段（可选，向后兼容） |
| `common/src/msg.rs` `Message::NewConnection` | 新增可选 http 元数据字段（M1 路径携带） |
| `common/src/msg.rs` `Message::ConnInit` | 新增可选 http 元数据字段（M2 路径携带） |
| `common/src/msg.rs` | 新增 `Message::HttpResponseMeta` 变体 |
| `server/src/session.rs:177` | 移除"非 Tcp 一律拒绝"，改为按类型分派校验 |
| `client/src/main.rs:34` | 移除"非 Tcp 一律拒绝"的启动检查 |
| `client/src/lib.rs:149` | `vhost: None` 硬编码改为从配置透传 |
| `server/src/state.rs` `Registry` | 新增 `by_vhost_exact` / `by_vhost_wildcard` 两张表 |
| `server/src/state.rs` `cleanup_session` | 同步清理域名索引 |

**兼容性**：以上均为"加字段不改语义"的次号演进（`docs/protocol.md` 版本策略），主号保持 `1.0`。
