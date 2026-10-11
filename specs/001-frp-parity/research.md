# Phase 0 Research: frp 功能对等

**Feature**: `001-frp-parity` | **Date**: 2026-10-11

Technical Context 中的未知项与关键选型在此收敛。每条记录包含决策、理由与被否决的替代方案。
设计重心是 P1（US1，域名路由型 HTTP/HTTPS 代理），其余故事只在此收敛其架构增量。

---

## D1. HTTP 服务端与客户端库

**Decision**: 引入 `hyper` 1.x + `hyper-util`（`server::conn::auto::Builder`）+ `http` 1.x +
`http-body-util`。服务端用它承载 vhost 网关的 h1 / h2c / TLS 终止；客户端用它构造发往本地服务的
请求。

**Rationale**:

- `auto::Builder` 在同一个监听端口上自动协商 h1 与 h2c，直接满足 FR-002 的"HTTP/1.1 与 HTTP/2"。
- hyper 的 `Body` 是流式 trait，与"不整体缓冲"（FR-011、SC-007）天然契合；自研解析器要做到同等
  正确性（分块编码、续行头、h2 帧层）成本远高于引入它。
- 与 M3 的衔接：`h3` crate 的 hyper 集成即为 hyper 1.x，现在选型等价于为 M3 铺路。
- 依赖可得性已验证：本机 cargo 缓存与稀疏索引中已有 `hyper` 1.8.1、`hyper-util` 0.1.19、
  `http` 1.4.0、`http-body-util` 0.1.3，可离线解析，不阻塞开工。

**Alternatives considered**:

- **axum**（缓存中亦有 0.8.9）：否决。它带出 tower/tower-http 依赖栈，是给通用 Web 服务准备的；
  本项目只需要"解析请求 → 转发"，多出的抽象层直接换成二进制体积与常驻内存，与宪法附加约束的
  低内存定位冲突。
- **自研 h1/h2 解析**：否决。h2 帧层与 h1 的分块编码、请求走私防御面都需要长期维护，收益仅是
  省掉一个依赖。
- **只支持 h1.1**：否决。FR-002 明确要求 h2，且现代后端普遍期望 h2；退一步会让 vhost 网关成为
  降级体验。

---

## D2. HTTP 元数据的承载位置（核心决策）

**Decision**: **HTTP 语义不进隧道**。隧道的每个方向只多一条"元数据首帧"，其余仍是裸字节透传：

| 方向 | 承载位置 | 内容 |
|---|---|---|
| 请求元数据（S→C） | QUIC 路径：数据流首帧；TCP 路径：控制通道的 `new_connection` | method、path、有序 header 列表 |
| 请求体（S→C） | 数据流裸字节，至半关闭 | 不变 |
| 响应元数据（C→S） | 数据流上 client 方向的第一条消息 | status、有序 header 列表 |
| 响应体（C→S） | 数据流裸字节，至半关闭 | 不变 |

**Rationale**:

- 帧协议保持传输无关（宪法原则 IV）：新增的是 `Message` 的字段与一个新的变体，与承载无关。
- 数据面零改造：现有"首帧 + 裸字节"的透传路径、半关闭映射、背压全部原样复用，M1/M2 两条承载
  都不需要新的流语义。
- 请求元数据与请求体必须**严格有序**：client 必须先知道 method/path/header 才能开始往本地服务
  写 body。放在"client 开始读 body 之前必然到达"的位置即可满足——QUIC 路径下是同一条流的首帧
  （顺序天然保证），TCP 路径下是控制通道的消息（client 回连前已收到）。
- 这条不对称（TCP 走控制通道、QUIC 走数据流）**不是新引入的**：M1 与 M2 本就在"数据通道如何
  建立、`new_connection` 是否使用"上不同，本决策沿用既有差异，没有增加新的分支维度。

**Alternatives considered**:

- **把 HTTP 语义序列化进数据流，做成通用隧道内的 L7 帧**：否决。那等于在隧道内再造一个 HTTP
  编解码层，直接违反宪法原则 IV 的传输无关与"不引入多路复用/编解码层"的取向，且会让 UDP（P2）
  无法复用同一模式。
- **HTTP 元数据也走 `new_connection`（两条承载统一走控制通道）**：否决。M2 已明确废弃
  `new_connection` 并把调度信息移入流首帧（见 `docs/protocol.md` M2 节），反向回退是宪法原则 V
  禁止的静默回退。
- **统一在数据流首帧，TCP 路径也改成 server 先发**：否决。M1 的数据流由 client 主动回连建立，
  让 server 在一条刚被 client 建立的连接上抢发首帧会引入"谁先写"的竞态，且要改 M1 既有的
  `conn_init` 语义。

---

## D3. 请求/响应头字段的表示与上限

**Decision**: header 用**有序的 `(name, value)` 列表**（`Vec<(String, String)>`）承载，不用 map。
单条元数据帧沿用现有 64 KiB 帧上限（`docs/protocol.md`：超出即协议错误）。超限时服务端回 4xx 且
**不断开控制通道**。

**Rationale**:

- 有序列表才能保留重复头（`Set-Cookie`、`Via`）与原始顺序，map 会静默合并或丢弃，是可观测的
  语义损失。
- 复用既有上限而不是新设一个，避免出现"两套长度约束"的心智负担；64 KiB 对请求头足够（主流
  服务器默认上限 8–16 KiB）。
- "回 4xx 不断开控制通道"与既有语义一致：控制通道是长连接，单次请求的失败不应影响其他代理。

**Alternatives considered**:

- **`HashMap<String, Vec<String>>`**：否决。有序性丢失，且与 h2 的 header 语义（顺序敏感）不符。
- **单独设更小的头上限（如 16 KiB）**：推迟。当前按 64 KiB 走，若实测发现放大攻击面再收紧；
  收紧不影响本决策的结构。

---

## D4. TLS 终止与按 SNI 动态选证书

**Decision**: 复用 `rustls` 0.23 与 `tokio-rustls`，实现 `ResolvesServerCert`，按 ClientHello 的
SNI 从内存证书表选证书；证书来源为配置文件中显式声明的域名 → PEM 路径映射。未命中的 SNI
**拒绝握手**，不回落默认证书。

**Rationale**:

- `ResolvesServerCert` 是 rustls 为多域名场景提供的标准扩展点，无需自建证书缓存层。
- 项目已在用 rustls 0.23（`Cargo.toml` 的 `workspace.dependencies`），不引入新的 TLS 栈，符合
  宪法附加约束。
- 未命中即拒绝：回落默认证书会让攻击者用任意域名探测到不属于它的证书，也掩盖配置错误。

**Alternatives considered**:

- **把每个域名的证书拆成独立的 rustls `ServerConfig`，按 SNI 手动选配置**：可行但更笨重——需要在
  TLS 层之外分流，且失去 rustls 自身的证书缓存与选择优化。
- **ACME 自动签发**：明确超出本计划范围（属 M3）；本计划只要求"能选中并终止配置中已有的证书"，
  与 spec 假设一致。

---

## D5. 路由表与匹配优先级

**Decision**: 路由键为**归一化后的 host**（小写、去端口、去末尾点）。匹配顺序固定为
**精确匹配 → 通配匹配**，两级各用一张 `HashMap`；未命中返回 404。域名注册落在既有
`ServerState.registry` 的同一把锁下，与端口注册共用冲突检测与清理路径。

**Rationale**:

- 两级哈希表既给出精确优先的确定性（spec 边界情形要求），又避免每次请求做线性扫描。
- 复用既有 registry 锁：`cleanup_session` 已经处理"只清理仍归属本会话的表项"，新增域名索引挂在
  同一处即可获得同样的会话结束清理语义，不重复实现。
- 归一化必须在注册与请求两侧用同一个函数，否则会出现"注册成功但匹配不上"的隐性 bug。

**Alternatives considered**:

- **单张表 + 通配前缀匹配**：否决。通配（`*.alice.dev` 恰好一层左标签）与后缀匹配的语义不同，
  混在一张表里会让"精确优先"变成实现细节而非结构保证。
- **注册时展开通配为多条精确项**：否决。通配是无限集合，展开不成立。

---

## D6. 流式转发与背压

**Decision**: 请求体方向，hyper 的 `Incoming` body 逐块读出后直接写隧道流；响应体方向，实现一个
把隧道读端包成 `hyper::body::Body` 的适配器。全程不聚合、不缓冲整包，**依赖两侧传输层各自的
流控**（QUIC stream flow control / TCP 的 socket 背压）形成端到端背压。

**Rationale**:

- SC-007 明确要求内存不随载荷线性增长，任何"先收完再发"的实现都会直接违反。
- 隧道两条承载都已具备背压：QUIC 有每流 flow control，TCP 有 socket 缓冲区回压。实现侧只需
  **不要在中间加无界 channel**——这是本决策真正的约束点。
- 半关闭映射已在 M1/M2 实现（`docs/protocol.md`：用户连接半关闭 ↔ stream 半关闭），请求体读完
  即可触发半关闭，无需新语义。

**Alternatives considered**:

- **中间加 channel 解耦读写**：否决（无界则丢背压、有界则等价于不做）。除确有需要（P3 的限速
  需要一个中间层做计量），不引入。
- **按 `Content-Length` 预分配缓冲**：否决，直接违反 SC-007。

---

## D7. 逐跳（hop-by-hop）头与转发头

**Decision**: 服务端在构造请求元数据前剥离逐跳头（`Connection`、`Keep-Alive`、
`Proxy-Authenticate`、`Proxy-Authorization`、`TE`、`Trailer`、`Transfer-Encoding`、`Upgrade`，
以及 `Connection` 中列出的自定义扩展头）；同时**追加** `X-Forwarded-For`（追加而非覆盖已有值）与
`X-Forwarded-Proto`。响应方向反向剥离同样的头集合。

**Rationale**:

- 逐跳头原样透传会让两端对连接状态的理解不一致，是经典的协议正确性问题（FR-004 明确要求正确
  处理而非原样透传）。
- `X-Forwarded-For` 必须追加：访客可能已经过一层 CDN，覆盖会丢失真实链路；这是运维者依赖的
  排障信息。

**Alternatives considered**:

- **全部原样透传**：否决，违反 FR-004。
- **用通用库处理（如 tower-http）**：否决，同上 D1 的理由（依赖面）。

---

## D8. 客户端访问本地服务的协议选择（FR-010）

**Decision**: 客户端默认以 HTTP/1.1 访问本地服务；新增强制/可选的 HTTPS 模式，由客户端配置
决定。本地为 HTTPS 时，客户端校验策略独立于隧道 TLS（可配置为跳过校验 / 使用系统根 / 指定
指纹），默认使用系统根。

**Rationale**:

- 隧道内是明文 HTTP 语义（`X-Forwarded-Proto` 已标出访客侧协议），客户端到本地这一段是它自己的
  一跳，与外网协议解耦——这正是边缘终止模式的价值（`docs/protocol.md` M3 节）。
- 客户端到本地通常在同机或同内网，若强制校验证书会与自签内网服务冲突；默认校验、可显式放宽，
  与宪法原则 III 的"明文/放宽必须显式声明"一致。

**Alternatives considered**:

- **强制校验**：否决，自签的内网服务（很常见）会直接不可用。
- **强制跳过校验**：否决，与宪法原则 III 的取向相悖。

---

## D9. 依赖引入与离线可行性

**Decision**: 通过 `workspace.dependencies` 新增 `hyper`、`hyper-util`、`http`、`http-body-util`
四项，版本取其在本机缓存中的最新稳定版。

**Rationale**: 宪法附加约束要求依赖统一走 `workspace.dependencies`。

**已验证事实**（本机 cargo 缓存与稀疏索引）：

- 可用：`hyper` 1.8.1、`hyper-util` 0.1.19、`http` 1.4.0、`http-body-util` 0.1.3、
  `rustls` 0.23.43、`tokio-rustls` 0.26.4、`quinn` 0.11.11。
- **不可用**：`h3`、`h3-quinn` 均不在缓存与索引中——M3 开工前需通过网络（本机代理
  `127.0.0.1:10809`）拉取。这是 M3 的环境前置，不是本计划的阻塞。

**Alternatives considered**: 无（约束型决策）。

---

## D10. UDP 会话的隧道内承载（S2 补充）

**Decision**: 一条 UDP 会话（键为「外部源地址 + 源端口」）对应**一条隧道流**；流内每个
数据报用 RFP/1 既有的长度前缀帧（`u32 BE len + payload`）承载。服务端一个 UDP socket
收全部数据报，按源地址分发到各会话的出站队列；每个会话独立开隧道流。

**Rationale**:

- 隧道是字节流，UDP 的报文边界必须由我们自己标记——裸字节透传会把相邻两个数据报粘成
  一个，对 DNS / 游戏类协议是致命的。复用既有帧格式而非新增编解码层，符合宪法原则 IV
  （帧协议传输无关、不引入多余编解码层）。
- 一会话一条流：故障隔离（一条会话的拥塞不影响其他会话），且天然复用既有的
  `open_tunnel`（M1 回连 / M2 `open_bi` 两条承载零改动），FR-015 的"与承载解耦"由此免费得到。
- 这正是 `docs/protocol.md` Open Question #1 中「每会话一条 uni-stream」那一支。
- 出站队列上限 64、满了丢包：UDP 语义本就允许丢包，无界堆积只会把服务端内存拖垮；
  有界队列同时也提供了天然背压。

**Alternatives considered**:

- **QUIC datagram 统一承载**：本轮否决。省流控开销，但会为 QUIC 路径引入一条与帧协议
  并列的承载，M1/TCP 路径无法对标——那是新的传输耦合，不是简化。
- **裸字节透传、边界交给上层**：否决，见上。
- **每个数据报开一条流**：否决。开流开销随包数放大，且"同源会话"的语义无处安放
  （无法做空闲回收，也无法复用本地 UDP socket）。

**帧上限**：UDP 理论最大载荷 65507 字节 < 64 KiB 帧上限，正常路径不可能超限；两侧仍显式
检查、丢弃并告警，杜绝任何形式的静默截断（FR-016）。

**空闲回收**：由服务端 `[udp] idle_timeout_secs`（默认 60）配置，两个方向任一有活动即刷新。
该阈值同时兑现 FR-014 的"可配置"要求；测试用把它压到 1s 来覆盖重建语义。

## 遗留待验证项

以下不阻塞开工，但在 S1 实现阶段必须实测确认，结论回填此处：

1. `auto::Builder` 在**同一端口**上对 h1 与 h2c 的协商行为在真实浏览器与 curl 下是否符合预期
   （尤其 h2c 需 prior knowledge，浏览器不会用明文 h2；如实测退化则明确"明文端口仅 h1.1、
   TLS 端口 h1+h2"并在 spec 侧记录）。
2. 客户端到本地服务使用 hyper client 时，连接复用策略对短连接本地服务（每次请求新建连接的
   origin）的影响。
3. 本机 rfpc ↔ 上游 rfps 链路上 vhost 网关的 P95 附加延迟实测值（对照 SC-004 的 50ms）。
