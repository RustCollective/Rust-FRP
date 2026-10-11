---

description: "Task list for 001-frp-parity"
---

# Tasks: frp 功能对等（技术债务清偿基线）

**Input**: Design documents from `/specs/001-frp-parity/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: 包含。spec 的 SC-003 要求"每一项新增能力至少伴随一条端到端测试"，宪法附加约束要求协议层单测 + 端到端真实链路。

**Organization**: 按用户故事（spec 的 P1→P5）分期，每期独立可交付、独立可验收。宪法原则 I 要求每期收尾独立提交并推送；宪法原则 II 要求每期验收走本机 rfpc ↔ 上游 rfps 真实链路。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 可并行（不同文件、无未完成依赖）
- **[Story]**: 所属用户故事（US1–US5）
- 描述包含确切文件路径

## Path Conventions

单 Cargo workspace 三 crate：`common/src/`、`client/src/`、`server/src/`；端到端测试在 `server/tests/`。

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: 依赖引入与模块骨架，全部故事共享

- [x] T001 在 `Cargo.toml` 的 `[workspace.dependencies]` 新增 `hyper` 1.x、`hyper-util` 0.1.x、`http` 1.x、`http-body-util` 0.1.x（research.md D9 已确认本机缓存可得）
- [x] T002 [P] 在 `server/Cargo.toml` 引用 T001 新增的四个依赖（用 `workspace = true`）
- [x] T003 [P] 在 `client/Cargo.toml` 引用 T001 新增的四个依赖（用 `workspace = true`）
- [x] T004 [P] 在 `client/src/lib.rs` 声明 `pub mod forward;` 与在 `client/src/main.rs` 声明对应模块（宪法附加约束：注释与文档使用中文）
- [x] T005 在 `server/src/lib.rs` 声明 `pub mod vhost;`，创建 `server/src/vhost/mod.rs` 空模块骨架，`cargo check --workspace` 通过

**Checkpoint**: `cargo check --workspace` 与 `cargo test --workspace` 全绿（基线 23 项无回归）

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: 协议层与配置层的共用改动。**⚠️ 本阶段完成前任何用户故事都无法开工**

- [x] T006 在 `common/src/msg.rs` 新增 `HttpInit` 结构体：`method: String`、`path: String`（含 query）、`version: String`、`headers: Vec<(String, String)>`（**有序，保留重复头**，见 data-model.md §4.1）
- [x] T007 在 `common/src/msg.rs` 新增 `Message::HttpResponseMeta { conn_id: u64, status: u16, headers: Vec<(String, String)> }` 变体（data-model.md §4.2）
- [x] T008 在 `common/src/msg.rs` 为 `Message::RegisterProxy` 新增可选字段 `vhosts: Vec<String>` 与 `subdomain: Option<String>`（`#[serde(default, skip_serializing_if)]`，次号演进，主号保持 `1.0`）
- [x] T009 在 `common/src/msg.rs` 为 `Message::NewConnection`（M1 路径）与 `Message::ConnInit`（M2 路径）新增可选字段 `http: Option<HttpInit>`（contracts/rfp1-http-vhost.md §3.1）
- [x] T010 [P] 在 `common/src/msg.rs` 的 `#[cfg(test)] mod tests` 新增：`HttpInit` 与 `HttpResponseMeta` 的 roundtrip、含 `http` 字段的 `ConnInit`/`NewConnection` roundtrip、**不含新字段的旧格式报文可被解析**（向后兼容）
- [x] T011 [P] 在 `common/src/msg.rs` 测试中新增头字段边界用例：空 header 列表、含重复 header 名、含非 ASCII 值的 roundtrip
- [x] T012 在 `server/src/state.rs` 的 `Registry` 新增 `by_vhost_exact: HashMap<String, Arc<SessionHandle>>` 与 `by_vhost_wildcard: HashMap<String, Arc<SessionHandle>>` 两张表（data-model.md §3）
- [x] T013 在 `server/src/state.rs` 新增 `normalize_host()`：ASCII 小写、剥离 `:` 之后的部分、剥离末尾 `.`；**注册侧与查询侧必须共用同一实现**（contracts/rfp1-http-vhost.md §5 的 Normative 条款）
- [x] T014 [P] 在 `server/src/state.rs` 的 `#[cfg(test)] mod tests` 新增 `normalize_host()` 单测：大小写、带端口、带末尾点、含非 ASCII、空串
- [x] T015 在 `server/src/state.rs` 的 `cleanup_session` 中同步清理 `by_vhost_exact` / `by_vhost_wildcard`，沿用既有"只清理仍归属本会话的表项"判定（`s.id == session.id`）
- [x] T016 在 `server/src/config.rs` 新增 `[http]`（`bind_port`、可选 `bind_addr`）与 `[https]`（同）两个段，均缺省不启用
- [x] T017 在 `server/src/config.rs` 新增 `subdomain_host: Option<String>` 与 `certs: Vec<CertEntry>`（`domain` / `cert` / `key` 三个字段）
- [x] T018 在 `server/src/config.rs` 实现启动期校验（contracts/config-vhost.md §1.3）：`[https]` 启用但 `certs` 为空 → 拒绝启动；证书与私钥不配对 / PEM 解析失败 → 拒绝启动并指明 `domain`；`subdomain_host` 与某精确域名同形 → 拒绝启动；端口与 `bind_port` 或已注册端口冲突 → 拒绝启动
- [x] T019 [P] 在 `server/src/config.rs` 的测试模块新增上述四条启动校验的正反用例
- [x] T020 在 `client/src/config.rs` 为代理配置新增 `custom_domains: Vec<String>`、`subdomain: Option<String>`、`[proxies.local_tls]`（`enabled` / `verify` / `fingerprint`）
- [x] T021 在 `client/src/config.rs` 实现启动期校验（contracts/config-vhost.md §2.3）：`http`/`https` 类型下 `custom_domains` 与 `subdomain` 至少一项非空且 `remote_port` 必须为空；`tcp`/`udp` 类型下二者必须为空；`verify = "fingerprint"` 时必须给 `fingerprint`
- [x] T022 [P] 在 `client/src/config.rs` 的测试模块新增上述校验的正反用例

**Checkpoint**: 协议与配置层就绪，`cargo test --workspace` 全绿；**此阶段收尾执行一次提交**（宪法原则 I）

---

## Phase 3: User Story 1 - 用自有域名暴露内网 Web 服务 (Priority: P1) 🎯 MVP

**Goal**: 客户端可注册 `http`/`https` 类型代理并绑定自有域名；服务端按 `:authority`/SNI 路由并终止 TLS，转发时附加 `X-Forwarded-For` / `X-Forwarded-Proto`。

**Independent Test**: 按 [quickstart.md](./quickstart.md) 第 4 节，在本机 rfpc ↔ 上游 rfps 真实链路上跑通场景 4.2–4.8。

### Tests for User Story 1 ⚠️

> **NOTE: 先写测试并确认失败，再进入实现**

- [x] T023 [P] [US1] 在 `server/tests/e2e.rs` 新增 vhost 明文路由 e2e：起 rfps（启用 `[http]`）+ rfpc，用 `Host` 头访问，断言内容来自本地 origin
- [x] T024 [P] [US1] 在 `server/tests/e2e.rs` 新增 HTTPS SNI 终止 e2e：用测试证书起 `[https]`，用 rustls 客户端以 SNI 连接，断言握手成功且收到 200
- [x] T025 [P] [US1] 在 `server/tests/e2e.rs` 新增未注册域名 e2e：断言返回 404，且客户端侧无任何转发记录
- [x] T026 [P] [US1] 在 `server/tests/e2e.rs` 新增域名冲突 e2e：第二个会话注册同域名，断言 `RegisterProxyAck.ok=false` 且携带冲突域名，先注册者访问仍正常
- [x] T027 [P] [US1] 在 `server/tests/e2e.rs` 新增转发头 e2e：断言 origin 侧收到 `X-Forwarded-For`（访客地址，非 loopback）与 `X-Forwarded-Proto`
- [x] T028 [P] [US1] 在 `server/tests/e2e.rs` 新增未配置 vhost 监听端口时注册失败的 e2e（spec 边界情形）
- [x] T029 [P] [US1] 在 `server/tests/e2e.rs` 新增授权失败 e2e：用户模式下的域名不在 `vhosts` 授权范围，断言注册被拒且原因复用既有措辞

### Implementation for User Story 1

- [x] T030 [P] [US1] 在 `server/src/vhost/router.rs` 实现路由查询：归一化 host 后先查 `exact` 再查 `wildcard`；wildcard 命中要求 `<label>.<后缀>` 且 `<label>` 非空、不含点；两级皆未中返回 `None`（data-model.md §3）
- [x] T031 [P] [US1] 在 `server/src/vhost/router.rs` 的测试模块新增匹配语义单测：精确优先于通配、`evil-alice.dev` 不匹配 `*.alice.dev`、`x.alice.dev` 匹配、`a.b.alice.dev` 不匹配、裸域不匹配通配
- [x] T032 [US1] 在 `server/src/state.rs` 实现域名注册路径：对 `vhost` / `vhosts` / `subdomain`（展开为 `<subdomain>.<subdomain_host>`）逐一走 `authorize_vhost()`、逐域名冲突检查、然后原子登记到两张表（依赖 T013、T016、T017）
- [x] T033 [US1] 在 `server/src/session.rs` 的 `register_proxy` 分派中移除 `if proxy_type != ProxyType::Tcp` 的一律拒绝（`server/src/session.rs:177`），改为按类型校验：`Http`/`Https` 要求 `remote_port` 为空且域名至少一项、要求对应监听端口已配置；错误原因按 contracts/rfp1-http-vhost.md §2 的表格分列
- [x] T034 [US1] 在 `server/src/vhost/certs.rs` 实现 rustls `ResolvesServerCert`：按 ClientHello 的 SNI 查证书表；**未命中一律拒绝握手，不回落默认证书**（research.md D4）
- [x] T035 [P] [US1] 在 `server/src/vhost/certs.rs` 的测试模块新增单测：命中精确域名、命中通配证书、未命中返回 `None`
- [x] T036 [US1] 在 `server/src/vhost/proxy.rs` 实现请求侧处理：剥离逐跳头（`connection`、`keep-alive`、`proxy-authenticate`、`proxy-authorization`、`te`、`trailer`、`transfer-encoding`、`upgrade`，以及 `connection` 中列出的自定义扩展头），**追加**（非覆盖）`x-forwarded-for` 与 `x-forwarded-proto`（research.md D7）
- [x] T037 [P] [US1] 在 `server/src/vhost/proxy.rs` 的测试模块新增逐跳头剥离与转发头追加的单测，含"已存在 `x-forwarded-for` 时用 `, ` 追加"的用例
- [x] T038 [US1] 在 `server/src/vhost/proxy.rs` 实现流式双向管道：请求体从 hyper 的 body 逐块读出直写隧道流，响应体用适配器把隧道读端包成 `hyper::body::Body`。**MUST NOT 整体缓冲，MUST NOT 在中间引入无界 channel**（research.md D6、FR-011、SC-007）
- [x] T039 [US1] 在 `server/src/vhost/proxy.rs` 实现错误响应：域名未命中或 `kind` 与监听端口不匹配 → 404 且不回落；元数据帧超 64 KiB → 4xx 且不断开控制通道；客户端本地服务拒绝连接 → 502（contracts/rfp1-http-vhost.md §5）
- [x] T040 [US1] 在 `server/src/vhost/mod.rs` 装配监听：`[http]` 用 `hyper_util::server::conn::auto::Builder` 自动协商 h1 与 h2c；`[https]` 用 `tokio-rustls` + T034 的证书解析 + 同一 auto builder
- [x] T041 [US1] 在 `server/src/session.rs` 的 M1 路径扩展 `new_connection`：`http` 类型代理在通知中携带 `HttpInit`，随后照旧等待 client 回连（contracts §3.1）
- [x] T042 [US1] 在 `server/src/quic.rs` 的 M2 路径：`open_bi` 后写入携带 `HttpInit` 的 `conn_init` 首帧，再进入裸字节转发
- [x] T043 [US1] 在 `client/src/lib.rs` 实现接收分派：识别 `http` 元数据（M1 来自 `new_connection`、M2 来自 `conn_init` 首帧），交由 `forward` 模块处理
- [x] T044 [US1] 在 `client/src/forward.rs` 实现请求转发：按 `HttpInit` 构造 HTTP/1.1 请求发往 `local_addr`；`[proxies.local_tls].enabled = true` 时用 TLS（`verify` 为 `system` 时用系统根、`skip` 时跳过并在日志以 warn 提示）——research.md D8
- [x] T045 [US1] 在 `client/src/forward.rs` 实现响应回传：在数据流上写 `http_response_meta` 作为**该方向第一条消息**，随后写裸响应体至半关闭（data-model.md §4.3）
- [x] T046 [US1] 在 `client/src/main.rs` 移除启动期"非 Tcp 一律拒绝"的检查（`client/src/main.rs:34`），改为调用 T021 的类型化校验
- [x] T047 [US1] 在 `client/src/lib.rs` 修正 `register_proxy` 的 `vhost: None` 硬编码（`client/src/lib.rs:149`），改为透传配置中的 `custom_domains` / `subdomain`
- [x] T048 [US1] 在 `server/src/lib.rs` 接线：按配置在启动时拉起 `vhost::mod` 的监听任务，与既有控制面共用 `ServerState`
- [x] T049 [US1] 在 `server/src/vhost/proxy.rs` 与 `client/src/forward.rs` 补齐 tracing：info 记代理名/域名/状态码/字节数，debug 记元数据帧内容（宪法附加约束的日志约定）

### Verification for User Story 1

- [x] T050 [US1] 跑 [quickstart.md](./quickstart.md) 第 2 节门禁：`cargo test --workspace` 全绿且既有 23 项无回归（SC-003）
- [x] T051 [US1] 部署到上游并按 quickstart 4.1 重启两侧服务；确认上游需先放行 vhost 端口（宪法原则 II 的环境前置），并把新端口写入 `docs/CONVENTIONS.md` 的「公网部署状态」
- [x] T052 [US1] 按 `specs/001-frp-parity/quickstart.md` 4.2–4.6 在真实链路上验收场景 A–E，**4.3 禁止用 `-k` 跳过证书校验**
- [ ] T053 [US1] 按 `specs/001-frp-parity/quickstart.md` 4.7 验收流式转发：1GB 与 1MB 下载下上游 rfps 的 RSS 增量处于同一量级（SC-007）
- [ ] T054 [US1] 按 `specs/001-frp-parity/quickstart.md` 4.8 验收延迟：P95 附加延迟 < 50ms（SC-004）
- [ ] T055 [US1] 回填 [research.md](./research.md) 的「遗留待验证项」1–3；若 auto builder 的 h2c 协商实测退化，明确"明文端口仅 h1.1、TLS 端口 h1+h2"并同步 spec 与 contracts

**Checkpoint**: US1 独立可交付。**此阶段收尾执行一次提交并推送**（宪法原则 I）

---

## Phase 4: User Story 2 - 暴露内网 UDP 服务 (Priority: P2)

**Goal**: `udp` 类型代理可用，按"外部源地址+源端口"识别会话，空闲可回收。

**Independent Test**: 按 quickstart 的对应扩展场景，在真实链路上跑通 UDP 回声并观察空闲回收。

**依赖**: 复用 US1 建立的"元数据进首帧、其余裸字节"承载模式（research.md D2）。

- [x] T056 [P] [US2] 在 `server/src/udp.rs` 新建模块并实现 UDP 监听与转发表骨架（`HashMap<(SocketAddr, u16/*?*/), UdpSession>`，键为外部源地址+源端口）
- [x] T057 [US2] 在 `server/src/udp.rs` 实现会话双向转发：保持数据报边界，**MUST NOT 合并或分片重组**（FR-013）
- [x] T058 [US2] 在 `server/src/state.rs` 的 `UdpSession` 增加 `last_active: Instant` 与可配置空闲阈值，实现后台回收任务（FR-014）
- [x] T059 [US2] 在 `server/src/udp.rs` 实现超帧数据报处置：单帧超限时丢弃并计数，MUST NOT 静默截断（FR-016）
- [x] T060 [US2] 在 `server/src/session.rs` 打开 `ProxyType::Udp` 的注册分支，端口授权复用既有 `authorize_port()`（FR-012）
- [x] T061 [US2] 在 `client/src/config.rs` 与 `client/src/lib.rs` 打开 `udp` 类型：本地 UDP 转发与数据报边界保持
- [x] T062 [P] [US2] 在 `server/tests/e2e.rs` 新增 e2e：UDP 回声链路、同一源端口复用同一会话、换源端口视为新会话
- [x] T063 [P] [US2] 在 `server/tests/e2e.rs` 新增 e2e：空闲回收后同源端口可重建会话
- [x] T064 [P] [US2] 在 `server/tests/e2e.rs` 新增 e2e：用户模式下端口不在授权区间时注册被拒（FR-012）
- [x] T065 [US2] 在 `server/tests/e2e.rs` 新增 e2e：UDP 代理分别经 TCP 隧道与 QUIC 隧道承载，行为一致（FR-015）
- [ ] T066 [US2] 在真实链路上验收 UDP：**需先解除上游 UDP 端口放行的遗留阻塞**（`docs/CONVENTIONS.md`「公网部署状态」），并把结果与放行后的端口写入该节；同步更新 `specs/001-frp-parity/spec.md` 附录 A.5

**Checkpoint**: US2 独立可交付。**收尾提交并推送**

---

## Phase 5: User Story 3 - 让穿透链路具备生产可用的转发选项 (Priority: P3)

**Goal**: 压缩、限速、PROXY 协议、健康检查、负载均衡、自动端口、冲突策略、路径路由逐项可用。

**Independent Test**: 每项按 spec US3 的验收场景独立验证，互不回归。

- [ ] T067 [P] [US3] 在 `common/src/msg.rs` 为 `RegisterProxy` 新增 `transport` 选项字段（压缩、带宽限制、PROXY 协议版本），保持"加字段不改语义"
- [ ] T068 [US3] 在 `client/src/forward.rs` 实现压缩：启用时对**该代理**的隧道载荷压缩，不影响其他代理（FR-017）
- [ ] T069 [US3] 在 `client/src/forward.rs` 与 `server/src/vhost/proxy.rs` 实现带宽限制：计量隧道内**实际传输字节**（而非原始载荷），限速作用于该代理（FR-018）
- [ ] T070 [US3] 在 `client/src/forward.rs` 实现 PROXY 协议头（v1/v2）：在业务数据之前发送，客户端配置驱动（FR-019）
- [ ] T071 [US3] 在 `client/src/health.rs` 新建模块实现周期性健康检查：连续失败达阈值 → 该代理拒绝新接入；恢复 → 自动重新接入，无需重启（FR-020）
- [ ] T072 [US3] 在 `client/src/health.rs` 保证探针流量**不受**该代理的压缩、限速与 PROXY 协议头设置影响（FR-021），并加注释说明原因
- [ ] T073 [US3] 在 `server/src/state.rs` 新增 `LoadBalancerGroup`（键为 proxy 名 + group key，组内成员必须同类型同入口标识）与按配置策略选后端（FR-022）
- [ ] T074 [US3] 在 `server/src/session.rs` 与 `server/src/state.rs` 实现自动端口分配：`remote_port` 缺省或为 0 时在授权区间内分配并回告客户端；区间耗尽必须失败并给出原因（FR-023）
- [ ] T075 [US3] 在 `server/src/config.rs` 新增同名代理冲突策略配置项（拒绝后者 / 抢占），并在客户端侧把处置结果明确回显（FR-024）
- [ ] T076 [US3] 在 `server/src/vhost/router.rs` 实现基于请求路径的路由细化，并固定匹配优先级（域名精确 → 域名通配 → 路径最长前缀），加单测锁定（FR-025）
- [ ] T077 [P] [US3] 在 `server/tests/e2e.rs` 新增 e2e：限速生效且不影响其他代理；压缩使隧道字节数显著低于原始体积
- [ ] T078 [P] [US3] 在 `server/tests/e2e.rs` 新增 e2e：PROXY 协议头在业务数据之前到达，origin 读到真实源地址
- [ ] T079 [P] [US3] 在 `server/tests/e2e.rs` 新增 e2e：健康检查失败后代理拒绝接入、恢复后自动重新接入
- [ ] T080 [P] [US3] 在 `server/tests/e2e.rs` 新增 e2e：负载均衡组内两后端都收到请求；自动端口分配落在授权区间内、区间耗尽时报错
- [ ] T081 [US3] 在真实链路上逐项验收 US3，并在 `docs/CONVENTIONS.md` 记录新增配置项

**Checkpoint**: US3 独立可交付。**收尾提交并推送**

---

## Phase 6: User Story 4 - 不暴露公网端口的点对点穿透 (Priority: P4)

**Goal**: `stcp` / `sudp` 密钥保护的穿透可用；`xtcp` 在可打洞时直连、失败回退中转。

**Independent Test**: 发布方不开公网端口，访问方持相同密钥可接入；密钥不符被拒；打洞失败时功能仍可用。

> ⚠️ **本阶段需先补 Phase 0 研究**：xtcp 的 NAT 类型探测与打洞策略未在本计划的 research.md 中收敛（当时设计重心是 P1）。T082 是显式的研究任务，产出回填 research.md 后才进入实现。

- [ ] T082 [US4] 补 Phase 0 研究：调研 NAT 类型探测与打洞方案（含失败回退判定），把决策/理由/被否决方案追加到 [research.md](./research.md)；同时确定 `stcp`/`sudp` 的密钥交换与校验方式（不允许明文传输密钥）
- [ ] T083 [US4] 在 `common/src/msg.rs` 新增 `stcp` / `sudp` / `xtcp` 所需的注册与访问消息（含密钥字段，保持加字段不改语义）
- [ ] T084 [US4] 在 `server/src/state.rs` 实现 `stcp` / `sudp`：不开放公网端口，仅按密钥匹配发布方与访问方（FR-026、FR-027）
- [ ] T085 [US4] 在 `client/src/lib.rs` 实现访问方本地监听：按配置在本地起监听并把连接接入发布方
- [ ] T086 [US4] 在 `server/src/state.rs` 保证密钥不匹配的接入被拒，且响应不泄露发布方是否存在以外的信息（FR-029）
- [ ] T087 [US4] 在 `server/src/xtcp.rs`（新建）与 `client/src/lib.rs` 实现 `xtcp` 直连：打洞成功走端到端，失败 MUST 自动回退到中转路径（FR-028）
- [ ] T088 [P] [US4] 在 `server/tests/e2e.rs` 新增 e2e：同密钥可接入、异密钥被拒、发布方无公网端口暴露
- [ ] T089 [P] [US4] 在 `server/tests/e2e.rs` 新增 e2e：打洞条件不成立时自动回退中转且功能可用
- [ ] T090 [US4] 按 `specs/001-frp-parity/quickstart.md` 的拓扑在真实链路上验收 US4（本机 rfpc ↔ 上游 rfps），结果写入该文件

**Checkpoint**: US4 独立可交付。**收尾提交并推送**

---

## Phase 7: User Story 5 - 用一个运维面看清并改动整个部署 (Priority: P5)

**Goal**: 管理接口（默认仅本机 + 凭证）、Dashboard、指标、热重载、includes、插件机制。

**Independent Test**: 管理接口从非本机被拒；查询返回代理与会话状态；热重载不中断在途连接；指标端点可被标准抓取器读取；配置拆分后行为一致。

- [ ] T091 [US5] 在 `server/src/admin.rs` 新建模块实现管理接口：**默认只监听本机并要求凭证**，能列出代理、会话与流量统计（FR-030）
- [ ] T092 [US5] 在 `server/src/admin.rs`（静态资源目录 `server/src/admin_assets/`）实现只读可视化界面，展示代理与会话状态（FR-031）
- [ ] T093 [US5] 在 `server/src/metrics.rs` 新建模块暴露标准抓取格式指标（连接数、流量、会话、代理状态），借鉴既有 health 检查思路，指标采集**不得反向影响数据面**（FR-032）
- [ ] T094 [US5] 在 `client/src/main.rs` 与 `client/src/lib.rs` 实现配置热重载：新增/变更代理生效、删除代理下线、**在途转发连接按既定语义处理且不悬挂**（FR-033）
- [ ] T095 [US5] 在 `server/src/config.rs` 与 `client/src/config.rs` 实现配置 `includes` 多文件合并，行为与单文件一致（FR-034）
- [ ] T096 [US5] 在 `client/src/plugin/mod.rs`（新建模块目录）设计并实现插件机制，至少覆盖：内网明文 HTTP 以 HTTPS 暴露、内网 HTTPS 以明文 HTTP 暴露、静态文件目录、SOCKS5、Unix 域套接字（FR-035）
- [ ] T097 [P] [US5] 在 `server/tests/e2e.rs` 新增 e2e：管理接口非本机访问被拒、本机带正确凭证可查
- [ ] T098 [P] [US5] 在 `server/tests/e2e.rs` 新增 e2e：热重载期间在途连接不中断、新增代理立即可用
- [ ] T099 [P] [US5] 在 `server/tests/e2e.rs` 新增 e2e：配置拆分与单文件行为一致
- [ ] T100 [US5] 在真实链路上验收 US5，并把管理接口与指标端点的监听地址、端口写入 `docs/CONVENTIONS.md`

**Checkpoint**: US5 独立可交付。**收尾提交并推送**

---

## Phase 8: Polish & Cross-Cutting Concerns

**Purpose**: 跨故事的收尾与对等性复核

- [ ] T101 [P] 更新 `README.md` 的 Roadmap（M2.5–M2.9 与 M3 的关系）与横向对比表
- [ ] T102 [P] 修正 `docs/protocol.md` 的状态行与 M1/M2/M3 之外的描述，使其与实现一致
- [ ] T103 [P] 逐条对照 `specs/001-frp-parity/spec.md` 的 FR-001~036 与 SC-001~007，产出对等性复核结论并回填 spec 的 Status
- [ ] T104 [P] 更新 `CHANGELOG.md`，按里程碑分节补充 S1–S5 的实际交付内容
- [ ] T105 复核 `specs/001-frp-parity/spec.md` 附录 A.5 的遗留阻塞是否已全部清零（公网 QUIC 验证、生产切换、ACME）
- [ ] T106 [P] 对照 `.specify/memory/constitution.md` 五条原则逐条复查 `specs/001-frp-parity/plan.md` 的宪法门禁表，结论回填该表（宪法 Governance 要求）
- [ ] T107 按 [quickstart.md](./quickstart.md) 跑一遍完整验收并记录结果

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: 无依赖，可立即开始
- **Foundational (Phase 2)**: 依赖 Setup —— **阻塞全部用户故事**
- **US1 (Phase 3)**: 依赖 Foundational。是 US2–US5 的架构前置（元数据承载模式、vhost 路由）
- **US2 (Phase 4)** / **US3 (Phase 5)**: 依赖 Foundational；US3 的路径路由复用 US1 的 router
- **US4 (Phase 6)**: 依赖 Foundational，且 T082 研究解锁前不得进入实现；UDP 相关依赖 US2
- **US5 (Phase 7)**: 依赖 Foundational；管理接口展示域名映射依赖 US1
- **Polish (Phase 8)**: 依赖所需故事全部完成

### User Story Dependencies

| 故事 | 可独立开工于 | 说明 |
|---|---|---|
| US1 | Foundational 之后 | 无跨故事依赖，MVP |
| US2 | Foundational 之后 | 复用 US1 承载模式，但可独立实现与测试 |
| US3 | Foundational 之后 | 路径路由（T076）需 US1 的 router 已存在 |
| US4 | T082 研究之后 | 阻塞点显式 |
| US5 | Foundational 之后 | 管理接口的域名视图需 US1 |

### Within Each User Story

- 测试先写并确认失败 → 模型 → 服务 → 集成 → 真实链路验收
- 一期完成再进入下一优先级（宪法原则 I：每期收尾独立提交）

### Parallel Opportunities

- T002 / T003 / T004（不同 Cargo.toml 与模块声明）
- T010 / T011（同一测试模块，但可与 T012 起的数据结构改动并行）
- T014 / T019 / T022（三处不同文件的单测）
- T023–T029（US1 的七条 e2e 用例）
- T030 / T031 与 T032 的 router 部分
- T035 与 T036 的实现
- 各故事的 [P] e2e 用例之间

---

## Parallel Example: User Story 1

```bash
# 七条 e2e 用例可并行编写（同一文件的不同测试函数，需协调写序避免冲突）：
Task: "vhost 明文路由 e2e in server/tests/e2e.rs"
Task: "HTTPS SNI 终止 e2e in server/tests/e2e.rs"
Task: "未注册域名 404 e2e in server/tests/e2e.rs"
Task: "域名冲突 e2e in server/tests/e2e.rs"

# 路由与证书两条支线可并行：
Task: "实现 router 查询与匹配语义单测 in server/src/vhost/router.rs"
Task: "实现 ResolvesServerCert 与单测 in server/src/vhost/certs.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup
2. Phase 2 Foundational（阻塞项，必须完成）
3. Phase 3 User Story 1
4. **STOP 并验收**：按 quickstart 第 4 节在真实链路验证
5. 提交推送（宪法原则 I）

US1 完成后即具备 M3（HTTP/3 网关）的起步条件——`vhost::router` 就是 H3 网关要复用的路由层。

### Incremental Delivery

1. Setup + Foundational → 地基就绪
2. US1 → 真实链路验收 → 提交（MVP，解锁 M3 前置）
3. US2 → 验收 → 提交（顺带解除 M2 遗留的 UDP 放行阻塞）
4. US3 → 验收 → 提交（承接 frp 存量配置）
5. US4 → 研究 → 验收 → 提交
6. US5 → 验收 → 提交（具备长期托付条件）

每一期都不破坏前一期。

---

## Notes

- [P] = 不同文件、无未完成依赖
- [Story] 标签把任务映射回 spec 的用户故事，便于追溯
- **宪法原则 I**：每期 Checkpoint 处提交并推送 `origin/main`，不积压
- **宪法原则 II**：T051/T066/T081/T090/T100 的"真实链路验收"是本机 rfpc ↔ 上游 rfps，本机自环只作回归
- **宪法原则 V**：不得为了省事改 `conn_id` 分配、加连接池、引入隧道内 L7 编解码层
- 实现前先看 [research.md](./research.md) 的决策与**被否决方案**，避免重复讨论

---

## Phase 9: Convergence（真实链路验收暴露的问题）

**来源**：2026-10-12 上游真实链路验收。证据见 [research.md](./research.md) D11。

- [ ] T108 修订 `contracts/rfp1-http-vhost.md` §3.3 与 `data-model.md` §4.3：把
      "半关闭即体结束"改为显式分帧（`HttpInit 帧 → N 个长度前缀体帧 → 0 长度帧`，
      响应方向同构），并说明为何不再依赖半关闭
- [ ] T109 按修订后的契约改 `server/src/vhost/proxy.rs`（请求方向分帧 + 不再提前
      shutdown；响应方向分帧收尾）
- [ ] T110 按修订后的契约改 `client/src/forward.rs`（两个方向都按帧收发；写完后
      等对端关闭连接再释放 socket，关闭时不得有在途数据）
- [ ] T111 在 `server/tests/e2e.rs` 增加"大响应不截断"回归用例（≥8 MiB，逐字节校验
      长度），并断言客户端关闭前对端已读完
- [ ] T112 重跑 T053（流式/SC-007）与 T054（延迟/SC-004）的上游真实链路验收
- [ ] T113 验收通过后清理上游的验收遗留：删除临时 nginx 站点文件并 reload、
      按需移除 `rfps.toml` 中的 `[http]`/`[https]`/`[[certs]]` 与 65532 端口授权
