# Implementation Plan: frp 功能对等（技术债务清偿基线）

**Branch**: `001-frp-parity` | **Date**: 2026-10-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-frp-parity/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command; its definition describes the execution workflow.

## Summary

按 spec 的 P1 → P5 优先级清偿与 frp 的功能差集。**P1（域名路由型 HTTP/HTTPS 代理）是本计划的
设计重心**，因为它是 HTTP/3 网关（M3）的唯一前置，且其余四个故事在架构上都是它的增量：
P2 复用同一套"数据流 + 元数据首帧"承载，P3/P4/P5 在既有隧道语义上叠加策略与观测。

技术路线的核心决策只有一条：**HTTP 语义不进隧道——只把请求/响应的元数据放进隧道两端各自的第一条
消息，其余仍是裸字节透传**。这样帧协议保持传输无关（宪法原则 IV），数据面零改造，且 P2 的 UDP
可以完全复用同一模式。

## Technical Context

**Language/Version**: Rust 2021 edition（当前工具链 rustc 1.94.1）

**Primary Dependencies**: 新增 `hyper` 1.x（h1/h2 服务端与客户端）、`hyper-util`（`auto::Builder`
同时处理 h1 与 h2c）、`http` 1.x、`http-body-util`。复用已有 `tokio`、`rustls` 0.23 /
`tokio-rustls`（SNI 动态证书解析）、`quinn`（隧道承载）。全部可从本机 cargo 缓存离线解析。

**Storage**: 无数据库。状态在内存（路由表、会话表、UDP 会话表）；证书从配置文件引用的 PEM 读取。

**Testing**: `cargo test`——`common` 单元测试（新帧的 roundtrip 与边界）、`server/tests` e2e
（新增 vhost 路由与 HTTPS 终止用例）。验收另需按宪法原则 II 跑本机 rfpc ↔ 上游 rfps 的真实链路。

**Target Platform**: Linux 服务器（服务端）+ Linux（客户端）；其余平台不做特别适配。

**Project Type**: 单 Cargo workspace，三个 crate（`common` 协议 / `client` rfpc / `server` rfps）。

**Performance Goals**: 域名路由场景下访客侧 P95 附加延迟 < 50ms（SC-004）；HTTP 转发全程流式，
服务端内存不随载荷大小增长（SC-007）。

**Constraints**: 服务端进程常驻内存目标与 frp 同量级或更低；不引入反向代理通用框架（axum 等）
以保持依赖面与内存可控。

**Scale/Scope**: 单机 500 个已注册代理 / 2000 条并发转发（SC-006）；本计划覆盖 spec 的
US1–US5 共 36 条 FR。

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| 原则 | 门禁检查 | 结论 |
|---|---|---|
| I. 提交纪律 | 本计划与后续每个实现阶段独立提交并推送 `origin/main` | PASS（已写入实施分期的完成定义） |
| II. 验证拓扑 | 验收必须走本机 rfpc（客户端）↔ 上游 rfps（服务端）真实公网链路；本机自环只作回归。**vhost 场景额外需要域名解析与上游端口放行** | PASS（quickstart.md 按此编写，且把"上游需新增 vhost 端口放行"列为环境前置） |
| III. 默认加密 | vhost HTTPS 终止复用 rustls；隧道保持 TLS 1.3。明文 vhost HTTP 监听是**显式配置的独立端口**，符合"明文必须显式声明"，不作为默认入口 | PASS |
| IV. 传输无关帧协议 | HTTP 元数据以 `Message` 扩展承载，不引入承载相关结构；M1 走控制通道、M2 走数据流首帧，两侧语义一致 | PASS（见 research.md D2） |
| V. 决策不可静默回退 | 不改 `conn_id` 分配方式；不引入连接池/多路复用层；QUIC 拒绝路径沿用显式 shutdown；不碰 M3 的端到端 H3 方向 | PASS |
| 附加约束 | 新增依赖进 `workspace.dependencies`；配置沿用 TOML 与 frp v0.52+ 风格；错误处理沿用 thiserror/anyhow 分工；注释中文 | PASS |
| 规格流程 | 本能力已在 `specs/001-frp-parity/spec.md` 登记为 US1/FR-001~011 | PASS |

**Phase 1 后复核**：设计产物（data-model.md / contracts/）未引入新的依赖或承载耦合，上表结论不变。

## Project Structure

### Documentation (this feature)

```text
specs/001-frp-parity/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
common/src/
├── msg.rs               # Message 枚举：新增 http 元数据与响应元数据帧
├── frame.rs             # 长度前缀帧读写（复用，无改动）
└── lib.rs

server/src/
├── lib.rs               # 启动流程：按配置拉起 vhost 网关
├── config.rs            # 新增 [http] / [https] / [[certs]] / subdomain_host
├── state.rs             # 路由表（域名 → 代理）、证书表
├── session.rs           # register_proxy 接受 http/https 类型；M1 路径下发 http 元数据
├── vhost/
│   ├── mod.rs           # 网关入口：h1/h2c 监听、h2/TLS 监听
│   ├── router.rs        # Host/:authority 归一化、精确优先 + 通配匹配、404
│   ├── proxy.rs         # 请求 → 隧道帧 → 流式双向管道
│   └── certs.rs         # rustls ResolvesServerCert：按 SNI 选证书
├── quic.rs              # M2 路径：open_bi 后写 http 元数据首帧
└── tls.rs

client/src/
├── config.rs            # 新增 custom_domains / subdomain / 本地服务 TLS 开关
├── lib.rs               # 收到 http 元数据 → 打本地服务 → 回响应元数据 + 裸 body
└── forward.rs           # 本地转发：h1 请求构造、流式双向管道

server/tests/e2e.rs      # 新增 vhost 路由、HTTPS 终止、404、域名冲突用例
```

**Structure Decision**: 服务端新增 `vhost/` 子模块承载网关（路由、转发、证书三者独立可测），
不新建 crate——网关与 session/state 共享路由表与身份授权，跨 crate 会引入不必要的边界。
客户端不改模块划分，转发逻辑在既有 `lib.rs` 内新增函数，保持 client crate 的平面结构。

## 实施分期与依赖

按 spec 的优先级排序。每期独立可交付、独立可验收，且每期收尾独立提交（宪法原则 I）。

| 期 | 覆盖 | 依赖 | 完成定义 |
|---|---|---|---|
| **S1** | US1 / FR-001~011：域名路由型 HTTP/HTTPS 代理 | 无 | 本机 rfpc ↔ 上游 rfps 上，`http` 与 `https` 两类代理均可被域名访问；404 与冲突路径可验；e2e 全绿 |
| **S2** | US2 / FR-012~016：UDP 代理 | S1 的元数据首帧模式 | UDP 回声在跨公网链路上双向通；空闲回收可观测 |
| **S3** | US3 / FR-017~025：压缩、限速、PROXY 协议、健康检查、负载均衡、自动端口、冲突策略、路径路由 | S1 | 逐项独立验收，互不回归 |
| **S4** | US4 / FR-026~029：stcp / sudp / xtcp | S2（UDP 数据面） | 密钥校验与打洞回退路径可验 |
| **S5** | US5 / FR-030~035：管理接口、Dashboard、指标、热重载、includes、插件 | S1（管理接口需展示域名映射） | 管理接口默认仅本机且需凭证；热重载不影响在途连接 |

FR-036（协议不回退）是贯穿全部期的约束，不是独立一期。

**M3（HTTP/3 网关）不在本计划内**——它以 S1 的 `vhost::router` 为直接前置，另立规格。

## 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 上游 UDP 端口未放行（遗留阻塞） | 不影响 S1（TCP/HTTPS）；影响 S2 的跨公网 UDP 验收 | S2 开工前先解除；S1 不受阻 |
| 上游需新增 vhost 端口放行与域名解析 | S1 的验收环境依赖 | 列入 quickstart 环境前置；本地先用 `curl -H 'Host:'` / `--resolve` 验证，再走上游真域名 |
| 引入 hyper 后二进制体积与常驻内存上升 | 与"低内存"定位冲突 | 只引 `hyper` + `hyper-util` + `http-body-util`，不引 axum/tower 栈；实现后按 SC-007 实测内存 |
| 请求/响应头逐跳字段处理不当 | 协议正确性缺陷 | 在 contracts 中明确 hop-by-hop 头清单与处置，e2e 覆盖 |
| 大 header 撑爆 64 KiB 帧上限 | 转发失败 | contracts 定义上限与超限行为（回 4xx，不断开控制通道） |

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

无违反项。本计划未引入新的 crate、未新增承载耦合、未推翻既有决策，因此不填此表。
