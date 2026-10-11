//! vhost 网关（S1）：按域名路由的 HTTP/HTTPS 边缘终止。
//!
//! 模块划分见 `specs/001-frp-parity/plan.md`：
//! - `router`：域名归一化与路由查询（精确优先 + 通配一层左标签）
//! - `certs`：rustls 的 `ResolvesServerCert` 实现，按 SNI 选证书
//! - `proxy`：请求 → 隧道帧 → 流式双向管道
//!
//! 协议契约见 `specs/001-frp-parity/contracts/rfp1-http-vhost.md`。
