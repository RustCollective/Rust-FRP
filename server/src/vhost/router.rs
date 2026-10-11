//! 域名路由：归一化域名 → 代理。
//!
//! 匹配顺序固定为**精确优先、其次通配**；通配只匹配恰好一层左标签
//! （契约 `specs/001-frp-parity/contracts/rfp1-http-vhost.md` §5）。
//!
//! **注册侧与查询侧都必须调用 `state::normalize_host`**——两侧不一致会产生
//! 「注册成功但访问 404」的隐性缺陷。

use std::sync::Arc;

use rfp_common::msg::ProxyType;

use crate::state::{normalize_host, Registry, SessionHandle, VhostEntry, VhostKey};

/// 由注册声明生成路由表键。
///
/// `*.example.com` → 通配键 `example.com`；其余为精确键。
/// 归一化后为空（或 `*.` 后为空）返回 `None`，由调用方报错。
pub fn vhost_key(domain: &str) -> Option<VhostKey> {
    let d = normalize_host(domain);
    // `"*."` 经归一化（剥末尾点）会退化成 `"*"`，必须与空域名一样拒绝
    if d.is_empty() || d == "*" {
        return None;
    }
    match d.strip_prefix("*.") {
        Some(suffix) => (!suffix.is_empty()).then(|| VhostKey {
            key: suffix.to_string(),
            wildcard: true,
        }),
        None => Some(VhostKey { key: d, wildcard: false }),
    }
}

/// 通配匹配：`host` 必须由「非空且不含点的标签」+ `.` + `suffix` 组成。
///
/// 例如 suffix = `alice.dev` 时：`x.alice.dev` ✓、`alice.dev` ✗、
/// `a.b.alice.dev` ✗、`evil-alice.dev` ✗。
pub fn wildcard_match(host: &str, suffix: &str) -> bool {
    match host.split_once('.') {
        Some((label, rest)) => !label.is_empty() && rest == suffix,
        None => false,
    }
}

/// 路由命中结果：足以定位代理并驱动一条隧道
pub struct RouteHit {
    pub session: Arc<SessionHandle>,
    pub proxy_name: String,
}

fn hit(e: &VhostEntry) -> RouteHit {
    RouteHit {
        session: Arc::clone(&e.session),
        proxy_name: e.proxy_name.clone(),
    }
}

/// 按请求的 host 查路由。
///
/// `kind` 是当前监听端口的类型：`Http` 对应明文监听、`Https` 对应 TLS 监听。
/// 域名命中但类型不符时返回 `None`（契约 §5：不回落其他代理）。
pub fn lookup(registry: &Registry, host: &str, kind: ProxyType) -> Option<RouteHit> {
    let host = normalize_host(host);
    if host.is_empty() {
        return None;
    }
    if let Some(e) = registry.by_vhost_exact.get(&host) {
        // 同名域名已存在但不是本端口的类型：不回落，直接未命中
        return (e.kind == kind).then(|| hit(e));
    }
    // 通配：后缀必然等于「第一个点之后的部分」，因此只需一次查表
    let (_, suffix) = host.split_once('.')?;
    let e = registry.by_vhost_wildcard.get(suffix)?;
    (e.kind == kind && wildcard_match(&host, suffix)).then(|| hit(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AuthIdentity, DataTransport, RegisteredProxy, SessionHandle};
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    fn session(id: &str) -> Arc<SessionHandle> {
        let (tx, _rx) = mpsc::unbounded_channel();
        Arc::new(SessionHandle {
            id: id.into(),
            identity: AuthIdentity::Legacy,
            cmd_tx: tx,
            data: DataTransport::Tcp,
            registered: Mutex::new(Vec::<RegisteredProxy>::new()),
        })
    }

    /// 建一张包含精确与通配的路由表
    fn registry() -> Registry {
        let mut r = Registry::default();
        r.by_vhost_exact.insert(
            "app.example.com".into(),
            VhostEntry {
                session: session("s1"),
                proxy_name: "web".into(),
                kind: ProxyType::Http,
            },
        );
        r.by_vhost_exact.insert(
            "tls.example.com".into(),
            VhostEntry {
                session: session("s1"),
                proxy_name: "web-tls".into(),
                kind: ProxyType::Https,
            },
        );
        r.by_vhost_wildcard.insert(
            "alice.dev".into(),
            VhostEntry {
                session: session("s2"),
                proxy_name: "wild".into(),
                kind: ProxyType::Http,
            },
        );
        r
    }

    #[test]
    fn exact_match_and_normalization() {
        let r = registry();
        for host in [
            "app.example.com",
            "APP.Example.com",
            "app.example.com:8080",
            "app.example.com.",
        ] {
            let hit = lookup(&r, host, ProxyType::Http).unwrap_or_else(|| panic!("miss: {host}"));
            assert_eq!(hit.proxy_name, "web", "host={host}");
        }
    }

    #[test]
    fn kind_must_match_listener() {
        let r = registry();
        // https 代理在明文监听上被访问 → 未命中（不回落）
        assert!(lookup(&r, "tls.example.com", ProxyType::Http).is_none());
        // 反向同理
        assert!(lookup(&r, "app.example.com", ProxyType::Https).is_none());
        assert!(lookup(&r, "tls.example.com", ProxyType::Https).is_some());
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        let r = registry();
        assert_eq!(lookup(&r, "x.alice.dev", ProxyType::Http).unwrap().proxy_name, "wild");
        // 裸域不算
        assert!(lookup(&r, "alice.dev", ProxyType::Http).is_none());
        // 两层左标签不算
        assert!(lookup(&r, "a.b.alice.dev", ProxyType::Http).is_none());
        // 前缀撞车不算
        assert!(lookup(&r, "evil-alice.dev", ProxyType::Http).is_none());
        assert!(lookup(&r, "x.alice.dev.cn", ProxyType::Http).is_none());
    }

    #[test]
    fn exact_wins_over_wildcard() {
        let mut r = registry();
        // 给一个与通配可匹配的同名精确域名
        r.by_vhost_exact.insert(
            "x.alice.dev".into(),
            VhostEntry {
                session: session("s3"),
                proxy_name: "exact".into(),
                kind: ProxyType::Http,
            },
        );
        assert_eq!(lookup(&r, "x.alice.dev", ProxyType::Http).unwrap().proxy_name, "exact");
        // 其他子域仍走通配
        assert_eq!(lookup(&r, "y.alice.dev", ProxyType::Http).unwrap().proxy_name, "wild");
    }

    #[test]
    fn unknown_and_empty_hosts_miss() {
        let r = registry();
        assert!(lookup(&r, "nope.example.com", ProxyType::Http).is_none());
        assert!(lookup(&r, "", ProxyType::Http).is_none());
        assert!(lookup(&r, "   ", ProxyType::Http).is_none());
        assert!(lookup(&r, "com", ProxyType::Http).is_none());
    }

    #[test]
    fn vhost_key_shapes() {
        let k = vhost_key("*.alice.dev").unwrap();
        assert!(k.wildcard);
        assert_eq!(k.key, "alice.dev");

        let k = vhost_key("App.Example.COM.").unwrap();
        assert!(!k.wildcard);
        assert_eq!(k.key, "app.example.com");

        assert!(vhost_key("").is_none());
        assert!(vhost_key("*.").is_none());
    }

    #[test]
    fn wildcard_match_helper() {
        assert!(wildcard_match("x.alice.dev", "alice.dev"));
        assert!(!wildcard_match("alice.dev", "alice.dev"));
        assert!(!wildcard_match("a.b.alice.dev", "alice.dev"));
        assert!(!wildcard_match("evil-alice.dev", "alice.dev"));
        assert!(!wildcard_match(".alice.dev", "alice.dev"));
        // 后缀 `dev` 配 `*.dev` 时，`alice.dev` 确实是恰好一层左标签
        assert!(wildcard_match("alice.dev", "dev"));
    }
}
