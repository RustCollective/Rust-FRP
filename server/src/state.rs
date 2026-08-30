//! 服务端全局状态、认证与授权策略、代理注册表。

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rfp_common::msg::Message;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Linux 默认临时端口范围：注册这个区间的代理端口会被出站连接随机抢占
pub const EPHEMERAL_RANGE: RangeInclusive<u16> = 32768..=60999;

/// 单个用户的授权配置（token 即身份）
pub struct UserAuth {
    pub name: String,
    pub token: String,
    /// 端口授权区间列表
    pub ports: Vec<(u16, u16)>,
    /// vhost 授权（精确匹配或 `*.domain` 通配）
    pub vhosts: Vec<String>,
}

impl UserAuth {
    pub fn allows_port(&self, port: u16) -> bool {
        self.ports.iter().any(|&(lo, hi)| port >= lo && port <= hi)
    }

    pub fn allows_vhost(&self, vhost: &str) -> bool {
        self.vhosts.iter().any(|p| match p.strip_prefix("*.") {
            // 通配匹配恰好一个左标签：x.alice.dev ✓ / alice.dev ✗ / a.b.alice.dev ✗ / evil-alice.dev ✗
            Some(base) => vhost.strip_suffix(base).is_some_and(|prefix| {
                prefix
                    .strip_suffix('.')
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'))
            }),
            None => p == vhost,
        })
    }
}

/// 认证后的身份
#[derive(Clone)]
pub enum AuthIdentity {
    /// 全局 token（或未配置认证）：端口不受限（拒绝临时端口区间）
    Legacy,
    /// 具名用户：端口/vhost 需在授权范围内
    User(Arc<UserAuth>),
}

impl AuthIdentity {
    pub fn label(&self) -> &str {
        match self {
            Self::Legacy => "legacy",
            Self::User(u) => &u.name,
        }
    }
}

/// 认证策略：配置了 [[users]] 走用户表，否则回退全局 token
pub enum AuthPolicy {
    /// 未配置 token 且无用户表：不认证
    Open,
    /// 全局 token（向后兼容）
    Legacy(String),
    /// 每用户独立 token
    Users(Vec<Arc<UserAuth>>),
}

/// 已注册代理表：名称/端口 → 会话
#[derive(Default)]
pub struct Registry {
    pub by_name: HashMap<String, Arc<SessionHandle>>,
    pub by_port: HashMap<u16, Arc<SessionHandle>>,
}

pub struct ServerState {
    pub policy: AuthPolicy,
    /// 代理端口监听地址
    pub bind_addr: String,
    next_conn_id: AtomicU64,
    /// 注册临界区含 bind（await），用 tokio Mutex
    pub registry: tokio::sync::Mutex<Registry>,
    /// conn_id → 等待隧道连接的用户连接
    pub pending: Mutex<HashMap<u64, oneshot::Sender<TcpStream>>>,
}

impl ServerState {
    pub fn new(policy: AuthPolicy, bind_addr: String) -> Self {
        Self {
            policy,
            bind_addr,
            next_conn_id: AtomicU64::new(1),
            registry: tokio::sync::Mutex::new(Registry::default()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// 认证：token → 身份。用户表模式下 token 不匹配任何用户即失败。
    pub fn authenticate(&self, token: &str) -> Option<AuthIdentity> {
        match &self.policy {
            AuthPolicy::Open => Some(AuthIdentity::Legacy),
            AuthPolicy::Legacy(global) => {
                ct_eq(global, token).then_some(AuthIdentity::Legacy)
            }
            AuthPolicy::Users(users) => users
                .iter()
                .find(|u| ct_eq(&u.token, token))
                .map(|u| AuthIdentity::User(Arc::clone(u))),
        }
    }
}

/// 端口授权检查
pub fn authorize_port(identity: &AuthIdentity, port: u16) -> Result<(), String> {
    match identity {
        AuthIdentity::Legacy => {
            if EPHEMERAL_RANGE.contains(&port) {
                Err(format!(
                    "端口 {port} 位于系统临时端口范围 32768-60999，会被出站连接随机抢占，拒绝注册"
                ))
            } else {
                Ok(())
            }
        }
        AuthIdentity::User(u) => {
            if u.allows_port(port) {
                Ok(())
            } else {
                Err(format!("端口 {port} 不在用户「{}」的授权范围内", u.name))
            }
        }
    }
}

/// vhost 授权检查（register_proxy 携带 vhost 时）
pub fn authorize_vhost(identity: &AuthIdentity, vhost: &str) -> Result<(), String> {
    match identity {
        AuthIdentity::Legacy => Ok(()),
        AuthIdentity::User(u) => {
            if u.allows_vhost(vhost) {
                Ok(())
            } else {
                Err(format!("vhost `{vhost}` 不在用户「{}」的授权范围内", u.name))
            }
        }
    }
}

/// 常量时间比较（长度不同直接失败）
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 一个已认证控制连接（会话）的句柄
pub struct SessionHandle {
    pub id: String,
    /// 认证身份（日志与授权检查用）
    pub identity: AuthIdentity,
    /// 控制通道写侧（session 循环消费）
    pub cmd_tx: mpsc::UnboundedSender<Message>,
    /// 本会话注册的代理（会话结束时清理）
    pub registered: Mutex<Vec<RegisteredProxy>>,
}

pub struct RegisteredProxy {
    pub name: String,
    pub port: u16,
    pub listener: JoinHandle<()>,
}

/// 会话结束：注销代理、停监听。只清理仍归属本会话的表项，避免误删新会话的注册。
pub async fn cleanup_session(state: &ServerState, session: &SessionHandle) {
    let mut registry = state.registry.lock().await;
    let mut registered = session.registered.lock().unwrap();
    for p in registered.drain(..) {
        let mine = |s: &Arc<SessionHandle>| s.id == session.id;
        if registry.by_name.get(&p.name).is_some_and(mine) {
            registry.by_name.remove(&p.name);
        }
        if registry.by_port.get(&p.port).is_some_and(mine) {
            registry.by_port.remove(&p.port);
        }
        p.listener.abort();
        tracing::info!(proxy = %p.name, port = p.port, "proxy unregistered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(ports: Vec<(u16, u16)>, vhosts: Vec<&str>) -> UserAuth {
        UserAuth {
            name: "alice".into(),
            token: "t".into(),
            ports,
            vhosts: vhosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn port_range_check() {
        let u = user(vec![(6000, 6100), (6200, 6200)], vec![]);
        assert!(u.allows_port(6000));
        assert!(u.allows_port(6100));
        assert!(u.allows_port(6200));
        assert!(!u.allows_port(5999));
        assert!(!u.allows_port(6101));
        assert!(!u.allows_port(6201));
    }

    #[test]
    fn vhost_patterns() {
        let u = user(vec![], vec!["a.example.com", "*.alice.dev", "bob.dev"]);
        assert!(u.allows_vhost("a.example.com"));
        assert!(u.allows_vhost("x.alice.dev"));
        assert!(!u.allows_vhost("alice.dev")); // 通配只匹配子域，不匹配裸域
        assert!(!u.allows_vhost("b.example.com"));
        assert!(!u.allows_vhost("x.alice.dev.cn"));
        assert!(!u.allows_vhost("evil-alice.dev")); // 前缀撞车不算
        assert!(!u.allows_vhost("a.b.alice.dev")); // 只匹配一层标签
    }

    #[test]
    fn authorize_rules() {
        // Legacy：拒绝临时端口区间
        assert!(authorize_port(&AuthIdentity::Legacy, 6022).is_ok());
        assert!(authorize_port(&AuthIdentity::Legacy, 32768).is_err());
        assert!(authorize_port(&AuthIdentity::Legacy, 60999).is_err());
        assert!(authorize_port(&AuthIdentity::Legacy, 61000).is_ok());
        // 用户：以授权表为准（显式允许可覆盖临时端口区间）
        let u = Arc::new(user(vec![(40000, 40000)], vec![]));
        let id = AuthIdentity::User(u);
        assert!(authorize_port(&id, 40000).is_ok());
        assert!(authorize_port(&id, 6022).is_err());
    }

    #[test]
    fn authenticate_policies() {
        // Open：任何 token 都过
        let s = ServerState::new(AuthPolicy::Open, "0.0.0.0".into());
        assert!(s.authenticate("anything").is_some());
        // Legacy：token 匹配
        let s = ServerState::new(AuthPolicy::Legacy("secret".into()), "0.0.0.0".into());
        assert!(s.authenticate("secret").is_some());
        assert!(s.authenticate("wrong").is_none());
        // Users：按 token 查用户
        let users = vec![Arc::new(user(vec![(6000, 6000)], vec![]))];
        let s = ServerState::new(AuthPolicy::Users(users), "0.0.0.0".into());
        assert!(matches!(s.authenticate("t"), Some(AuthIdentity::User(_))));
        assert!(s.authenticate("secret").is_none());
    }
}
