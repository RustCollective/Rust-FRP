//! 服务端全局状态与代理注册表。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rfp_common::msg::Message;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// 已注册代理表：名称/端口 → 会话
#[derive(Default)]
pub struct Registry {
    pub by_name: HashMap<String, Arc<SessionHandle>>,
    pub by_port: HashMap<u16, Arc<SessionHandle>>,
}

pub struct ServerState {
    /// 空 = 不认证
    pub token: String,
    /// 代理端口监听地址
    pub bind_addr: String,
    next_conn_id: AtomicU64,
    /// 注册临界区含 bind（await），用 tokio Mutex
    pub registry: tokio::sync::Mutex<Registry>,
    /// conn_id → 等待隧道连接的用户连接
    pub pending: Mutex<HashMap<u64, oneshot::Sender<TcpStream>>>,
}

impl ServerState {
    pub fn new(token: String, bind_addr: String) -> Self {
        Self {
            token,
            bind_addr,
            next_conn_id: AtomicU64::new(1),
            registry: tokio::sync::Mutex::new(Registry::default()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }
}

/// 一个已认证控制连接（会话）的句柄
pub struct SessionHandle {
    pub id: String,
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
