//! frpc：控制通道维护 + 数据连接桥接。

pub mod config;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use rfp_common::frame::{control_framed, recv_msg, send_msg, write_frame};
use rfp_common::msg::{version_compatible, Message, VERSION};
use rfp_common::now_ms;
use tokio::net::TcpStream;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, info, warn};

use config::ClientConfig;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// run_once 的错误分类：Fatal 放弃重试，Retry 退避后重连
#[derive(Debug)]
pub enum RunError {
    Fatal(anyhow::Error),
    Retry(anyhow::Error),
}

fn retry(e: impl Into<anyhow::Error>) -> RunError {
    RunError::Retry(e.into())
}

/// 主循环：断线自动重连
pub async fn run(cfg: ClientConfig) -> anyhow::Result<()> {
    loop {
        match run_once(cfg.clone()).await {
            Err(RunError::Fatal(e)) => return Err(e),
            Err(RunError::Retry(e)) => {
                warn!(error = %e, "control connection lost, retrying in 5s");
                tokio::time::sleep(RECONNECT_INTERVAL).await;
            }
            Ok(()) => return Ok(()),
        }
    }
}

/// 单次会话：连接 → 认证 → 注册代理 → 转发循环。控制连接断开即返回。
pub async fn run_once(cfg: ClientConfig) -> Result<(), RunError> {
    let stream = TcpStream::connect((cfg.server_addr.as_str(), cfg.server_port))
        .await
        .map_err(retry)?;
    let _ = stream.set_nodelay(true);
    let mut framed = control_framed(stream);

    // 认证
    send_msg(
        &mut framed,
        &Message::Hello {
            version: VERSION.into(),
            token: cfg.token.clone(),
            hostname: None,
        },
    )
    .await
    .map_err(retry)?;
    let ack = timeout(HANDSHAKE_TIMEOUT, recv_msg(&mut framed))
        .await
        .map_err(|_| retry(anyhow!("handshake timeout")))?
        .map_err(retry)?;
    let session_id = match ack {
        Some(Message::HelloAck { version, session_id }) => {
            if !version_compatible(&version) {
                return Err(RunError::Fatal(anyhow!(
                    "server protocol version {version}, client {VERSION}: incompatible"
                )));
            }
            session_id
        }
        Some(Message::Error { code, message }) => {
            return Err(RunError::Fatal(anyhow!(
                "server rejected handshake: {code}: {message}"
            )));
        }
        other => return Err(retry(anyhow!("unexpected handshake reply: {other:?}"))),
    };
    info!(session = %session_id, "connected");

    // 注册代理
    for p in &cfg.proxies {
        send_msg(
            &mut framed,
            &Message::RegisterProxy {
                name: p.name.clone(),
                proxy_type: p.proxy_type,
                local_addr: p.local_addr.clone(),
                remote_port: Some(p.remote_port),
                vhost: None,
            },
        )
        .await
        .map_err(retry)?;
        let resp = timeout(HANDSHAKE_TIMEOUT, recv_msg(&mut framed))
            .await
            .map_err(|_| retry(anyhow!("register ack timeout")))?
            .map_err(retry)?;
        match resp {
            Some(Message::RegisterProxyAck { name, ok: true, .. }) => {
                info!(proxy = %name, remote_port = p.remote_port, local_addr = %p.local_addr, "proxy registered");
            }
            Some(Message::RegisterProxyAck { name, ok: false, error }) => {
                // 按可重试处理：断开重连（可能是上一会话尚未清理的瞬时冲突）
                return Err(retry(anyhow!(
                    "proxy `{name}` register failed: {}",
                    error.unwrap_or_default()
                )));
            }
            other => return Err(retry(anyhow!("unexpected register reply: {other:?}"))),
        }
    }

    // 转发循环
    let proxies: Arc<HashMap<String, String>> = Arc::new(
        cfg.proxies
            .iter()
            .map(|p| (p.name.clone(), p.local_addr.clone()))
            .collect(),
    );
    let mut ping = interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ping.tick() => {
                send_msg(&mut framed, &Message::Ping { ts: now_ms() })
                    .await
                    .map_err(retry)?;
            }
            msg = recv_msg(&mut framed) => {
                match msg.map_err(retry)? {
                    None => return Err(retry(anyhow!("control connection closed"))),
                    Some(Message::NewConnection { conn_id, proxy_name }) => {
                        debug!(conn_id, proxy = %proxy_name, "new connection");
                        tokio::spawn(handle_new_conn(
                            cfg.server_addr.clone(),
                            cfg.server_port,
                            Arc::clone(&proxies),
                            conn_id,
                            proxy_name,
                        ));
                    }
                    Some(Message::Ping { ts }) => {
                        send_msg(&mut framed, &Message::Pong { ts })
                            .await
                            .map_err(retry)?;
                    }
                    Some(Message::Pong { ts }) => debug!(rtt_ms = now_ms() - ts, "pong"),
                    Some(Message::Error { code, message }) => {
                        warn!(code, message, "server error")
                    }
                    Some(other) => warn!(?other, "unexpected message"),
                }
            }
        }
    }
}

/// 收到 new_connection：回连 server 建隧道（ConnInit 首帧标识），再拨本地服务并桥接。
/// server 侧对 conn_init 有 5s 匹配窗口，先建隧道可让本地拨号失败时快速传导为用户连接关闭。
async fn handle_new_conn(
    server_addr: String,
    server_port: u16,
    proxies: Arc<HashMap<String, String>>,
    conn_id: u64,
    proxy_name: String,
) {
    let Some(local_addr) = proxies.get(&proxy_name) else {
        warn!(conn_id, proxy = %proxy_name, "no such proxy");
        return;
    };
    let mut tunnel = match TcpStream::connect((server_addr.as_str(), server_port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(conn_id, error = %e, "tunnel dial failed");
            return;
        }
    };
    let _ = tunnel.set_nodelay(true);
    let init = Message::ConnInit { conn_id, proxy_name };
    if let Err(e) = write_frame(&mut tunnel, &init.encode()).await {
        warn!(conn_id, error = %e, "send conn_init failed");
        return;
    }
    let mut local = match TcpStream::connect(local_addr.as_str()).await {
        Ok(s) => s,
        Err(e) => {
            // 隧道随即关闭，server 侧用户连接跟着关闭
            warn!(conn_id, local_addr, error = %e, "local dial failed");
            return;
        }
    };
    let _ = local.set_nodelay(true);
    match tokio::io::copy_bidirectional(&mut tunnel, &mut local).await {
        Ok((up, down)) => debug!(conn_id, up, down, "connection closed"),
        Err(e) => debug!(conn_id, error = %e, "connection error"),
    }
}
