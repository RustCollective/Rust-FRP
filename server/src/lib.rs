//! rfps：接入分发（控制/数据连接同端口，首帧识别）。

pub mod config;
mod session;
mod state;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rfp_common::frame::{read_frame, write_frame};
use rfp_common::msg::Message;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

pub use config::ServerConfig;
use state::{AuthPolicy, ServerState};

/// 首帧（hello / conn_init）等待上限
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// 绑定并进入服务循环
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind((cfg.bind_addr.as_str(), cfg.bind_port)).await?;
    info!(addr = %listener.local_addr()?, "rfps listening");
    serve(listener, cfg).await
}

/// 在已有 listener 上服务（测试入口）
pub async fn serve(listener: TcpListener, cfg: ServerConfig) -> Result<()> {
    let policy = cfg
        .auth_policy()
        .map_err(|e| anyhow::anyhow!("认证配置无效: {e}"))?;
    match &policy {
        AuthPolicy::Open => warn!("未配置 token 与用户表，认证已关闭"),
        AuthPolicy::Legacy(_) => warn!("使用全局 token（legacy 模式），建议迁移到 [[users]] 授权"),
        AuthPolicy::Users(users) => info!(count = users.len(), "用户认证模式"),
    }
    let state = Arc::new(ServerState::new(policy, cfg.bind_addr.clone()));
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept error");
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let peer = peer.to_string();
            // 首帧识别：Hello → 控制会话；ConnInit → 数据连接
            let first =
                match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame(&mut stream)).await {
                    Ok(Ok(buf)) => buf,
                    Ok(Err(e)) => {
                        debug!(peer, error = %e, "first frame error");
                        return;
                    }
                    Err(_) => {
                        debug!(peer, "first frame timeout");
                        return;
                    }
                };
            match Message::parse(&first) {
                Ok(Message::Hello {
                    version,
                    token,
                    hostname,
                }) => {
                    session::handle_control(state, stream, version, token, hostname).await;
                }
                Ok(Message::ConnInit { conn_id, .. }) => {
                    handle_data_conn(&state, stream, conn_id).await;
                }
                Ok(other) => {
                    debug!(peer, ?other, "unexpected first frame");
                    let err = Message::Error {
                        code: "unexpected_message".into(),
                        message: "first frame must be hello or conn_init".into(),
                    };
                    let _ = write_frame(&mut stream, &err.encode()).await;
                }
                Err(e) => {
                    debug!(peer, error = %e, "first frame parse error");
                    let err = Message::Error {
                        code: "parse".into(),
                        message: e.to_string(),
                    };
                    let _ = write_frame(&mut stream, &err.encode()).await;
                }
            }
        });
    }
}

/// 数据连接：按 ConnInit.conn_id 匹配等待中的用户连接并移交，桥接在 relay 侧完成。
async fn handle_data_conn(state: &ServerState, stream: TcpStream, conn_id: u64) {
    let tx = state.pending.lock().unwrap().remove(&conn_id);
    match tx {
        Some(tx) => {
            let _ = tx.send(stream);
        }
        None => {
            debug!(conn_id, "data conn for unknown or timed-out conn_id");
        }
    }
}
