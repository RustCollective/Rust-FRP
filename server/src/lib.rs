//! rfps：接入分发（控制/数据连接同端口，首帧识别）。

pub mod config;
mod quic;
mod session;
mod state;
pub mod tls;
pub mod vhost;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rfp_common::frame::{read_frame, write_frame};
use rfp_common::msg::Message;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub use config::ServerConfig;
use state::{AuthPolicy, DataTransport, ServerState, VhostSettings};

/// 首帧（hello / conn_init）等待上限
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// 绑定并进入服务循环
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind((cfg.bind_addr.as_str(), cfg.bind_port)).await?;
    info!(addr = %listener.local_addr()?, "rfps listening");
    serve(listener, cfg).await
}

/// 在已有 listener 上服务（测试入口）。QUIC 启用时同端口（UDP）并行监听。
pub async fn serve(listener: TcpListener, cfg: ServerConfig) -> Result<()> {
    let policy = cfg
        .auth_policy()
        .map_err(|e| anyhow::anyhow!("认证配置无效: {e}"))?;
    match &policy {
        AuthPolicy::Open => warn!("未配置 token 与用户表，认证已关闭"),
        AuthPolicy::Legacy(_) => warn!("使用全局 token（legacy 模式），建议迁移到 [[users]] 授权"),
        AuthPolicy::Users(users) => info!(count = users.len(), "用户认证模式"),
    }
    // S1：vhost 网关配置的结构性校验（证书配对在 CertTable::load 里拦）
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("vhost 配置无效: {e}"))?;
    let vhost_settings = VhostSettings {
        http: cfg.http.is_some(),
        https: cfg.https.is_some(),
        subdomain_host: cfg.subdomain_host.clone(),
    };
    let state = Arc::new(
        ServerState::new(policy, cfg.bind_addr.clone()).with_vhost(vhost_settings),
    );

    // S1：vhost 明文 HTTP 监听（h1 + h2c）
    if let Some(h) = &cfg.http {
        let addr = h.addr(&cfg.bind_addr);
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = vhost::proxy::run_http(s, addr).await {
                error!(error = %e, "vhost http 监听启动失败");
            }
        });
    }
    // S1：vhost TLS 监听（按 SNI 选证书；未命中的 SNI 拒绝握手）
    if let Some(h) = &cfg.https {
        let table = vhost::certs::CertTable::load(&cfg.certs)
            .map_err(|e| anyhow::anyhow!("证书表加载失败: {e}"))?;
        info!(count = table.len(), "vhost 证书表就绪");
        let table = Arc::new(table);
        let addr = h.addr(&cfg.bind_addr);
        let s = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = vhost::proxy::run_https(s, addr, table).await {
                error!(error = %e, "vhost https 监听启动失败");
            }
        });
    }
    let tls_setup = if cfg.tls.enabled {
        Some(tls::setup(cfg.tls.cert.as_deref(), cfg.tls.key.as_deref())?)
    } else {
        warn!("TLS 已显式关闭（明文模式），仅建议调试使用");
        None
    };
    // QUIC 传输（TLS 内生，不依赖 tls.enabled；证书配置仍复用 [tls]）
    if cfg.quic.enabled {
        let tls_for_quic = match &tls_setup {
            Some(t) => t.clone(),
            None => tls::setup(cfg.tls.cert.as_deref(), cfg.tls.key.as_deref())?,
        };
        let endpoint = quic::endpoint(&cfg, &tls_for_quic)?;
        let quic_state = Arc::clone(&state);
        tokio::spawn(quic::serve_quic(quic_state, endpoint));
    }
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept error");
                continue;
            }
        };
        let state = Arc::clone(&state);
        let tls_setup = tls_setup.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let peer = peer.to_string();
            // TLS 握手（启用时）；此后为明文/统一抽象流
            let mut stream: state::BoxedStream = match &tls_setup {
                Some(t) => match t.acceptor.accept(stream).await {
                    Ok(s) => Box::new(s),
                    Err(e) => {
                        debug!(peer, error = %e, "tls handshake failed");
                        return;
                    }
                },
                None => Box::new(stream),
            };
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
                    session::handle_control(
                        state,
                        stream,
                        peer,
                        version,
                        token,
                        hostname,
                        DataTransport::Tcp,
                    )
                    .await;
                }
                Ok(Message::ConnInit { conn_id, .. }) => {
                    handle_data_conn(&state, stream, conn_id);
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
fn handle_data_conn(state: &ServerState, stream: state::BoxedStream, conn_id: u64) {
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
