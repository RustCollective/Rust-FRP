//! rfps QUIC 接入（M2）：单连接多路复用。
//!
//! - client 打开的第一条 bi-stream = 控制通道（首帧 Hello，帧协议与 TCP 路径一致）
//! - 数据隧道由 server 在同一连接上主动 `open_bi`（首帧 ConnInit），
//!   不再有 M1 的 NewConnection 通知 + client 回连
//! - TLS 内生于 QUIC：复用 `[tls]` 证书配置，ALPN `rfp/1`，支持 0-RTT

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rfp_common::frame::{read_frame, write_frame};
use rfp_common::msg::Message;
use rfp_common::quic::{QuicStream, ALPN};
use tracing::{debug, info};

use crate::config::ServerConfig;
use crate::state::{DataTransport, ServerState};
use crate::tls::TlsSetup;

/// 首帧（Hello）等待上限，与 TCP 路径一致
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// 构建 QUIC endpoint（复用 TCP 路径的证书）
pub fn endpoint(cfg: &ServerConfig, tls: &TlsSetup) -> Result<quinn::Endpoint> {
    let mut rustls_cfg = (*tls.rustls).clone();
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];
    rustls_cfg.max_early_data_size = u32::MAX; // QUIC 要求 0 或 u32::MAX；开启 0-RTT 接收
    let quic_tls = QuicServerConfig::try_from(Arc::new(rustls_cfg))
        .map_err(|e| anyhow!("QUIC TLS 配置失败: {e}"))?;
    let mut qcfg = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    // 隧道场景并发流远多于普通 HTTP，放宽默认 100 条的并发 bi-stream 上限
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256u32.into());
    qcfg.transport_config(Arc::new(transport));

    let addr = format!("{}:{}", cfg.bind_addr, cfg.quic_port());
    let ep = quinn::Endpoint::server(qcfg, addr.parse().context("QUIC 监听地址解析失败")?)
        .with_context(|| format!("QUIC 监听 {addr} 失败"))?;
    info!(addr, "rfps quic listening");
    Ok(ep)
}

/// QUIC 接入循环
pub async fn serve_quic(state: Arc<ServerState>, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            match incoming.accept() {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => handle_conn(state, conn).await,
                    Err(e) => debug!(error = %e, "quic handshake failed"),
                },
                Err(e) => debug!(error = %e, "quic accept failed"),
            }
        });
    }
}

/// 单个 QUIC 连接：第一条 bi-stream 为控制通道，认证后进入通用会话循环
async fn handle_conn(state: Arc<ServerState>, conn: quinn::Connection) {
    let peer = conn.remote_address().to_string();
    let stream = match conn.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            debug!(peer, error = %e, "quic accept_bi failed");
            return;
        }
    };
    let mut stream: QuicStream = stream.into();
    // 首帧必须是 Hello
    let first = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            debug!(peer, error = %e, "quic first frame error");
            return;
        }
        Err(_) => {
            debug!(peer, "quic first frame timeout");
            return;
        }
    };
    match Message::parse(&first) {
        Ok(Message::Hello { version, token, hostname }) => {
            crate::session::handle_control(
                Arc::clone(&state),
                stream,
                peer.clone(),
                version,
                token,
                hostname,
                DataTransport::Quic(conn.clone()),
            )
            .await;
        }
        Ok(other) => {
            debug!(peer, ?other, "quic unexpected first frame");
            let err = Message::Error {
                code: "unexpected_message".into(),
                message: "first frame must be hello".into(),
            };
            let _ = write_frame(&mut stream, &err.encode()).await;
        }
        Err(e) => {
            debug!(peer, error = %e, "quic first frame parse error");
        }
    }
    // 控制会话结束：不主动 close——已建立的数据隧道继续到流结束（与 M1 语义一致），
    // 死连接由空闲超时/对端关闭清理。主动 close 会与最后的控制帧（如认证失败的
    // Error）竞态，导致对端读到 ConnectionClosed 而非协议错误
    debug!(peer, "quic control session ended");
}
