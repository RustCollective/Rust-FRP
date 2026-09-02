//! frpc：控制通道维护 + 数据连接桥接。
//!
//! - TCP（M1）：控制连接 + 按需回连数据连接
//! - QUIC（M2）：单连接多路复用，控制为第一条 bi-stream，
//!   数据隧道由 server 主动开 bi-stream 下发（首帧 ConnInit）；
//!   endpoint 跨重连复用 → 会话恢复 + 0-RTT

pub mod config;
pub mod tls;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use quinn::crypto::rustls::QuicClientConfig;
use rfp_common::frame::{control_framed, read_frame, recv_msg, send_msg, write_frame, Control};
use rfp_common::msg::{version_compatible, Message, VERSION};
use rfp_common::now_ms;
use rfp_common::quic::{QuicStream, ALPN};
use rfp_common::AsyncStream;
use tokio::net::TcpStream;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use config::{ClientConfig, Transport};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// QUIC 传输层保活（配合默认 30s 空闲超时，快速感知断线）
const QUIC_KEEPALIVE: Duration = Duration::from_secs(15);

/// run_once 的错误分类：Fatal 放弃重试，Retry 退避后重连
#[derive(Debug)]
pub enum RunError {
    Fatal(anyhow::Error),
    Retry(anyhow::Error),
}

fn retry(e: impl Into<anyhow::Error>) -> RunError {
    RunError::Retry(e.into())
}

type MaybeTlsStream = rfp_common::BoxedStream;

/// 主循环：断线自动重连
pub async fn run(cfg: ClientConfig) -> anyhow::Result<()> {
    match cfg.transport {
        Transport::Tcp => loop {
            match run_once(cfg.clone()).await {
                Err(RunError::Fatal(e)) => return Err(e),
                Err(RunError::Retry(e)) => {
                    warn!(error = %e, "control connection lost, retrying in 5s");
                    tokio::time::sleep(RECONNECT_INTERVAL).await;
                }
                Ok(()) => return Ok(()),
            }
        },
        Transport::Quic => {
            // QUIC 内生 TLS 1.3，无明文模式
            if !cfg.tls.enabled {
                return Err(anyhow!(
                    "transport = \"quic\" 需要 TLS（QUIC 强制加密），请移除 tls.enabled = false"
                ));
            }
            // endpoint 跨重连复用：rustls 会话票据保存在其配置内，重连走恢复（含 0-RTT）
            let endpoint = quic_endpoint(&cfg)?;
            loop {
                match run_quic_once(&endpoint, cfg.clone()).await {
                    Err(RunError::Fatal(e)) => return Err(e),
                    Err(RunError::Retry(e)) => {
                        warn!(error = %e, "quic connection lost, retrying in 5s");
                        tokio::time::sleep(RECONNECT_INTERVAL).await;
                    }
                    Ok(()) => return Ok(()),
                }
            }
        }
    }
}

/// 构建 QUIC client endpoint（0-RTT + ALPN + keepalive）。
/// endpoint 需跨重连复用（会话票据存在其 rustls 配置内），故独立于 run_quic_once 暴露。
pub fn quic_endpoint(cfg: &ClientConfig) -> anyhow::Result<quinn::Endpoint> {
    let mut rustls_cfg = tls::rustls_client_config(cfg.tls.server_fingerprint.as_deref())?;
    rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];
    rustls_cfg.enable_early_data = true; // 会话恢复时 0-RTT 发送
    let quic_tls = QuicClientConfig::try_from(Arc::new(rustls_cfg))
        .map_err(|e| anyhow!("QUIC TLS 配置失败: {e}"))?;
    let mut qcfg = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(QUIC_KEEPALIVE));
    transport.max_concurrent_bidi_streams(256u32.into());
    qcfg.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(qcfg);
    Ok(endpoint)
}

/// 认证 + 注册代理（TCP/QUIC 共用）
async fn handshake<S: AsyncStream>(
    framed: &mut Control<S>,
    cfg: &ClientConfig,
) -> Result<String, RunError> {
    // 认证
    send_msg(
        framed,
        &Message::Hello {
            version: VERSION.into(),
            token: cfg.token.clone(),
            hostname: None,
        },
    )
    .await
    .map_err(retry)?;
    let ack = timeout(HANDSHAKE_TIMEOUT, recv_msg(framed))
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
            framed,
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
        let resp = timeout(HANDSHAKE_TIMEOUT, recv_msg(framed))
            .await
            .map_err(|_| retry(anyhow!("register ack timeout")))?
            .map_err(retry)?;
        match resp {
            Some(Message::RegisterProxyAck { name, ok: true, .. }) => {
                info!(proxy = %name, remote_port = p.remote_port, local_addr = p.local_addr, "proxy registered");
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
    Ok(session_id)
}

/// TLS connector（启用时构建一次）；明文模式返回 None
fn build_connector(cfg: &ClientConfig) -> Option<TlsConnector> {
    if !cfg.tls.enabled {
        warn!("TLS 已显式关闭（明文模式），仅建议调试使用");
        return None;
    }
    match tls::connector(cfg.tls.server_fingerprint.as_deref()) {
        Ok(c) => Some(c),
        // 配置错误（如 fingerprint 格式非法）是 Fatal，但此处类型限制，转 panic 语义不合适；
        // 由 main 启动时提前校验规避，这里兜底按无 TLS 处理会掩盖问题，直接返回 None 并已在启动时报错
        Err(e) => {
            warn!(error = %e, "TLS connector 构建失败，回退明文（不应发生）");
            None
        }
    }
}

/// 按配置包装 TLS；server_name 用配置的 server_addr（IP 或域名）
async fn tls_connect(
    connector: &Option<TlsConnector>,
    stream: TcpStream,
    cfg: &ClientConfig,
) -> Result<MaybeTlsStream, RunError> {
    match connector {
        Some(c) => {
            let name = rustls_pki_types::ServerName::try_from(cfg.server_addr.clone())
                .map_err(|e| retry(anyhow!("server_addr 不能用作 TLS SNI: {e}")))?;
            let s = c
                .connect(name, stream)
                .await
                .map_err(|e| retry(anyhow!("TLS 握手失败: {e}")))?;
            Ok(Box::new(s))
        }
        None => Ok(Box::new(stream)),
    }
}

/// 单次 TCP 会话：连接 → (TLS) → 认证 → 注册代理 → 转发循环。控制连接断开即返回。
pub async fn run_once(cfg: ClientConfig) -> Result<(), RunError> {
    let connector = build_connector(&cfg);
    let stream = TcpStream::connect((cfg.server_addr.as_str(), cfg.server_port))
        .await
        .map_err(retry)?;
    let _ = stream.set_nodelay(true);
    let stream = tls_connect(&connector, stream, &cfg).await?;
    let mut framed = control_framed(stream);
    handshake(&mut framed, &cfg).await?;

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
                            connector.clone(),
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

/// 单次 QUIC 会话：连接（0-RTT 尝试）→ 控制通道（第一条 bi-stream）→ 转发循环。
/// 数据隧道由 server 主动开 bi-stream 下发，本侧只负责接收桥接。
pub async fn run_quic_once(
    endpoint: &quinn::Endpoint,
    cfg: ClientConfig,
) -> Result<(), RunError> {
    let addr = tokio::net::lookup_host((cfg.server_addr.as_str(), cfg.server_port))
        .await
        .map_err(retry)?
        .next()
        .ok_or_else(|| retry(anyhow!("server_addr 解析无结果")))?;
    let connecting = endpoint
        .connect(addr, &cfg.server_addr)
        .map_err(retry)?;
    // 有会话票据时进入 0-RTT：控制流（含 Hello）作为 early data 发送；
    // 被拒（server 重启/票据过期）时降级为握手后的 1-RTT 流
    let (conn, zero_rtt) = match connecting.into_0rtt() {
        Ok((conn, accepted)) => (conn, Some(accepted)),
        Err(connecting) => (connecting.await.map_err(retry)?, None),
    };
    let early = match &zero_rtt {
        Some(_) => conn.open_bi().await.ok(),
        None => None,
    };
    let zrtt_ok = match zero_rtt {
        Some(f) => f.await,
        None => false,
    };
    let (framed, used_0rtt) = match early {
        Some((send, recv)) if zrtt_ok => (control_framed(QuicStream::new(send, recv)), true),
        _ => {
            // 无票据 / 0-RTT 被拒：early 流丢弃（server 侧本就不处理），开握手后的 1-RTT 流
            let (send, recv) = conn.open_bi().await.map_err(retry)?;
            (control_framed(QuicStream::new(send, recv)), false)
        }
    };
    let mut framed = framed;
    let session_id = handshake(&mut framed, &cfg).await?;
    if used_0rtt {
        info!(session = %session_id, "connected (0-RTT)");
    }

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
                    None => return Err(retry(anyhow!("control stream closed"))),
                    Some(Message::NewConnection { .. }) => {
                        warn!("new_connection is TCP-only; unexpected over quic");
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
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        tokio::spawn(handle_quic_data(
                            QuicStream::new(send, recv),
                            Arc::clone(&proxies),
                        ));
                    }
                    Err(e) => {
                        debug!(error = %e, "quic accept_bi failed");
                        return Err(retry(anyhow!("quic connection lost")));
                    }
                }
            }
        }
    }
}

/// server 下发的数据隧道：首帧 ConnInit 标识代理 → 拨本地服务 → 桥接。
async fn handle_quic_data(mut stream: QuicStream, proxies: Arc<HashMap<String, String>>) {
    let first = match read_frame(&mut stream).await {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "quic data stream first frame error");
            return;
        }
    };
    let Ok(Message::ConnInit { conn_id, proxy_name }) = Message::parse(&first) else {
        warn!("quic data stream: unexpected first frame");
        return;
    };
    debug!(conn_id, proxy = %proxy_name, "quic data stream");
    let Some(local_addr) = proxies.get(&proxy_name) else {
        warn!(conn_id, proxy = %proxy_name, "no such proxy");
        return;
    };
    let mut local = match TcpStream::connect(local_addr.as_str()).await {
        Ok(s) => s,
        Err(e) => {
            // 本地拨号失败：流随关闭传导给 server 侧用户连接
            warn!(conn_id, local_addr, error = %e, "local dial failed");
            return;
        }
    };
    let _ = local.set_nodelay(true);
    match tokio::io::copy_bidirectional(&mut stream, &mut local).await {
        Ok((up, down)) => debug!(conn_id, up, down, "connection closed"),
        Err(e) => debug!(conn_id, error = %e, "connection error"),
    }
}

/// 收到 new_connection：回连 server 建隧道（ConnInit 首帧标识），再拨本地服务并桥接。
/// server 侧对 conn_init 有 5s 匹配窗口，先建隧道可让本地拨号失败时快速传导为用户连接关闭。
async fn handle_new_conn(
    server_addr: String,
    server_port: u16,
    connector: Option<TlsConnector>,
    proxies: Arc<HashMap<String, String>>,
    conn_id: u64,
    proxy_name: String,
) {
    let Some(local_addr) = proxies.get(&proxy_name) else {
        warn!(conn_id, proxy = %proxy_name, "no such proxy");
        return;
    };
    let tcp = match TcpStream::connect((server_addr.as_str(), server_port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(conn_id, error = %e, "tunnel dial failed");
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    // 回连与控制连接走同一 TLS 策略
    let mut tunnel: rfp_common::BoxedStream = match &connector {
        Some(c) => match c
            .connect(
                rustls_pki_types::ServerName::try_from(server_addr.clone()).expect("控制连接已验证过 SNI 有效性"),
                tcp,
            )
            .await
        {
            Ok(s) => Box::new(s),
            Err(e) => {
                warn!(conn_id, error = %e, "tunnel tls handshake failed");
                return;
            }
        },
        None => Box::new(tcp),
    };
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
