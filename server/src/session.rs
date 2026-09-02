//! 控制会话处理：认证、代理注册、连接调度。

use std::sync::Arc;
use std::time::Duration;

use rfp_common::frame::{control_framed, recv_msg, send_msg, write_frame};
use rfp_common::msg::{version_compatible, Message, ProxyType, VERSION};
use rfp_common::now_ms;
use rfp_common::quic::QuicStream;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::state::{
    authorize_port, authorize_vhost, cleanup_session, AsyncStream, BoxedStream, DataTransport,
    RegisteredProxy, ServerState, SessionHandle,
};

/// new_connection 发出后等待 conn_init 的窗口
const PENDING_TIMEOUT: Duration = Duration::from_secs(5);

/// 发送拒绝消息并确认对端收到后再关闭。
/// QUIC 流 drop 时会 reset（丢弃未发出的数据），必须显式 shutdown（发 FIN）；
/// 且需等到对端关闭连接（读到 EOF/错误）才返回，否则 Error 帧可能随连接关闭被丢。
async fn reject<S: AsyncStream>(framed: &mut rfp_common::frame::Control<S>, msg: Message) {
    use tokio::io::AsyncWriteExt;
    let _ = send_msg(framed, &msg).await;
    let _ = framed.get_mut().shutdown().await;
    // 等对端读完关闭（防挂死：2s 兜底超时）
    let _ = tokio::time::timeout(Duration::from_secs(2), recv_msg(framed)).await;
}

/// 处理一条控制连接（Hello 已在接入层解析，认证在此进行）。
pub async fn handle_control<S: AsyncStream>(
    state: Arc<ServerState>,
    stream: S,
    peer: String,
    version: String,
    token: String,
    hostname: Option<String>,
    data: DataTransport,
) {
    let mut framed = control_framed(stream);

    // 认证失败不区分具体原因（防探测）
    let Some(identity) = state.authenticate(&token) else {
        reject(
            &mut framed,
            Message::Error {
                code: "auth_failed".into(),
                message: "authentication failed".into(),
            },
        )
        .await;
        info!(peer, "rejected: auth failed");
        return;
    };
    if !version_compatible(&version) {
        reject(
            &mut framed,
            Message::Error {
                code: "version_mismatch".into(),
                message: format!("server {VERSION}, client {version}"),
            },
        )
        .await;
        info!(peer, %version, "rejected: version mismatch");
        return;
    }

    let session_id = uuid::Uuid::new_v4().simple().to_string();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let handle = Arc::new(SessionHandle {
        id: session_id.clone(),
        identity: identity.clone(),
        cmd_tx,
        data,
        registered: Default::default(),
    });
    if send_msg(
        &mut framed,
        &Message::HelloAck {
            version: VERSION.into(),
            session_id: session_id.clone(),
        },
    )
    .await
    .is_err()
    {
        return;
    }
    info!(session = %session_id, user = identity.label(), peer, ?hostname, "session established");

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(msg) => {
                        if send_msg(&mut framed, &msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = recv_msg(&mut framed) => {
                match msg {
                    Err(e) => {
                        debug!(session = %session_id, error = %e, "control read error");
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(Message::RegisterProxy { name, proxy_type, local_addr, remote_port, vhost })) => {
                        let result = register_proxy(
                            &state,
                            &handle,
                            &name,
                            proxy_type,
                            remote_port,
                            vhost.as_deref(),
                        )
                        .await;
                        let ack = match result {
                            Ok(port) => {
                                info!(session = %session_id, proxy = %name, port, local_addr = %local_addr, "proxy registered");
                                Message::RegisterProxyAck { name, ok: true, error: None }
                            }
                            Err(err) => {
                                warn!(session = %session_id, proxy = %name, error = %err, "proxy register rejected");
                                Message::RegisterProxyAck { name, ok: false, error: Some(err) }
                            }
                        };
                        if send_msg(&mut framed, &ack).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Message::Ping { ts })) => {
                        if send_msg(&mut framed, &Message::Pong { ts }).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Message::Pong { ts })) => {
                        debug!(session = %session_id, rtt_ms = now_ms() - ts, "pong")
                    }
                    Ok(Some(Message::Error { code, message })) => {
                        warn!(session = %session_id, code, message, "client error")
                    }
                    Ok(Some(other)) => {
                        warn!(session = %session_id, ?other, "unexpected message");
                        let _ = send_msg(
                            &mut framed,
                            &Message::Error {
                                code: "unexpected_message".into(),
                                message: "unexpected message type".into(),
                            },
                        )
                        .await;
                    }
                }
            }
        }
    }

    cleanup_session(&state, &handle).await;
    info!(session = %session_id, "session closed");
}

/// 校验并注册代理：授权检查 + 名称/端口冲突检查 + 绑定监听 + 注册表登记。
async fn register_proxy(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    name: &str,
    proxy_type: ProxyType,
    remote_port: Option<u16>,
    vhost: Option<&str>,
) -> Result<u16, String> {
    if proxy_type != ProxyType::Tcp {
        return Err("M1 仅支持 tcp 代理".into());
    }
    let Some(port) = remote_port else {
        return Err("tcp 代理需要 remote_port".into());
    };
    if port == 0 {
        return Err("remote_port 不能为 0".into());
    }
    // 授权检查（用户模式下端口/vhost 必须在授权范围内）
    authorize_port(&session.identity, port)?;
    if let Some(vh) = vhost {
        authorize_vhost(&session.identity, vh)?;
    }

    let mut registry = state.registry.lock().await;
    if registry.by_name.contains_key(name) {
        return Err("同名代理已存在".into());
    }
    if registry.by_port.contains_key(&port) {
        return Err(format!("端口 {port} 已被占用"));
    }
    let listener = TcpListener::bind((state.bind_addr.as_str(), port))
        .await
        .map_err(|e| format!("监听 {port} 失败: {e}"))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    registry.by_name.insert(name.to_string(), Arc::clone(session));
    registry.by_port.insert(port, Arc::clone(session));
    drop(registry);

    let task = tokio::spawn(proxy_listener(
        Arc::clone(state),
        Arc::clone(session),
        name.to_string(),
        listener,
    ));
    session.registered.lock().unwrap().push(RegisteredProxy {
        name: name.to_string(),
        port,
        listener: task,
    });
    Ok(port)
}

/// 代理端口监听：用户连接到达 → 通知 client 回连 → 桥接。
async fn proxy_listener(
    state: Arc<ServerState>,
    session: Arc<SessionHandle>,
    name: String,
    listener: TcpListener,
) {
    loop {
        match listener.accept().await {
            Ok((user, peer)) => {
                let _ = user.set_nodelay(true);
                info!(proxy = %name, %peer, "user connection");
                tokio::spawn(relay(
                    Arc::clone(&state),
                    Arc::clone(&session),
                    name.clone(),
                    user,
                ));
            }
            Err(e) => {
                warn!(proxy = %name, error = %e, "accept error");
                break;
            }
        }
    }
}

/// 用户连接 ↔ 隧道数据通道桥接。
async fn relay(
    state: Arc<ServerState>,
    session: Arc<SessionHandle>,
    proxy_name: String,
    mut user: tokio::net::TcpStream,
) {
    let conn_id = state.next_conn_id();
    let mut tunnel: BoxedStream = match &session.data {
        // M1 TCP：通知 client 回连，经 pending 表匹配移交
        DataTransport::Tcp => {
            if session
                .cmd_tx
                .send(Message::NewConnection {
                    conn_id,
                    proxy_name: proxy_name.clone(),
                })
                .is_err()
            {
                return; // 会话已死，关闭用户连接
            }
            let (tx, rx) = oneshot::channel();
            state.pending.lock().unwrap().insert(conn_id, tx);
            match tokio::time::timeout(PENDING_TIMEOUT, rx).await {
                Ok(Ok(t)) => t,
                _ => {
                    state.pending.lock().unwrap().remove(&conn_id);
                    debug!(conn_id, "tunnel conn timeout or aborted");
                    return;
                }
            }
        }
        // M2 QUIC：直接在既有连接上开 bi-stream，首帧 ConnInit 标识归属
        DataTransport::Quic(quic) => {
            let mut stream: QuicStream = match quic.open_bi().await {
                Ok(s) => QuicStream::from(s),
                Err(e) => {
                    debug!(conn_id, error = %e, "quic open_bi failed");
                    return;
                }
            };
            let init = Message::ConnInit {
                conn_id,
                proxy_name: proxy_name.clone(),
            };
            if let Err(e) = write_frame(&mut stream, &init.encode()).await {
                debug!(conn_id, error = %e, "quic conn_init write failed");
                return;
            }
            Box::new(stream)
        }
    };
    match tokio::io::copy_bidirectional(&mut user, &mut tunnel).await {
        Ok((up, down)) => debug!(conn_id, up, down, "connection closed"),
        Err(e) => debug!(conn_id, error = %e, "connection error"),
    }
}
