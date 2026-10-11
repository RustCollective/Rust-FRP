//! 控制会话处理：认证、代理注册、连接调度。

use std::sync::Arc;
use std::time::Duration;

use rfp_common::frame::{control_framed, recv_msg, send_msg, write_frame};
use rfp_common::msg::{version_compatible, HttpInit, Message, ProxyType, VERSION};
use rfp_common::now_ms;
use rfp_common::quic::QuicStream;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::state::{
    authorize_port, authorize_vhost, cleanup_session, AsyncStream, BoxedStream, DataTransport,
    RegisteredProxy, ServerState, SessionHandle, VhostEntry,
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
                    Ok(Some(Message::RegisterProxy {
                        name,
                        proxy_type,
                        local_addr,
                        remote_port,
                        vhost,
                        vhosts,
                        subdomain,
                    })) => {
                        let result = register_proxy(
                            &state,
                            &handle,
                            &name,
                            proxy_type,
                            remote_port,
                            vhost.as_deref(),
                            &vhosts,
                            subdomain.as_deref(),
                        )
                        .await;
                        let ack = match result {
                            Ok(port) => {
                                info!(session = %session_id, proxy = %name, port = ?port, local_addr = %local_addr, "proxy registered");
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

fn type_name(t: ProxyType) -> &'static str {
    match t {
        ProxyType::Tcp => "tcp",
        ProxyType::Udp => "udp",
        ProxyType::Http => "http",
        ProxyType::Https => "https",
    }
}

/// 校验并注册代理，按类型分派。
///
/// 返回服务端实际暴露的端口：`tcp` 为具体端口，`http`/`https` 为 `None`
/// （域名型代理不占用公网端口，FR-001）。
#[allow(clippy::too_many_arguments)]
async fn register_proxy(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    name: &str,
    proxy_type: ProxyType,
    remote_port: Option<u16>,
    vhost: Option<&str>,
    vhosts: &[String],
    subdomain: Option<&str>,
) -> Result<Option<u16>, String> {
    match proxy_type {
        ProxyType::Tcp => register_tcp(state, session, name, remote_port, vhost)
            .await
            .map(Some),
        ProxyType::Http | ProxyType::Https => {
            register_vhost(state, session, name, proxy_type, vhost, vhosts, subdomain).await?;
            Ok(None)
        }
        ProxyType::Udp => register_udp(state, session, name, remote_port)
            .await
            .map(Some),
    }
}

/// UDP 型代理注册（S2）：端口授权 → 冲突检查 → 绑定 UDP → 起会话分发任务。
async fn register_udp(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    name: &str,
    remote_port: Option<u16>,
) -> Result<u16, String> {
    let Some(port) = remote_port else {
        return Err("udp 代理需要 remote_port".into());
    };
    if port == 0 {
        return Err("remote_port 不能为 0".into());
    }
    authorize_port(&session.identity, port)?;

    let mut registry = state.registry.lock().await;
    if registry.by_name.contains_key(name) {
        return Err("同名代理已存在".into());
    }
    if registry.by_port.contains_key(&port) {
        // tcp 与 udp 共用端口表：同端口不同协议也视为冲突，避免语义歧义
        return Err(format!("端口 {port} 已被占用（tcp/udp 共用端口表）"));
    }
    let socket = tokio::net::UdpSocket::bind((state.bind_addr.as_str(), port))
        .await
        .map_err(|e| format!("绑定 UDP {port} 失败: {e}"))?;
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(port);
    registry.by_name.insert(name.to_string(), Arc::clone(session));
    registry.by_port.insert(port, Arc::clone(session));
    drop(registry);

    let task = tokio::spawn(crate::udp::serve(
        Arc::clone(state),
        Arc::clone(session),
        name.to_string(),
        Arc::new(socket),
    ));
    session.registered.lock().unwrap().push(RegisteredProxy {
        name: name.to_string(),
        port: Some(port),
        listener: Some(task),
        vhosts: vec![],
    });
    info!(proxy = %name, port, "udp proxy registered");
    Ok(port)
}

/// 域名型代理注册（S1）：监听端口已配置 → 域名授权 → 冲突 → 原子登记。
///
/// 错误原因按 `contracts/rfp1-http-vhost.md` §2 的表格分列，便于客户端直接展示。
#[allow(clippy::too_many_arguments)]
async fn register_vhost(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    name: &str,
    proxy_type: ProxyType,
    vhost: Option<&str>,
    vhosts: &[String],
    subdomain: Option<&str>,
) -> Result<(), String> {
    // 1. 对应监听端口必须已配置，否则注册成功也访问不通
    let enabled = match proxy_type {
        ProxyType::Http => state.vhost.http,
        ProxyType::Https => state.vhost.https,
        _ => unreachable!("register_vhost 只处理 http/https"),
    };
    if !enabled {
        let section = if proxy_type == ProxyType::Http {
            "[http] bind_port"
        } else {
            "[https] bind_port"
        };
        return Err(format!(
            "服务端未配置 {section}，无法注册 {} 类型代理",
            type_name(proxy_type)
        ));
    }

    // 2. 汇总域名：vhost 与 vhosts 取并集，subdomain 展开为完整域名
    let mut domains: Vec<String> = Vec::new();
    if let Some(v) = vhost {
        domains.push(v.to_string());
    }
    domains.extend(vhosts.iter().cloned());
    if let Some(tag) = subdomain {
        let Some(host) = state.vhost.subdomain_host.as_deref() else {
            return Err("服务端未配置 subdomain_host，不能用 subdomain 注册".into());
        };
        domains.push(format!("{tag}.{host}"));
    }
    if domains.is_empty() {
        return Err("http/https 类型必须声明至少一个域名（vhost / vhosts / subdomain）".into());
    }

    // 3. 逐个归一化 + 授权检查
    let mut keys = Vec::with_capacity(domains.len());
    for d in &domains {
        let Some(k) = crate::vhost::router::vhost_key(d, proxy_type) else {
            return Err(format!("域名 `{d}` 无效"));
        };
        authorize_vhost(&session.identity, d)?;
        keys.push(k);
    }

    // 4. 冲突检查与登记在同一临界区内完成（登记前不释放锁）
    let mut registry = state.registry.lock().await;
    if registry.by_name.contains_key(name) {
        return Err("同名代理已存在".into());
    }
    for (d, k) in domains.iter().zip(keys.iter()) {
        // 冲突按 (类型, 域名) 判定：同域名的 http 与 https 是两条独立映射
        let slot = (proxy_type, k.key.clone());
        let owner = if k.wildcard {
            registry.by_vhost_wildcard.get(&slot)
        } else {
            registry.by_vhost_exact.get(&slot)
        };
        if let Some(e) = owner {
            return Err(format!("域名 `{d}` 已被会话 {} 注册", e.session.id));
        }
    }
    for k in &keys {
        let row = VhostEntry {
            session: Arc::clone(session),
            proxy_name: name.to_string(),
        };
        let slot = (proxy_type, k.key.clone());
        if k.wildcard {
            registry.by_vhost_wildcard.insert(slot, row);
        } else {
            registry.by_vhost_exact.insert(slot, row);
        }
    }
    registry.by_name.insert(name.to_string(), Arc::clone(session));
    drop(registry);

    session.registered.lock().unwrap().push(RegisteredProxy {
        name: name.to_string(),
        port: None,
        // 域名型代理没有端口监听任务
        listener: None,
        vhosts: keys,
    });
    info!(proxy = %name, kind = %type_name(proxy_type), domains = ?domains, "vhost proxy registered");
    Ok(())
}

/// TCP 型代理注册：授权检查 + 名称/端口冲突检查 + 绑定监听 + 注册表登记。
async fn register_tcp(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    name: &str,
    remote_port: Option<u16>,
    vhost: Option<&str>,
) -> Result<u16, String> {
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
        port: Some(port),
        listener: Some(task),
        // TCP 代理不注册域名；域名路由见 S1（US1）
        vhosts: vec![],
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
    let Some(mut tunnel) = open_tunnel(&state, &session, conn_id, &proxy_name, None).await else {
        return;
    };
    match tokio::io::copy_bidirectional(&mut user, &mut tunnel).await {
        Ok((up, down)) => debug!(conn_id, up, down, "connection closed"),
        Err(e) => debug!(conn_id, error = %e, "connection error"),
    }
}

/// 为一次转发取得隧道流（S1 起同时供 vhost 网关复用）。
///
/// - `DataTransport::Tcp`：控制通道下发 `NewConnection`（可携带 HTTP 元数据），
///   等客户端回连并经 `pending` 表按 `conn_id` 移交。
/// - `DataTransport::Quic`：在既有连接上 `open_bi`，首帧 `ConnInit` 携带 HTTP 元数据。
///
/// 两条路径都保证「客户端开始读请求体之前，请求元数据必然已到达」——
/// 这是 `contracts/rfp1-http-vhost.md` §3 的硬性约束。
pub(crate) async fn open_tunnel(
    state: &Arc<ServerState>,
    session: &Arc<SessionHandle>,
    conn_id: u64,
    proxy_name: &str,
    http: Option<HttpInit>,
) -> Option<BoxedStream> {
    match &session.data {
        // M1 TCP：通知 client 回连，经 pending 表匹配移交
        DataTransport::Tcp => {
            if session
                .cmd_tx
                .send(Message::NewConnection {
                    conn_id,
                    proxy_name: proxy_name.to_string(),
                    http,
                })
                .is_err()
            {
                return None; // 会话已死
            }
            let (tx, rx) = oneshot::channel();
            state.pending.lock().unwrap().insert(conn_id, tx);
            match tokio::time::timeout(PENDING_TIMEOUT, rx).await {
                Ok(Ok(t)) => Some(t),
                _ => {
                    state.pending.lock().unwrap().remove(&conn_id);
                    debug!(conn_id, "tunnel conn timeout or aborted");
                    None
                }
            }
        }
        // M2 QUIC：直接在既有连接上开 bi-stream，首帧 ConnInit 标识归属
        DataTransport::Quic(quic) => {
            let mut stream: QuicStream = match quic.open_bi().await {
                Ok(s) => QuicStream::from(s),
                Err(e) => {
                    debug!(conn_id, error = %e, "quic open_bi failed");
                    return None;
                }
            };
            let init = Message::ConnInit {
                conn_id,
                proxy_name: proxy_name.to_string(),
                http,
            };
            if let Err(e) = write_frame(&mut stream, &init.encode()).await {
                debug!(conn_id, error = %e, "quic conn_init write failed");
                return None;
            }
            Some(Box::new(stream))
        }
    }
}
