//! 端到端：echo 服务 → rfps → rfpc → 隧道访问。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rfp_client::config::{
    ClientConfig, LocalTlsConfig, ProxyConfig, TlsConfig as ClientTls, Transport,
};
use rfp_client::{quic_endpoint, run_once, run_quic_once, RunError};
use rfp_common::frame::{control_framed, recv_msg, send_msg};
use rfp_common::msg::{Message, ProxyType, VERSION};

use rfp_server::config::{
    CertEntry, QuicConfig, ServerConfig, TlsConfig as ServerTls, UdpConfig, UserConfig, VhostListener,
};
use rfp_server::serve;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn plain_client_tls() -> ClientTls {
    ClientTls {
        enabled: false,
        server_fingerprint: None,
    }
}

// ------------------------------------------------ 控制面注册（协议级）

/// 用一条独立控制连接做 Hello + RegisterProxy，返回注册应答。
///
/// 拒绝原因（FR-007 / FR-012 / FR-024 要求"必须可区分"）是**服务端**契约，
/// 客户端的处置策略另由会话级用例覆盖：单个代理注册失败不再断开整条会话
/// （F5），所以不能再靠 `run_once` 返回错误来断言这些原因。
async fn control_register(srv_port: u16, token: &str, proxy: ProxyConfig) -> Message {
    let tcp = TcpStream::connect(("127.0.0.1", srv_port))
        .await
        .expect("控制连接失败");
    let mut framed = control_framed(tcp);
    send_msg(
        &mut framed,
        &Message::Hello {
            version: VERSION.into(),
            token: token.into(),
            hostname: None,
        },
    )
    .await
    .expect("发送 Hello 失败");
    match recv_msg(&mut framed).await {
        Ok(Some(Message::HelloAck { .. })) => {}
        other => panic!("预期 HelloAck，收到 {other:?}"),
    }
    send_msg(
        &mut framed,
        &Message::RegisterProxy {
            name: proxy.name.clone(),
            proxy_type: proxy.proxy_type,
            local_addr: proxy.local_addr.clone(),
            remote_port: proxy.remote_port,
            vhost: None,
            vhosts: proxy.custom_domains.clone(),
            subdomain: proxy.subdomain.clone(),
        },
    )
    .await
    .expect("发送 RegisterProxy 失败");
    match recv_msg(&mut framed).await {
        Ok(Some(msg @ Message::RegisterProxyAck { .. })) => msg,
        other => panic!("预期 RegisterProxyAck，收到 {other:?}"),
    }
}

/// 断言注册被拒并返回原因文本
async fn expect_register_rejected(srv_port: u16, token: &str, proxy: ProxyConfig) -> String {
    match control_register(srv_port, token, proxy).await {
        Message::RegisterProxyAck {
            ok: false, error, ..
        } => error.unwrap_or_default(),
        other => panic!("预期注册被拒，收到 {other:?}"),
    }
}

/// tcp 类型代理配置（拒绝原因类断言用；local_addr 不会被服务端校验）
fn tcp_proxy(name: &str, remote_port: u16, local_addr: &str) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        proxy_type: ProxyType::Tcp,
        local_addr: local_addr.into(),
        remote_port: Some(remote_port),
        custom_domains: vec![],
        subdomain: None,
        local_tls: LocalTlsConfig::default(),
    }
}

/// 起一个 echo origin 服务，返回端口
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn test_server_config(port: u16, token: &str) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        token: token.into(),
        users: vec![],
        tls: ServerTls {
            enabled: false,
            cert: None,
            key: None,
        },
        quic: QuicConfig::default(),
        // S1：vhost 段缺省不启用
        http: None,
        https: None,
        subdomain_host: None,
        certs: vec![],
        udp: UdpConfig::default(),
    }
}

#[tokio::test]
async fn tcp_proxy_end_to_end() {
    let echo_port = spawn_echo().await;

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, test_server_config(srv_port, "secret")));

    // 远端代理端口：固定安全区找空闲口（临时端口区间的注册会被 legacy 模式拒绝）
    let remote_port = safe_port(16100).await;

    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: "echo".into(),
            proxy_type: ProxyType::Tcp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(remote_port),
            // S1 新增字段：tcp 类型不允许域名与本地 TLS
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: plain_client_tls(),
    }));

    // 等待代理就绪（client 注册 → server 绑定监听）
    let mut user = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(c) = TcpStream::connect(("127.0.0.1", remote_port)).await {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("proxy not ready in 10s");

    // 第一段：写 → echo 回
    user.write_all(b"hello rust-frp").await.unwrap();
    let mut buf = vec![0u8; b"hello rust-frp".len()];
    tokio::time::timeout(Duration::from_secs(5), user.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf, b"hello rust-frp");

    // 第二段：确认流式连续
    user.write_all(b"second chunk").await.unwrap();
    let mut buf2 = vec![0u8; b"second chunk".len()];
    tokio::time::timeout(Duration::from_secs(5), user.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(buf2, b"second chunk");
}

#[tokio::test]
async fn auth_failure_is_fatal() {
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, test_server_config(srv_port, "secret")));

    let res = tokio::time::timeout(
        Duration::from_secs(10),
        run_once(ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port: srv_port,
            transport: Transport::Tcp,
            token: "wrong".into(),
            proxies: vec![],
            tls: plain_client_tls(),
        }),
    )
    .await
    .expect("timeout");

    assert!(matches!(res, Err(RunError::Fatal(_))));
}

fn user_server_config(port: u16) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        token: "legacy-ignored".into(),
        users: vec![UserConfig {
            name: "alice".into(),
            token: "alice-token".into(),
            ports: vec!["61000-61010".into()],
            vhosts: vec!["*.alice.dev".into()],
        }],
        tls: ServerTls {
            enabled: false,
            cert: None,
            key: None,
        },
        quic: QuicConfig::default(),
        // S1：vhost 段缺省不启用
        http: None,
        https: None,
        subdomain_host: None,
        certs: vec![],
        udp: UdpConfig::default(),
    }
}

/// 从指定起始端口找一个可绑定的端口（避开临时端口区间，
/// bind(0) 拿到的是 32768-60999 的随机端口，会被 rfps 拒绝注册）
async fn safe_port(start: u16) -> u16 {
    for p in start..start + 200 {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", p)).await {
            drop(l);
            return p;
        }
    }
    panic!("no available port from {start}");
}

#[tokio::test]
async fn user_mode_port_authorization() {
    let echo_port = spawn_echo().await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, user_server_config(srv_port)));

    let client = |remote_port: u16| ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "alice-token".into(),
        proxies: vec![ProxyConfig {
            name: "echo".into(),
            proxy_type: ProxyType::Tcp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(remote_port),
            // S1 新增字段：tcp 类型不允许域名与本地 TLS
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: plain_client_tls(),
    };

    // 授权范围内：注册成功 + 转发可用
    // （在授权区间 61000-61010 里挑当前空闲的端口，避免与残留进程打架）
    let allowed = {
        let mut found = None;
        for p in 61000..=61010u16 {
            if let Ok(l) = TcpListener::bind(("127.0.0.1", p)).await {
                drop(l);
                found = Some(p);
                break;
            }
        }
        found.expect("授权区间 61000-61010 内无空闲端口")
    };
    {
        tokio::spawn(run_once(client(allowed)));
        let mut user = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(c) = TcpStream::connect(("127.0.0.1", allowed)).await {
                    return c;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("proxy not ready");
        user.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        user.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
    }

    // 授权范围外：注册被拒，原因必须点明授权范围
    let outside = safe_port(16200).await;
    let reason = expect_register_rejected(
        srv_port,
        "alice-token",
        tcp_proxy("echo-outside", outside, &format!("127.0.0.1:{echo_port}")),
    )
    .await;
    assert!(reason.contains("授权范围"), "unexpected reason: {reason}");

    // 错误 token：认证失败 Fatal
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        run_once(ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port: srv_port,
            transport: Transport::Tcp,
            token: "bob-token".into(),
            proxies: vec![],
            tls: plain_client_tls(),
        }),
    )
    .await
    .expect("timeout");
    assert!(matches!(res, Err(RunError::Fatal(_))));
}

/// TLS + fingerprint pinning 全链路：控制连接与数据回连都走 TLS
#[tokio::test]
async fn tls_pinned_end_to_end() {
    let echo_port = spawn_echo().await;

    // 生成自签证书落盘（服务端复用同一对文件）
    let (cert, key) = rfp_server::tls::generate_self_signed().unwrap();
    let fingerprint = rfp_common::sha256_hex(cert.as_ref());
    let dir = std::env::temp_dir().join(format!("rfp-tls-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    std::fs::write(&cert_path, cert.as_ref()).unwrap();
    std::fs::write(&key_path, &key).unwrap();

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: srv_port,
            token: "secret".into(),
            users: vec![],
            tls: ServerTls {
                enabled: true,
                cert: Some(cert_path.display().to_string()),
                key: Some(key_path.display().to_string()),
            },
            quic: QuicConfig::default(),
            // S1：vhost 段缺省不启用
            http: None,
            https: None,
            subdomain_host: None,
            certs: vec![],
            udp: UdpConfig::default(),
        },
    ));

    let remote_port = safe_port(16300).await;
    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: "echo".into(),
            proxy_type: ProxyType::Tcp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(remote_port),
            // S1 新增字段：tcp 类型不允许域名与本地 TLS
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: ClientTls {
            enabled: true,
            server_fingerprint: Some(fingerprint),
        },
    }));

    // 等代理就绪并验证回显（控制 + 数据连接均经 TLS）
    let mut user = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(c) = TcpStream::connect(("127.0.0.1", remote_port)).await {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("proxy not ready");
    user.write_all(b"tls!").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), user.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"tls!");

    let _ = std::fs::remove_dir_all(&dir);
}

/// fingerprint 不匹配：TLS 握手被拒（Retry 语义，重连后仍失败）
#[tokio::test]
async fn tls_wrong_fingerprint_rejected() {
    // 服务端用一对独立证书；client 配全 0 指纹
    let (cert, key) = rfp_server::tls::generate_self_signed().unwrap();
    let dir = std::env::temp_dir().join(format!("rfp-tls-wrong-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    std::fs::write(&cert_path, cert.as_ref()).unwrap();
    std::fs::write(&key_path, &key).unwrap();

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: srv_port,
            token: "secret".into(),
            users: vec![],
            tls: ServerTls {
                enabled: true,
                cert: Some(cert_path.display().to_string()),
                key: Some(key_path.display().to_string()),
            },
            quic: QuicConfig::default(),
            // S1：vhost 段缺省不启用
            http: None,
            https: None,
            subdomain_host: None,
            certs: vec![],
            udp: UdpConfig::default(),
        },
    ));

    let res = tokio::time::timeout(
        Duration::from_secs(10),
        run_once(ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port: srv_port,
            transport: Transport::Tcp,
            token: "secret".into(),
            proxies: vec![],
            tls: ClientTls {
                enabled: true,
                server_fingerprint: Some("00".repeat(32)),
            },
        }),
    )
    .await
    .expect("timeout");
    assert!(matches!(res, Err(RunError::Retry(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

/// 落盘一对自签证书，返回 (cert_path, key_path, fingerprint)
fn write_cert(dir_tag: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let (cert, key) = rfp_server::tls::generate_self_signed().unwrap();
    let fingerprint = rfp_common::sha256_hex(cert.as_ref());
    let dir = std::env::temp_dir().join(format!("{dir_tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.der");
    let key_path = dir.join("key.der");
    std::fs::write(&cert_path, cert.as_ref()).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    (cert_path, key_path, fingerprint)
}

fn quic_server_config(srv_port: u16, cert: &str, key: &str) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: srv_port,
        token: "secret".into(),
        users: vec![],
        tls: ServerTls {
            enabled: true,
            cert: Some(cert.into()),
            key: Some(key.into()),
        },
        quic: QuicConfig {
            enabled: true,
            bind_port: None,
        },
        // S1：vhost 段缺省不启用
        http: None,
        https: None,
        subdomain_host: None,
        certs: vec![],
        udp: UdpConfig::default(),
    }
}

/// 等代理就绪并回读一轮 echo，返回用户连接。
/// 旧会话清理有延迟：端口可能已监听但隧道已死（连接被重置），需整体重试。
async fn wait_proxy_and_echo(remote_port: u16) -> tokio::net::TcpStream {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(mut c) = TcpStream::connect(("127.0.0.1", remote_port)).await {
                if c.write_all(b"quic!").await.is_ok() {
                    let mut buf = [0u8; 5];
                    let read = tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut buf))
                        .await
                        .unwrap_or(Err(std::io::Error::other("read timeout")));
                    if read.is_ok() && &buf == b"quic!" {
                        return c;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("proxy not ready")
}

/// QUIC 全链路：TLS 内生 + fingerprint pinning + server 下发 bi-stream 数据隧道
#[tokio::test]
async fn quic_end_to_end() {
    let echo_port = spawn_echo().await;
    let (cert_path, key_path, fingerprint) = write_cert("rfp-quic-test");

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        quic_server_config(srv_port, &cert_path.display().to_string(), &key_path.display().to_string()),
    ));

    let remote_port = safe_port(16400).await;
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Quic,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: "echo".into(),
            proxy_type: ProxyType::Tcp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(remote_port),
            // S1 新增字段：tcp 类型不允许域名与本地 TLS
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: ClientTls {
            enabled: true,
            server_fingerprint: Some(fingerprint),
        },
    };
    let endpoint = quic_endpoint(&cfg).unwrap();
    let ep = endpoint.clone();
    tokio::spawn(async move { run_quic_once(&ep, cfg).await });

    let mut user = wait_proxy_and_echo(remote_port).await;
    // 流式连续性：第二段写读
    user.write_all(b"second chunk").await.unwrap();
    let mut buf2 = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(5), user.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf2, b"second chunk");

    let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
}

/// QUIC 断线重连：会话票据保留在复用的 endpoint 上，重连走恢复（含 0-RTT 路径）
#[tokio::test]
async fn quic_reconnect_after_drop() {
    let echo_port = spawn_echo().await;
    let (cert_path, key_path, fingerprint) = write_cert("rfp-quic-reconnect");

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        quic_server_config(srv_port, &cert_path.display().to_string(), &key_path.display().to_string()),
    ));

    let remote_port = safe_port(16500).await;
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Quic,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: "echo".into(),
            proxy_type: ProxyType::Tcp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(remote_port),
            // S1 新增字段：tcp 类型不允许域名与本地 TLS
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: ClientTls {
            enabled: true,
            server_fingerprint: Some(fingerprint),
        },
    };
    let endpoint = quic_endpoint(&cfg).unwrap();
    let endpoint2 = endpoint.clone();
    let cfg_for_task = cfg.clone();
    let task = tokio::spawn(async move { run_quic_once(&endpoint, cfg_for_task).await });
    let _user = wait_proxy_and_echo(remote_port).await;

    // 模拟连接断开：任务 abort（连接随之关闭），endpoint 克隆保留 → 会话票据存活
    task.abort();

    // 同一 endpoint 重连（rfpc run() 的生产路径）：走会话恢复 / 0-RTT；
    // server 侧旧会话清理有延迟，注册冲突按 Retry 重试
    let cfg2 = cfg.clone();
    tokio::spawn(async move {
        loop {
            if matches!(run_quic_once(&endpoint2, cfg2.clone()).await, Ok(())) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    // 重连后隧道仍可用
    let _user2 = wait_proxy_and_echo(remote_port).await;

    let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
}

/// QUIC 认证失败：Fatal
#[tokio::test]
async fn quic_auth_failure_is_fatal() {
    let (cert_path, key_path, fingerprint) = write_cert("rfp-quic-auth");

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        quic_server_config(srv_port, &cert_path.display().to_string(), &key_path.display().to_string()),
    ));

    let cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Quic,
        token: "wrong".into(),
        proxies: vec![],
        tls: ClientTls {
            enabled: true,
            server_fingerprint: Some(fingerprint),
        },
    };
    let endpoint = quic_endpoint(&cfg).unwrap();
    let res = tokio::time::timeout(Duration::from_secs(10), run_quic_once(&endpoint, cfg))
        .await
        .expect("timeout");
    assert!(
        matches!(res, Err(RunError::Fatal(_))),
        "unexpected result: {res:?}"
    );

    let _ = std::fs::remove_dir_all(cert_path.parent().unwrap());
}

// ============================================================ S1：vhost 网关

/// 最小 HTTP/1.1 origin：记录收到的请求头，回固定响应体
async fn spawn_http_origin(body: &'static str) -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let seen_out = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            let seen = Arc::clone(&seen_out);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                *seen.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// 带 vhost 段的服务端配置
fn vhost_server_config(
    port: u16,
    http_port: Option<u16>,
    https_port: Option<u16>,
    certs: Vec<CertEntry>,
) -> ServerConfig {
    let mut cfg = test_server_config(port, "secret");
    cfg.http = http_port.map(|p| VhostListener { bind_port: p, bind_addr: None });
    cfg.https = https_port.map(|p| VhostListener { bind_port: p, bind_addr: None });
    cfg.certs = certs;
    cfg
}

/// 域名型代理的客户端配置
fn vhost_client_config(
    srv_port: u16,
    proxy_type: ProxyType,
    name: &str,
    origin_port: u16,
    domains: Vec<String>,
) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: name.into(),
            proxy_type,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: None,
            custom_domains: domains,
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: plain_client_tls(),
    }
}

/// 向 vhost 明文端口发一个 h1 请求，读完整响应
async fn vhost_request(port: u16, host: &str, path: &str) -> String {
    let mut s = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(e) => return format!("<connect-failed: {e}>"),
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return String::new();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).to_string()
}

/// 轮询到命中为止（客户端注册与旧会话清理都有延迟）；失败时把最后一次响应带出来
async fn vhost_get_until_ok(port: u16, host: &str, path: &str) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last = String::new();
    while tokio::time::Instant::now() < deadline {
        last = vhost_request(port, host, path).await;
        if last.starts_with("HTTP/1.1 200") {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("vhost 请求始终未命中（host={host} port={port}），最后一次响应: {last:?}");
}

/// T023 + T027：明文按 Host 路由，且 origin 侧收到转发头
#[tokio::test]
async fn vhost_http_host_routing() {
    let (origin_port, seen) = spawn_http_origin("hello-from-origin").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18080).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));

    let resp = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(resp.contains("hello-from-origin"), "响应体不符: {resp}");

    // 转发头：由服务端追加，且 x-forwarded-proto 反映入口协议
    let head = seen.lock().unwrap().clone();
    let lower = head.to_lowercase();
    assert!(lower.contains("x-forwarded-for"), "origin 未收到 XFF:\n{head}");
    assert!(
        lower.contains("x-forwarded-proto: http"),
        "origin 未收到 XFP:\n{head}"
    );
    // 逐跳头必须被剥离（请求里带的是 Connection: close）
    assert!(!lower.contains("connection: close"), "逐跳头未被剥离:\n{head}");
}

/// T025：未注册域名返回 404，且不回落其他代理
#[tokio::test]
async fn vhost_unknown_domain_returns_404() {
    let (origin_port, _seen) = spawn_http_origin("should-not-be-reached").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18200).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));

    // 先确认网关已可用，保证 404 不是"还没起来"
    let ok = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(ok.starts_with("HTTP/1.1 200"));

    let resp = vhost_request(http_port, "nope.example.com", "/").await;
    assert!(resp.starts_with("HTTP/1.1 404"), "未注册域名应 404: {resp}");
    assert!(
        !resp.contains("should-not-be-reached"),
        "404 不应回落其他代理: {resp}"
    );
}

/// T026：域名冲突被拒，且先注册者不受影响
#[tokio::test]
async fn vhost_domain_conflict_rejected() {
    let (origin_port, _seen) = spawn_http_origin("first-wins").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18300).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));

    // 先注册者
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));
    vhost_get_until_ok(http_port, "app.example.com", "/").await;

    // 后注册者：同域名不同代理名，必须被拒且原因里带冲突域名
    let reason = expect_register_rejected(
        srv_port,
        "secret",
        ProxyConfig {
            name: "web2".into(),
            proxy_type: ProxyType::Http,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: None,
            custom_domains: vec!["app.example.com".into()],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        },
    )
    .await;
    assert!(
        reason.contains("app.example.com"),
        "拒绝原因未指明冲突域名: {reason}"
    );

    // 先注册者仍然可用
    let resp = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(resp.contains("first-wins"), "{resp}");
}

/// T028：服务端未配置 [http] 监听时注册必须失败（而非"注册成功但访问不通"）
#[tokio::test]
async fn vhost_register_rejected_without_listener() {
    let (origin_port, _seen) = spawn_http_origin("nope").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    // 刻意不配置 [http]
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, None, None, vec![]),
    ));

    let reason = expect_register_rejected(
        srv_port,
        "secret",
        ProxyConfig {
            name: "web".into(),
            proxy_type: ProxyType::Http,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: None,
            custom_domains: vec!["app.example.com".into()],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        },
    )
    .await;
    assert!(
        reason.contains("[http] bind_port"),
        "拒绝原因未指明缺少的监听段: {reason}"
    );
}

/// T024：HTTPS 按 SNI 终止——必须在证书校验真的通过的前提下成功
#[tokio::test]
async fn vhost_https_sni_termination() {
    let (origin_port, _seen) = spawn_http_origin("hello-vhost-tls").await;

    // 域名证书
    let ck = rcgen::generate_simple_self_signed(vec!["app.example.com".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("rfp-e2e-vhost-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("app.crt");
    let key_path = dir.join("app.key");
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
    let fingerprint = rfp_common::sha256_hex(ck.cert.der());

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let https_port = safe_port(18443).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(
            srv_port,
            None,
            Some(https_port),
            vec![CertEntry {
                domain: "app.example.com".into(),
                cert: cert_path.display().to_string(),
                key: key_path.display().to_string(),
            }],
        ),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Https,
        "web-tls",
        origin_port,
        vec!["app.example.com".into()],
    )));

    // 指纹固定：指纹必须真的匹配，"跳过校验"不能算通过
    let tls_cfg = rfp_client::tls::rustls_client_config(Some(&fingerprint)).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let name = rustls::pki_types::ServerName::try_from("app.example.com").unwrap();

    let body = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let Ok(tcp) = TcpStream::connect(("127.0.0.1", https_port)).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let Ok(mut tls) = connector.connect(name.clone(), tcp).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let req = "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n";
            if tls.write_all(req.as_bytes()).await.is_err() {
                continue;
            }
            let mut out = Vec::new();
            let _ = tls.read_to_end(&mut out).await;
            let resp = String::from_utf8_lossy(&out).to_string();
            if resp.contains("hello-vhost-tls") {
                return resp;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("HTTPS vhost 请求始终未成功");

    assert!(body.starts_with("HTTP/1.1 200"), "{body}");

    // SNI 未命中证书表 → 握手必须失败（不回落默认证书）
    let other = rustls::pki_types::ServerName::try_from("nope.example.com").unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", https_port)).await.unwrap();
    let handshake = connector.connect(other, tcp).await;
    assert!(handshake.is_err(), "未命中 SNI 的握手必须失败");

    std::fs::remove_dir_all(dir).ok();
}

/// T029：用户模式下域名不在 `vhosts` 授权范围时注册被拒（FR-009 从"形同占位"变为真正生效）
#[tokio::test]
async fn vhost_domain_authorization() {
    let (origin_port, _seen) = spawn_http_origin("alice-page").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18500).await;
    // 用户模式：alice 的 vhosts = ["*.alice.dev"]
    let mut cfg = user_server_config(srv_port);
    cfg.http = Some(VhostListener { bind_port: http_port, bind_addr: None });
    tokio::spawn(serve(srv_listener, cfg));

    let client_for = |domain: &str| {
        let mut c = vhost_client_config(
            srv_port,
            ProxyType::Http,
            "web",
            origin_port,
            vec![domain.to_string()],
        );
        c.token = "alice-token".into();
        c
    };

    // 越权域名：必须被拒，且原因里带域名
    let reason = expect_register_rejected(
        srv_port,
        "alice-token",
        ProxyConfig {
            name: "web-evil".into(),
            proxy_type: ProxyType::Http,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: None,
            custom_domains: vec!["evil.example.com".into()],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        },
    )
    .await;
    assert!(
        reason.contains("evil.example.com"),
        "拒绝原因未指明域名: {reason}"
    );

    // 授权范围内的域名：注册成功且可访问
    tokio::spawn(run_once(client_for("app.alice.dev")));
    let resp = vhost_get_until_ok(http_port, "app.alice.dev", "/").await;
    assert!(resp.contains("alice-page"), "{resp}");
}

/// T042：QUIC 路径的 vhost 转发——元数据随数据流首帧（`conn_init`）下发。
///
/// 与 TCP 用例的区别在于承载：TCP 走控制通道的 `new_connection`，QUIC 走
/// server 主动 `open_bi` 后的首帧。若首帧没有携带 HTTP 元数据，客户端会退化成
/// 裸字节桥接（把帧字节当请求发给本地服务），本用例就会因等不到
/// `http_response_meta` 而失败——因此这条用例确实在区分两条承载路径。
#[tokio::test]
async fn vhost_quic_http_routing() {
    let (origin_port, seen) = spawn_http_origin("hello-over-quic").await;
    let (cert_path, key_path, fingerprint) = write_cert("rfp-vhost-quic");

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18600).await;

    // QUIC 传输 + vhost 明文监听
    let mut cfg = quic_server_config(
        srv_port,
        &cert_path.display().to_string(),
        &key_path.display().to_string(),
    );
    cfg.http = Some(VhostListener { bind_port: http_port, bind_addr: None });
    tokio::spawn(serve(srv_listener, cfg));

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Quic,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: "web".into(),
            proxy_type: ProxyType::Http,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: None,
            custom_domains: vec!["app.example.com".into()],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: ClientTls {
            enabled: true,
            server_fingerprint: Some(fingerprint),
        },
    };
    let endpoint = quic_endpoint(&client_cfg).unwrap();
    let ep = endpoint.clone();
    tokio::spawn(async move { run_quic_once(&ep, client_cfg).await });

    let resp = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(resp.contains("hello-over-quic"), "{resp}");

    // 转发头与 TCP 路径一致
    let head = seen.lock().unwrap().clone().to_lowercase();
    assert!(head.contains("x-forwarded-for"), "origin 未收到 XFF:\n{head}");
    assert!(
        head.contains("x-forwarded-proto: http"),
        "origin 未收到 XFP:\n{head}"
    );
}

// ============================================================ S2：UDP 代理

/// 起一个 UDP 回显服务，返回端口
async fn spawn_udp_echo() -> u16 {
    let sock = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    port
}

/// 反复发包直到收到回显。
///
/// 会话与隧道的建立有延迟，首个数据报可能先丢——UDP 语义允许，测试必须容忍。
async fn udp_echo_until(sock: &tokio::net::UdpSocket, payload: &[u8]) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut buf = vec![0u8; 4096];
    while tokio::time::Instant::now() < deadline {
        let _ = sock.send(payload).await;
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await
        {
            buf.truncate(n);
            return buf;
        }
    }
    panic!("UDP 回显始终未成功（payload 长度 {}）", payload.len());
}

/// UDP 代理的客户端配置（TCP 承载、明文）
fn udp_client_config(
    srv_port: u16,
    name: &str,
    origin_port: u16,
    remote_port: u16,
) -> ClientConfig {
    ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![ProxyConfig {
            name: name.into(),
            proxy_type: ProxyType::Udp,
            local_addr: format!("127.0.0.1:{origin_port}"),
            remote_port: Some(remote_port),
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        }],
        tls: plain_client_tls(),
    }
}

/// T062：UDP 全链路——数据报边界、同源端口复用会话、换源端口即新会话
#[tokio::test]
async fn udp_proxy_end_to_end() {
    let echo_port = spawn_udp_echo().await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, test_server_config(srv_port, "secret")));

    let remote_port = safe_port(16600).await;
    tokio::spawn(run_once(udp_client_config(srv_port, "udp-echo", echo_port, remote_port)));

    // 源端口 A
    let a = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    a.connect(("127.0.0.1", remote_port)).await.unwrap();
    let got = udp_echo_until(&a, b"hello-udp-a").await;
    assert_eq!(got, b"hello-udp-a");

    // 同一会话内数据报边界不粘连：连发两个不同长度的包，应收到两个独立回显
    let _ = a.send(b"11111").await;
    let _ = a.send(b"2222222222").await;
    let mut sizes = Vec::new();
    for _ in 0..2 {
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), a.recv(&mut buf))
            .await
            .expect("等待第二个回显超时")
            .unwrap();
        sizes.push(n);
    }
    sizes.sort_unstable();
    assert_eq!(sizes, vec![5, 10], "数据报边界被破坏");

    // 换源端口 → 另一条会话，同样可用
    let b = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    b.connect(("127.0.0.1", remote_port)).await.unwrap();
    let got_b = udp_echo_until(&b, b"hello-udp-b").await;
    assert_eq!(got_b, b"hello-udp-b");

    // 源 A 仍然可用（未被 B 顶掉）
    let again = udp_echo_until(&a, b"still-a").await;
    assert_eq!(again, b"still-a");
}

/// T063：空闲回收后，同源端口再发包应能重建会话。
///
/// 回收触发本身由 `udp::idle_watch` 的单测覆盖；这里覆盖"重建"这一段语义。
#[tokio::test]
async fn udp_session_rebuilt_after_idle() {
    let echo_port = spawn_udp_echo().await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    // 空闲阈值压到 1s，让测试不必等默认的 60s
    let mut cfg = test_server_config(srv_port, "secret");
    cfg.udp = UdpConfig { idle_timeout_secs: 1 };
    tokio::spawn(serve(srv_listener, cfg));

    let remote_port = safe_port(16700).await;
    tokio::spawn(run_once(udp_client_config(srv_port, "udp-echo", echo_port, remote_port)));

    let a = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    a.connect(("127.0.0.1", remote_port)).await.unwrap();
    assert_eq!(udp_echo_until(&a, b"before-idle").await, b"before-idle");

    // 超过阈值（1s）+ 一轮检查间隔（1s）
    tokio::time::sleep(Duration::from_secs(4)).await;

    // 同一源端口：会话已回收，应能重新建立
    assert_eq!(udp_echo_until(&a, b"after-idle").await, b"after-idle");
}

/// T064：用户模式下 UDP 端口不在授权区间时注册被拒
#[tokio::test]
async fn udp_port_authorization() {
    let echo_port = spawn_udp_echo().await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, user_server_config(srv_port)));

    // alice 的授权区间是 61000-61010
    let reason = expect_register_rejected(
        srv_port,
        "alice-token",
        ProxyConfig {
            name: "udp-echo-outside".into(),
            proxy_type: ProxyType::Udp,
            local_addr: format!("127.0.0.1:{echo_port}"),
            remote_port: Some(62000),
            custom_domains: vec![],
            subdomain: None,
            local_tls: LocalTlsConfig::default(),
        },
    )
    .await;
    assert!(reason.contains("62000"), "拒绝原因未指明端口: {reason}");

    // 区间内可用
    let mut cfg = udp_client_config(srv_port, "udp-echo", echo_port, 61005);
    cfg.token = "alice-token".into();
    tokio::spawn(run_once(cfg));
    let a = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    a.connect(("127.0.0.1", 61005)).await.unwrap();
    assert_eq!(udp_echo_until(&a, b"authorized").await, b"authorized");
}

/// T065：UDP 代理经 QUIC 隧道承载时行为一致（承载与 UDP 语义解耦）
#[tokio::test]
async fn udp_over_quic_transport() {
    let echo_port = spawn_udp_echo().await;
    let (cert_path, key_path, fingerprint) = write_cert("rfp-udp-quic");

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(
        srv_listener,
        quic_server_config(
            srv_port,
            &cert_path.display().to_string(),
            &key_path.display().to_string(),
        ),
    ));

    let remote_port = safe_port(16800).await;
    let mut cfg = udp_client_config(srv_port, "udp-echo", echo_port, remote_port);
    cfg.transport = Transport::Quic;
    cfg.tls = ClientTls {
        enabled: true,
        server_fingerprint: Some(fingerprint),
    };
    let endpoint = quic_endpoint(&cfg).unwrap();
    let ep = endpoint.clone();
    tokio::spawn(async move { run_quic_once(&ep, cfg).await });

    let a = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    a.connect(("127.0.0.1", remote_port)).await.unwrap();
    assert_eq!(udp_echo_until(&a, b"over-quic").await, b"over-quic");
}

/// 同一域名同时注册 `http` 与 `https` 两条代理：互不抢占，各自由对应监听服务。
///
/// 这是 spec.md 的边界情形，也是 2026-10-12 真实链路验收时暴露出来的实现缺陷
/// （原实现把同域名的 http/https 判成了冲突）。回归防线就放这里。
#[tokio::test]
async fn vhost_same_domain_http_and_https() {
    let (plain_origin, _s1) = spawn_http_origin("plain-side").await;
    let (tls_origin, _s2) = spawn_http_origin("tls-side").await;

    let ck = rcgen::generate_simple_self_signed(vec!["app.example.com".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("rfp-e2e-bothkind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("app.crt");
    let key_path = dir.join("app.key");
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
    let fingerprint = rfp_common::sha256_hex(ck.cert.der());

    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18700).await;
    let https_port = safe_port(18800).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(
            srv_port,
            Some(http_port),
            Some(https_port),
            vec![CertEntry {
                domain: "app.example.com".into(),
                cert: cert_path.display().to_string(),
                key: key_path.display().to_string(),
            }],
        ),
    ));

    let mk = |name: &str, kind: ProxyType, origin: u16| ProxyConfig {
        name: name.into(),
        proxy_type: kind,
        local_addr: format!("127.0.0.1:{origin}"),
        remote_port: None,
        custom_domains: vec!["app.example.com".into()],
        subdomain: None,
        local_tls: LocalTlsConfig::default(),
    };
    // 同一个会话里注册同名域名的 http 与 https 两条代理
    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![
            mk("web-http", ProxyType::Http, plain_origin),
            mk("web-https", ProxyType::Https, tls_origin),
        ],
        tls: plain_client_tls(),
    }));

    // 明文监听 → plain-side
    let plain = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(plain.contains("plain-side"), "{plain}");
    assert!(!plain.contains("tls-side"), "明文监听串到了 https 代理: {plain}");

    // TLS 监听 → tls-side（证书必须真校验通过，不用跳过）
    let tls_cfg = rfp_client::tls::rustls_client_config(Some(&fingerprint)).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let name = rustls::pki_types::ServerName::try_from("app.example.com").unwrap();
    let body = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let Ok(tcp) = TcpStream::connect(("127.0.0.1", https_port)).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let Ok(mut tls) = connector.connect(name.clone(), tcp).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let req = "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n";
            if tls.write_all(req.as_bytes()).await.is_err() {
                continue;
            }
            let mut out = Vec::new();
            let _ = tls.read_to_end(&mut out).await;
            let resp = String::from_utf8_lossy(&out).to_string();
            if resp.contains("tls-side") {
                return resp;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("HTTPS vhost 请求始终未成功");
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");

    std::fs::remove_dir_all(dir).ok();
}

/// h2c（prior knowledge）访客：Host 来自 `:authority`，必须被补回转发头。
///
/// 2026-10-12 真实链路验收发现的缺陷：同一个 TLS 监听，curl 走 h1.1 时 origin
/// 能收到 Host，协商到 h2 就丢了（h2 没有 Host 头，authority 在伪头里）。
#[tokio::test]
async fn vhost_http2_authority_becomes_host() {
    let (origin_port, seen) = spawn_http_origin("h2-ok").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(18900).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));

    let body = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let Ok(tcp) = TcpStream::connect(("127.0.0.1", http_port)).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            // h2c：明文上的 HTTP/2（prior knowledge）
            let Ok((mut sender, conn)) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                hyper_util::rt::TokioIo::new(tcp),
            )
            .await
            else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            tokio::spawn(async move {
                let _ = conn.await;
            });
            // h2 的 authority 来自 URI，而不是 Host 头
            let req = hyper::Request::builder()
                .method("GET")
                .uri("http://app.example.com/")
                .body(http_body_util::Empty::<hyper::body::Bytes>::new())
                .unwrap();
            let Ok(resp) = sender.send_request(req).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let status = resp.status();
            let bytes = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).to_string();
            if status == 200 && text.contains("h2-ok") {
                return text;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("h2c vhost 请求始终未成功");

    assert!(body.contains("h2-ok"), "{body}");
    // 关键断言：origin 必须收到 Host
    let head = seen.lock().unwrap().clone().to_lowercase();
    assert!(
        head.contains("host: app.example.com"),
        "h2 访客的 Host 没有传到 origin:\n{head}"
    );
}

// ============================================================ S1 回归：体分帧（T111）

/// 可校验载荷：第 i 字节 = i % 251（逐字节可比）
fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// 大响应 origin：声明 `Content-Length: n`，分块写出（模拟真实大文件）
async fn spawn_big_origin(n: usize) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(payload(n));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                // 先读完请求头（不关心内容）
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                    body.len()
                );
                if s.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                for part in body.chunks(64 * 1024) {
                    if s.write_all(part).await.is_err() {
                        return;
                    }
                }
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

/// chunked 响应 origin（**不声明 Content-Length**）：响应的结束只能靠分块终止符
async fn spawn_chunked_origin(chunks: Vec<Vec<u8>>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let chunks = Arc::new(chunks);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            let chunks = Arc::clone(&chunks);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                if s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                for c in chunks.iter() {
                    let framed = format!("{:x}\r\n", c.len());
                    if s.write_all(framed.as_bytes()).await.is_err()
                        || s.write_all(c).await.is_err()
                        || s.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
                let _ = s.flush().await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

/// 走 vhost 明文端口取回完整响应（字节级，不做 UTF-8 假设）
async fn vhost_request_raw(port: u16, host: &str, path: &str) -> Vec<u8> {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return Vec::new();
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).await.is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    out
}

/// 拆出 (响应头原文, 响应体)
fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("响应缺少头体分隔，收到 {} 字节", raw.len()));
    (
        String::from_utf8_lossy(&raw[..pos]).to_string(),
        raw[pos + 4..].to_vec(),
    )
}

/// 解 chunked 编码：响应体长度未知时 hyper 会用分块编码发给访客
fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&rest[..pos]).to_string();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap().trim(), 16)
            .unwrap_or_else(|e| panic!("分块长度非法 {size_line:?}: {e}"));
        rest = &rest[pos + 2..];
        if size == 0 {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    out
}

/// T111：大响应必须逐字节完整送达（8 MiB，体分帧回归）。
///
/// 2026-10-12 真实链路验收发现大响应被静默截断（8 MiB 只到 7.8 MiB，64 MiB 只到
/// 63.5 MiB）：服务端在请求体泵完就半关闭，客户端写完后无法判断对端是否读完，
/// 一关 socket 内核就以 RST 丢掉在途尾部（research D11 的 F3）。修法是把体改成
/// 显式分帧 + 关序。回环上跑不出 RST，但这条用例锁定「体不再依赖半关闭 / EOF，
/// 长度与内容逐字节一致」——这也是 M1/M2 两条承载共用的数据面契约。
#[tokio::test]
async fn vhost_large_response_not_truncated() {
    const N: usize = 8 * 1024 * 1024;

    let origin_port = spawn_big_origin(N).await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(19000).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));

    let raw = tokio::time::timeout(Duration::from_secs(60), async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let raw = vhost_request_raw(http_port, "app.example.com", "/big").await;
            if raw.starts_with(b"HTTP/1.1 200") {
                return raw;
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "vhost 请求始终未命中，最后一次收到 {} 字节",
                    raw.len()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("8 MiB 响应超时");

    let (head, body) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        body.len(),
        N,
        "响应体长度不符（截断）：收到 {} / 期望 {N}",
        body.len()
    );
    assert!(body == payload(N), "响应体内容不一致（尾部被截断或错位）");
}

/// 单次探测：连上代理端口并回读一轮
async fn echo_once(remote_port: u16, payload: &[u8]) -> bool {
    let Ok(mut c) = TcpStream::connect(("127.0.0.1", remote_port)).await else {
        return false;
    };
    if c.write_all(payload).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut buf)).await,
        Ok(Ok(n)) if n == payload.len()
    ) && buf == payload
}

/// T116（F5 回归）：单个代理注册失败不得拖垮整个会话。
///
/// 一个客户端注册两个 tcp 代理，其中坏的那个用系统临时端口（legacy 模式必然被拒）。
/// 原实现把该失败当成会话级 Retry：整条控制连接断开重连，好代理每 5 秒陪跑掉线
/// 一次且永不收敛（2026-10-12 真实链路验收发现）。现在应为：坏代理不上线并在日志
/// 给出原因，好代理持续可用。
#[tokio::test]
async fn one_bad_proxy_does_not_kill_session() {
    let echo_port = spawn_echo().await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    tokio::spawn(serve(srv_listener, test_server_config(srv_port, "secret")));

    let good_port = safe_port(17200).await;
    let mk = |name: &str, port: u16| ProxyConfig {
        name: name.into(),
        proxy_type: ProxyType::Tcp,
        local_addr: format!("127.0.0.1:{echo_port}"),
        remote_port: Some(port),
        custom_domains: vec![],
        subdomain: None,
        local_tls: LocalTlsConfig::default(),
    };
    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![
            mk("good", good_port),
            // 32768 落在系统临时端口区间：legacy 模式必然拒绝
            mk("bad", 32768),
        ],
        tls: plain_client_tls(),
    }));

    wait_proxy_and_echo(good_port).await;

    // 跨越一个重连周期（RECONNECT_INTERVAL = 5s）持续探测：好代理不应出现任何失败。
    // 原实现会在坏代理注册失败后 5s 断开整条会话，这里必然抓到。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        assert!(
            echo_once(good_port, b"still-up").await,
            "好代理被坏代理的注册失败拖下线了"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// T115（F4 回归）：注册期插进来的 `NewConnection` 不得被当成异常应答断开会话。
///
/// 场景：客户端同时注册一个 vhost 代理与一个「注册必然失败」的 tcp 代理。失败代理
/// 在客户端侧会占用一段重试窗口，这期间的访客请求命中已注册的 vhost，服务端就会在
/// 控制通道里插一条 `NewConnection`——原实现把这条消息判成"异常应答"并断开整条控制
/// 连接，会话反复重启（表现为 vhost 间歇性 404）。现在应按正常数据连接接管，
/// 探测期间不允许出现任何失败。
#[tokio::test]
async fn new_connection_during_registration_is_handled() {
    let (origin_port, _seen) = spawn_http_origin("reg-race-ok").await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(17300).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
        transport: Transport::Tcp,
        token: "secret".into(),
        proxies: vec![
            ProxyConfig {
                name: "web".into(),
                proxy_type: ProxyType::Http,
                local_addr: format!("127.0.0.1:{origin_port}"),
                remote_port: None,
                custom_domains: vec!["app.example.com".into()],
                subdomain: None,
                local_tls: LocalTlsConfig::default(),
            },
            // 注册必失败（临时端口区间），把客户端卡在注册重试窗口里
            ProxyConfig {
                name: "bad".into(),
                proxy_type: ProxyType::Tcp,
                local_addr: format!("127.0.0.1:{origin_port}"),
                remote_port: Some(32768),
                custom_domains: vec![],
                subdomain: None,
                local_tls: LocalTlsConfig::default(),
            },
        ],
        tls: plain_client_tls(),
    }));

    let ok = vhost_get_until_ok(http_port, "app.example.com", "/").await;
    assert!(ok.contains("reg-race-ok"), "{ok}");

    // 覆盖失败代理的注册重试窗口（3 次尝试 × 1s 间隔）：会话不得重启
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let resp = vhost_request(http_port, "app.example.com", "/").await;
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "注册期插入的 NewConnection 打断了会话: {resp}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// T111：无 Content-Length 的响应靠 EOB 帧收尾（不再靠隧道 EOF）。
///
/// origin 用 chunked 编码应答，hyper 解码后只把裸体交给 vhost 网关——网关这一侧
/// 已经看不到分块终止符，体结束只能来自显式分帧的 EOB。原实现用「半关闭 = 结束」
/// 表达这件事，本用例锁住新契约。
#[tokio::test]
async fn vhost_chunked_response_completes() {
    let chunks = vec![
        payload(1024),
        payload(3000),
        payload(7),
    ];
    let expect: Vec<u8> = chunks.iter().flatten().copied().collect();

    let origin_port = spawn_chunked_origin(chunks).await;
    let srv_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();
    let http_port = safe_port(19100).await;
    tokio::spawn(serve(
        srv_listener,
        vhost_server_config(srv_port, Some(http_port), None, vec![]),
    ));
    tokio::spawn(run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    )));

    let raw = tokio::time::timeout(Duration::from_secs(30), async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let raw = vhost_request_raw(http_port, "app.example.com", "/chunked").await;
            if raw.starts_with(b"HTTP/1.1 200") {
                return raw;
            }
            if tokio::time::Instant::now() > deadline {
                panic!("chunked vhost 请求始终未命中，最后一次收到 {} 字节", raw.len());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("chunked 响应超时");

    let (head, body) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // 长度未知 → 访客侧响应是分块编码，先解码再比对
    let body = decode_chunked(&body);
    assert_eq!(body.len(), expect.len(), "chunked 响应体长度不符: {head}");
    assert!(body == expect, "chunked 响应体内容不一致: {head}");
}
