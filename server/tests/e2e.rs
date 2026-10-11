//! 端到端：echo 服务 → rfps → rfpc → 隧道访问。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rfp_client::config::{
    ClientConfig, LocalTlsConfig, ProxyConfig, TlsConfig as ClientTls, Transport,
};
use rfp_client::{quic_endpoint, run_once, run_quic_once, RunError};
use rfp_common::msg::ProxyType;

use rfp_server::config::{
    CertEntry, QuicConfig, ServerConfig, TlsConfig as ServerTls, UserConfig, VhostListener,
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
    let allowed = client(61005).proxies[0].remote_port.unwrap();
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

    // 授权范围外：注册被拒
    let outside = safe_port(16200).await;
    let res = tokio::time::timeout(Duration::from_secs(10), run_once(client(outside)))
        .await
        .expect("timeout");
    match res {
        Err(RunError::Retry(e)) => assert!(
            e.to_string().contains("授权范围"),
            "unexpected error: {e}"
        ),
        other => panic!("expect retry error, got: {other:?}"),
    }

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
    let err = run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web2",
        origin_port,
        vec!["app.example.com".into()],
    ))
    .await
    .expect_err("同域名注册应被拒绝");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("app.example.com"),
        "拒绝原因未指明冲突域名: {msg}"
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

    let err = run_once(vhost_client_config(
        srv_port,
        ProxyType::Http,
        "web",
        origin_port,
        vec!["app.example.com".into()],
    ))
    .await
    .expect_err("未配置 [http] 时注册应被拒绝");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("[http] bind_port"),
        "拒绝原因未指明缺少的监听段: {msg}"
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
    let err = run_once(client_for("evil.example.com"))
        .await
        .expect_err("越权域名应被拒绝");
    let msg = format!("{err:?}");
    assert!(msg.contains("evil.example.com"), "拒绝原因未指明域名: {msg}");

    // 授权范围内的域名：注册成功且可访问
    tokio::spawn(run_once(client_for("app.alice.dev")));
    let resp = vhost_get_until_ok(http_port, "app.alice.dev", "/").await;
    assert!(resp.contains("alice-page"), "{resp}");
}
