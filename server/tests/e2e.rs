//! 端到端：echo 服务 → rfps → rfpc → 隧道访问。

use std::time::Duration;

use rfp_client::config::{ClientConfig, ProxyConfig, TlsConfig as ClientTls, Transport};
use rfp_client::{quic_endpoint, run_once, run_quic_once, RunError};
use rfp_common::msg::ProxyType;
use rfp_server::config::{
    QuicConfig, ServerConfig, TlsConfig as ServerTls, UserConfig,
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
            remote_port,
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
            remote_port,
        }],
        tls: plain_client_tls(),
    };

    // 授权范围内：注册成功 + 转发可用
    let allowed = client(61005).proxies[0].remote_port;
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
            remote_port,
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
            remote_port,
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
            remote_port,
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
