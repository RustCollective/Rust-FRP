//! 端到端：echo 服务 → rfps → rfpc → 隧道访问。

use std::time::Duration;

use rfp_client::config::{ClientConfig, ProxyConfig, TlsConfig as ClientTls};
use rfp_client::{run_once, RunError};
use rfp_common::msg::ProxyType;
use rfp_server::config::{ServerConfig, TlsConfig as ServerTls, UserConfig};
use rfp_server::{serve};
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
        },
    ));

    let remote_port = safe_port(16300).await;
    tokio::spawn(run_once(ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port: srv_port,
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
        },
    ));

    let res = tokio::time::timeout(
        Duration::from_secs(10),
        run_once(ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port: srv_port,
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
