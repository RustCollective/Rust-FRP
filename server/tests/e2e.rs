//! 端到端：echo 服务 → rfps → rfpc → 隧道访问。

use std::time::Duration;

use rfp_client::config::{ClientConfig, ProxyConfig};
use rfp_client::{run_once, RunError};
use rfp_common::msg::ProxyType;
use rfp_server::config::UserConfig;
use rfp_server::{serve, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
        }),
    )
    .await
    .expect("timeout");
    assert!(matches!(res, Err(RunError::Fatal(_))));
}
