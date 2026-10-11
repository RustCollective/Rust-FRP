//! RFP/1 控制消息定义。
//!
//! 控制消息以 JSON 编码，`type` 字段作为判别标签；
//! 未知字段忽略（向后兼容），未知 `type` / 格式错误统一按解析错误处理，
//! 由调用方决定回 Error 还是断开。

use serde::{Deserialize, Serialize};

/// 协议版本（主.次），主号不一致即拒绝
pub const VERSION: &str = "1.0";

/// 代理类型。M1 实现 TCP；S1 起实现 HTTP/HTTPS（域名路由）。
///
/// 实现 `Hash` 是给服务端的域名路由表用的：同一域名可以有 `http` 与 `https`
/// 两条独立代理（监听端口不同、证书不同），路由键因此是 `(类型, 域名)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyType {
    Tcp,
    Udp,
    Http,
    Https,
}

/// 请求元数据（S1）：服务端收到访客请求后把 HTTP 语义下发给客户端。
///
/// 承载位置见 `specs/001-frp-parity/contracts/rfp1-http-vhost.md` §3.1——
/// QUIC 路径随数据流首帧（`ConnInit.http`），TCP 路径随控制通道的
/// `NewConnection.http`。两种情况都保证「客户端开始读请求体之前必然到达」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpInit {
    /// 请求方法，原样透传
    pub method: String,
    /// 请求路径（含 query string）
    pub path: String,
    /// 协议版本：`HTTP/1.1` 或 `HTTP/2`
    pub version: String,
    /// **有序**请求头列表，保留重复头（不合并、不排序）。
    ///
    /// 已由服务端剥离逐跳头并追加 `x-forwarded-for` / `x-forwarded-proto`。
    pub headers: Vec<(String, String)>,
}

/// 控制通道消息
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// C→S 认证
    Hello {
        version: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    },
    /// S→C 认证通过
    HelloAck { version: String, session_id: String },
    /// C→S 注册代理
    RegisterProxy {
        name: String,
        proxy_type: ProxyType,
        local_addr: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vhost: Option<String>,
        /// S1 新增：多域名（与 `vhost` 取并集，次号演进，缺省为空）
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        vhosts: Vec<String>,
        /// S1 新增：子域名标签（需服务端配置 `subdomain_host`）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subdomain: Option<String>,
    },
    /// S→C 注册结果
    RegisterProxyAck {
        name: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// S→C 通知 client 建立数据连接（仅 M1）
    NewConnection {
        conn_id: u64,
        proxy_name: String,
        /// S1 新增：HTTP 类型代理的请求元数据（M1 路径承载位置）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http: Option<HttpInit>,
    },
    /// 数据连接首帧，标识归属
    ConnInit {
        conn_id: u64,
        proxy_name: String,
        /// S1 新增：HTTP 类型代理的请求元数据（M2 路径承载位置）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http: Option<HttpInit>,
    },
    /// S1 新增：响应元数据（C→S），数据流上 client 方向的第一条消息
    HttpResponseMeta {
        conn_id: u64,
        status: u16,
        /// **有序**响应头列表，已剥离逐跳头
        headers: Vec<(String, String)>,
    },
    /// 延迟统计用，连接活性由传输层负责
    Ping { ts: i64 },
    /// 回显 Ping 的 ts
    Pong { ts: i64 },
    /// 通用错误
    Error { code: String, message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing `type` field")]
    MissingType,
}

impl Message {
    /// 解析一帧控制消息
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let value: serde_json::Value = serde_json::from_slice(buf)?;
        match value.get("type").and_then(|v| v.as_str()) {
            Some(_) => serde_json::from_value(value).map_err(ParseError::Json),
            None => Err(ParseError::MissingType),
        }
    }

    /// 编码为 JSON 字节
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("json serialization cannot fail")
    }
}

/// 主号是否兼容
pub fn version_compatible(their: &str) -> bool {
    fn major(v: &str) -> &str {
        v.split('.').next().unwrap_or_default()
    }
    major(their) == major(VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let msgs = vec![
            Message::Hello {
                version: VERSION.into(),
                token: "secret".into(),
                hostname: Some("box".into()),
            },
            Message::RegisterProxy {
                name: "ssh".into(),
                proxy_type: ProxyType::Tcp,
                local_addr: "127.0.0.1:22".into(),
                remote_port: Some(6022),
                vhost: None,
                vhosts: vec![],
                subdomain: None,
            },
            Message::NewConnection {
                conn_id: 42,
                proxy_name: "ssh".into(),
                http: None,
            },
            Message::Error { code: "auth_failed".into(), message: "no".into() },
        ];
        for m in msgs {
            assert_eq!(Message::parse(&m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn unknown_type_is_error() {
        let buf = br#"{"type":"quantum_tunnel","x":1}"#;
        assert!(Message::parse(buf).is_err());
    }

    #[test]
    fn missing_type_is_error() {
        assert!(Message::parse(br#"{"ts":1}"#).is_err());
    }

    #[test]
    fn unknown_field_ignored() {
        let buf = br#"{"type":"ping","ts":123,"extra":true}"#;
        assert_eq!(Message::parse(buf).unwrap(), Message::Ping { ts: 123 });
    }

    #[test]
    fn version_check() {
        assert!(version_compatible("1.0"));
        assert!(version_compatible("1.9"));
        assert!(!version_compatible("2.0"));
        assert!(!version_compatible("garbage"));
    }

    /// S1：请求/响应元数据帧与控制消息的 roundtrip
    #[test]
    fn http_meta_roundtrip() {
        let http = HttpInit {
            method: "GET".into(),
            path: "/dash?tab=1".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("host".into(), "app.example.com".into()),
                ("x-forwarded-for".into(), "203.0.113.7".into()),
            ],
        };
        let msgs = vec![
            Message::ConnInit {
                conn_id: 7,
                proxy_name: "web".into(),
                http: Some(http.clone()),
            },
            Message::NewConnection {
                conn_id: 7,
                proxy_name: "web".into(),
                http: Some(http.clone()),
            },
            Message::HttpResponseMeta {
                conn_id: 7,
                status: 200,
                headers: vec![("content-type".into(), "text/html".into())],
            },
        ];
        for m in msgs {
            assert_eq!(Message::parse(&m.encode()).unwrap(), m);
        }
    }

    /// S1：头字段有序、重复头不合并、非 ASCII 值可往返
    #[test]
    fn http_init_header_order_and_duplicates() {
        let http = HttpInit {
            method: "POST".into(),
            path: "/".into(),
            version: "HTTP/2".into(),
            headers: vec![
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
                ("x-note".into(), "中文值".into()),
            ],
        };
        let m = Message::ConnInit {
            conn_id: 1,
            proxy_name: "web".into(),
            http: Some(http.clone()),
        };
        let back = Message::parse(&m.encode()).unwrap();
        assert_eq!(back, m);
        // 顺序与重复头都保留
        if let Message::ConnInit { http: Some(h), .. } = back {
            assert_eq!(h.headers, http.headers);
        } else {
            panic!("expected ConnInit with http meta");
        }
        // 空头列表也应可往返
        let empty = HttpInit {
            method: "HEAD".into(),
            path: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
        };
        let m = Message::ConnInit { conn_id: 2, proxy_name: "w".into(), http: Some(empty.clone()) };
        assert_eq!(Message::parse(&m.encode()).unwrap(), m);
    }

    /// S1：次号演进——不含新字段的旧格式报文必须仍可解析
    #[test]
    fn legacy_register_proxy_accepted() {
        let buf = br#"{"type":"register_proxy","name":"ssh","proxy_type":"tcp",
                      "local_addr":"127.0.0.1:22","remote_port":6022}"#;
        match Message::parse(buf).unwrap() {
            Message::RegisterProxy { name, vhosts, subdomain, vhost, .. } => {
                assert_eq!(name, "ssh");
                assert!(vhosts.is_empty());
                assert!(subdomain.is_none());
                assert!(vhost.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        // 不带 http 字段的旧格式 conn_init / new_connection 同样可解析
        let buf = br#"{"type":"conn_init","conn_id":1,"proxy_name":"ssh"}"#;
        match Message::parse(buf).unwrap() {
            Message::ConnInit { http, .. } => assert!(http.is_none()),
            other => panic!("unexpected: {other:?}"),
        }
        let buf = br#"{"type":"new_connection","conn_id":1,"proxy_name":"ssh"}"#;
        match Message::parse(buf).unwrap() {
            Message::NewConnection { http, .. } => assert!(http.is_none()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// S1：新增字段缺省时不序列化，保持报文紧凑且与旧端兼容
    #[test]
    fn optional_fields_are_skipped() {
        let m = Message::RegisterProxy {
            name: "web".into(),
            proxy_type: ProxyType::Http,
            local_addr: "127.0.0.1:3000".into(),
            remote_port: None,
            vhost: Some("app.example.com".into()),
            vhosts: vec![],
            subdomain: None,
        };
        let json = String::from_utf8(m.encode()).unwrap();
        assert!(!json.contains("vhosts"), "空的 vhosts 不应出现在报文里: {json}");
        assert!(!json.contains("subdomain"), "None 的 subdomain 不应出现在报文里: {json}");
        assert!(!json.contains("remote_port"), "None 的 remote_port 不应出现在报文里: {json}");
    }
}
