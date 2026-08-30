//! RFP/1 控制消息定义。
//!
//! 控制消息以 JSON 编码，`type` 字段作为判别标签；
//! 未知字段忽略（向后兼容），未知 `type` / 格式错误统一按解析错误处理，
//! 由调用方决定回 Error 还是断开。

use serde::{Deserialize, Serialize};

/// 协议版本（主.次），主号不一致即拒绝
pub const VERSION: &str = "1.0";

/// 代理类型。M1 仅实现 TCP。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyType {
    Tcp,
    Udp,
    Http,
    Https,
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
    },
    /// S→C 注册结果
    RegisterProxyAck {
        name: String,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// S→C 通知 client 建立数据连接（仅 M1）
    NewConnection { conn_id: u64, proxy_name: String },
    /// 数据连接首帧，标识归属
    ConnInit { conn_id: u64, proxy_name: String },
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
            },
            Message::NewConnection { conn_id: 42, proxy_name: "ssh".into() },
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
}
