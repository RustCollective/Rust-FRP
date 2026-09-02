//! frpc 配置。

use rfp_common::msg::ProxyType;
use serde::Deserialize;

fn default_server_port() -> u16 {
    7000
}

/// 控制通道传输方式（M2 起支持 QUIC）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址（IP 或域名）
    pub server_addr: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    /// 传输方式：tcp（M1，默认）或 quic（M2，server 需开启 [quic]）
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub token: String,
    pub proxies: Vec<ProxyConfig>,
    /// TLS 配置（默认开启）
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// 默认 true；false = 明文模式（不推荐，仅调试用）
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// server 证书 SHA256 fingerprint（hex，自签场景 pinning 用）
    #[serde(default)]
    pub server_fingerprint: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            server_fingerprint: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    /// 本地服务地址，如 127.0.0.1:22
    pub local_addr: String,
    /// 服务端暴露端口
    pub remote_port: u16,
}
