//! frpc 配置。

use rfp_common::msg::ProxyType;
use serde::Deserialize;

fn default_server_port() -> u16 {
    7000
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址（IP 或域名）
    pub server_addr: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default)]
    pub token: String,
    pub proxies: Vec<ProxyConfig>,
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
