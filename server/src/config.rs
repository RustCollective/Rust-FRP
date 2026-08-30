//! rfps 配置。

use serde::Deserialize;

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 监听地址（控制/数据连接与代理端口共用）
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub bind_port: u16,
    /// 认证 token；空 = 不认证
    #[serde(default)]
    pub token: String,
}
