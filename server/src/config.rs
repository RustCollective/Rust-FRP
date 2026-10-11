//! rfps 配置。

use std::collections::HashSet;
use std::sync::Arc;

use serde::Deserialize;

use crate::state::{AuthPolicy, UserAuth};

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 监听地址（控制/数据连接与代理端口共用）
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub bind_port: u16,
    /// 全局 token（向后兼容；配置了 [[users]] 时忽略）
    #[serde(default)]
    pub token: String,
    /// 每用户授权表；非空时启用用户认证模式
    #[serde(default)]
    pub users: Vec<UserConfig>,
    /// TLS 配置（默认开启；关闭需显式声明）
    #[serde(default)]
    pub tls: TlsConfig,
    /// QUIC 传输（M2；默认关闭，显式开启）
    #[serde(default)]
    pub quic: QuicConfig,
    /// vhost 明文 HTTP 监听（S1；缺省不启用）
    #[serde(default)]
    pub http: Option<VhostListener>,
    /// vhost TLS 监听（S1；缺省不启用）
    #[serde(default)]
    pub https: Option<VhostListener>,
    /// 子域名后缀（S1）：配置后客户端只声明 `subdomain` 标签即可注册
    #[serde(default)]
    pub subdomain_host: Option<String>,
    /// 域名证书表（S1）：未列出的 SNI 一律拒绝握手
    #[serde(default)]
    pub certs: Vec<CertEntry>,
}

/// vhost 监听段（`[http]` / `[https]`）
#[derive(Debug, Clone, Deserialize)]
pub struct VhostListener {
    pub bind_port: u16,
    /// 缺省复用全局 `bind_addr`
    #[serde(default)]
    pub bind_addr: Option<String>,
}

impl VhostListener {
    /// 实际监听地址
    pub fn addr(&self, default_bind: &str) -> String {
        self.bind_addr
            .clone()
            .unwrap_or_else(|| default_bind.to_string())
    }
}

/// 域名证书项（`[[certs]]`）
#[derive(Debug, Clone, Deserialize)]
pub struct CertEntry {
    /// 域名，支持 `*.example.com` 通配；匹配语义由 rustls 决定
    pub domain: String,
    /// 证书链 PEM 路径
    pub cert: String,
    /// 私钥 PEM 路径
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// 默认 true；false = 明文模式（不推荐，仅调试用）
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 证书/私钥路径（DER 或 PEM）；缺省时自动生成自签并落盘
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            cert: None,
            key: None,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct QuicConfig {
    /// 默认 false；QUIC 需要安全组额外放行 UDP
    #[serde(default)]
    pub enabled: bool,
    /// QUIC UDP 监听端口；缺省复用 bind_port
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_port: Option<u16>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self { enabled: false, bind_port: None }
    }
}

impl ServerConfig {
    /// QUIC 实际监听端口（缺省复用 TCP bind_port，UDP/TCP 端口号不冲突）
    pub fn quic_port(&self) -> u16 {
        self.quic.bind_port.unwrap_or(self.bind_port)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub name: String,
    pub token: String,
    /// 端口授权：`"6000-6100"` 区间或 `"65533"` 单端口
    #[serde(default)]
    pub ports: Vec<String>,
    /// vhost 授权：`"a.example.com"` 精确或 `"*.alice.dev"` 通配
    #[serde(default)]
    pub vhosts: Vec<String>,
}

impl ServerConfig {
    /// 构建认证策略；校验端口表达式与重复项
    pub fn auth_policy(&self) -> Result<AuthPolicy, String> {
        if self.users.is_empty() {
            return Ok(if self.token.is_empty() {
                AuthPolicy::Open
            } else {
                AuthPolicy::Legacy(self.token.clone())
            });
        }
        let mut users = Vec::with_capacity(self.users.len());
        let mut tokens = HashSet::new();
        let mut names = HashSet::new();
        for u in &self.users {
            if u.token.is_empty() {
                return Err(format!("用户 `{}` 的 token 为空", u.name));
            }
            if !names.insert(u.name.clone()) {
                return Err(format!("用户名重复: {}", u.name));
            }
            if !tokens.insert(u.token.clone()) {
                return Err(format!("用户 `{}` 的 token 与其他用户重复", u.name));
            }
            let mut ports = Vec::with_capacity(u.ports.len());
            for spec in &u.ports {
                let r = parse_port_range(spec)
                    .map_err(|e| format!("用户 `{}` 端口配置 `{spec}` 无效: {e}", u.name))?;
                ports.push(r);
            }
            users.push(Arc::new(UserAuth {
                name: u.name.clone(),
                token: u.token.clone(),
                ports,
                vhosts: u.vhosts.clone(),
            }));
        }
        Ok(AuthPolicy::Users(users))
    }
}

/// "6000-6100" | "65533" → (lo, hi)
fn parse_port_range(spec: &str) -> Result<(u16, u16), String> {
    let parse = |s: &str| {
        s.trim()
            .parse::<u16>()
            .map_err(|_| "非法端口数字".to_string())
    };
    if let Some((lo, hi)) = spec.split_once('-') {
        let (lo, hi) = (parse(lo)?, parse(hi)?);
        if lo > hi {
            return Err("起点大于终点".into());
        }
        Ok((lo, hi))
    } else {
        let p = parse(spec)?;
        Ok((p, p))
    }
}

impl ServerConfig {
    /// 启动期结构校验（S1）。
    ///
    /// 证书文件的加载与「证书/私钥配对」校验在 `vhost::certs` 中完成（那里才有
    /// PEM 解析能力），两者共同构成 `contracts/config-vhost.md` §1.3 的启动期校验。
    pub fn validate(&self) -> Result<(), String> {
        if self.https.is_some() && self.certs.is_empty() {
            return Err("[https] 已启用但 [[certs]] 为空：TLS 监听没有可用证书".into());
        }
        // 监听端口互斥（同一端口无法同时承载控制面与 vhost 网关）
        let mut ports = HashSet::new();
        ports.insert(self.bind_port);
        if let Some(h) = &self.http {
            if !ports.insert(h.bind_port) {
                return Err(format!("[http] bind_port {} 与已有监听端口冲突", h.bind_port));
            }
        }
        if let Some(h) = &self.https {
            if !ports.insert(h.bind_port) {
                return Err(format!(
                    "[https] bind_port {} 与已有监听端口冲突",
                    h.bind_port
                ));
            }
        }
        // 证书域名：归一化后非空、不重复，且路径非空
        let mut domains = HashSet::new();
        for c in &self.certs {
            let d = crate::state::normalize_host(&c.domain);
            if d.is_empty() {
                return Err("[[certs]] 的 domain 不能为空".into());
            }
            if !domains.insert(d.clone()) {
                return Err(format!("[[certs]] 域名重复: {d}"));
            }
            if c.cert.is_empty() || c.key.is_empty() {
                return Err(format!("[[certs]] `{d}` 的 cert / key 路径不能为空"));
            }
        }
        if let Some(sub) = &self.subdomain_host {
            let d = crate::state::normalize_host(sub);
            if d.is_empty() || d.contains('*') {
                return Err(format!(
                    "subdomain_host `{sub}` 无效：必须是具体域名，不支持通配"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_parse() {
        assert_eq!(parse_port_range("6000").unwrap(), (6000, 6000));
        assert_eq!(parse_port_range("6000-6100").unwrap(), (6000, 6100));
        assert_eq!(parse_port_range(" 42 - 43 ").unwrap(), (42, 43));
        assert!(parse_port_range("6100-6000").is_err());
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("0-70000").is_err());
        assert!(parse_port_range("").is_err());
    }

    #[test]
    fn policy_fallback() {
        // 无用户表：Open / Legacy
        let cfg = toml::from_str::<ServerConfig>("bind_port = 7000").unwrap();
        assert!(matches!(cfg.auth_policy().unwrap(), AuthPolicy::Open));
        let cfg = toml::from_str::<ServerConfig>("bind_port = 7000\ntoken = \"t\"").unwrap();
        assert!(matches!(cfg.auth_policy().unwrap(), AuthPolicy::Legacy(_)));
    }

    #[test]
    fn policy_users_validation() {
        let cfg = toml::from_str::<ServerConfig>(
            r#"
bind_port = 7000
[[users]]
name = "alice"
token = "a"
ports = ["6000-6100", "6200"]
vhosts = ["*.alice.dev"]
"#,
        )
        .unwrap();
        match cfg.auth_policy().unwrap() {
            AuthPolicy::Users(users) => {
                assert_eq!(users.len(), 1);
                assert!(users[0].allows_port(6000));
                assert!(users[0].allows_port(6200));
                assert!(users[0].allows_vhost("x.alice.dev"));
            }
            _ => panic!("expect Users policy"),
        }
        // 重复 token 拒绝
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\n[[users]]\nname=\"a\"\ntoken=\"t\"\n[[users]]\nname=\"b\"\ntoken=\"t\"\n",
        )
        .unwrap();
        assert!(cfg.auth_policy().is_err());
        // 空 token 拒绝
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\n[[users]]\nname=\"a\"\ntoken=\"\"\n",
        )
        .unwrap();
        assert!(cfg.auth_policy().is_err());
    }

    /// S1：vhost 段与证书表的启动期校验
    #[test]
    fn vhost_startup_validation() {
        // [https] 启用但证书表为空 → 拒绝
        let cfg =
            toml::from_str::<ServerConfig>("bind_port = 7000\n[https]\nbind_port = 8443\n").unwrap();
        assert!(cfg.validate().unwrap_err().contains("certs"));

        // [http] 明文监听不需要证书
        let cfg =
            toml::from_str::<ServerConfig>("bind_port = 7000\n[http]\nbind_port = 8080\n").unwrap();
        assert!(cfg.validate().is_ok());

        // 端口冲突：[http] 与 bind_port 同端口
        let cfg =
            toml::from_str::<ServerConfig>("bind_port = 7000\n[http]\nbind_port = 7000\n").unwrap();
        assert!(cfg.validate().unwrap_err().contains("冲突"));

        // 端口冲突：[http] 与 [https] 同端口
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\n[http]\nbind_port = 8080\n[https]\nbind_port = 8080\n\
             [[certs]]\ndomain = \"a.example.com\"\ncert = \"/tmp/a.crt\"\nkey = \"/tmp/a.key\"\n",
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("冲突"));

        // 证书域名重复（大小写归一化后同形）
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\n[https]\nbind_port = 8443\n\
             [[certs]]\ndomain = \"A.example.com\"\ncert = \"/tmp/a.crt\"\nkey = \"/tmp/a.key\"\n\
             [[certs]]\ndomain = \"a.example.com\"\ncert = \"/tmp/b.crt\"\nkey = \"/tmp/b.key\"\n",
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("重复"));

        // 证书路径为空
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\n[https]\nbind_port = 8443\n\
             [[certs]]\ndomain = \"a.example.com\"\ncert = \"\"\nkey = \"/tmp/a.key\"\n",
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("路径"));

        // subdomain_host 不支持通配
        let cfg =
            toml::from_str::<ServerConfig>("bind_port = 7000\nsubdomain_host = \"*.example.com\"\n")
                .unwrap();
        assert!(cfg.validate().unwrap_err().contains("subdomain_host"));

        // 合法：完整 vhost 配置
        let cfg = toml::from_str::<ServerConfig>(
            "bind_port = 7000\nsubdomain_host = \"example.com\"\n[http]\nbind_port = 8080\n\
             [https]\nbind_port = 8443\n\
             [[certs]]\ndomain = \"*.example.com\"\ncert = \"/tmp/w.crt\"\nkey = \"/tmp/w.key\"\n",
        )
        .unwrap();
        assert!(cfg.validate().is_ok());
    }
}
