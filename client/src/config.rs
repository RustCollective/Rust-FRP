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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: ProxyType,
    /// 本地服务地址，如 127.0.0.1:22
    pub local_addr: String,
    /// 服务端暴露端口。tcp/udp 必填；http/https 必须缺省（域名型代理不占用公网端口）
    #[serde(default)]
    pub remote_port: Option<u16>,
    /// 自定义域名（http/https），对齐 frp 的 `customDomains`
    #[serde(default)]
    pub custom_domains: Vec<String>,
    /// 子域名标签（http/https），需服务端配置 `subdomain_host`
    #[serde(default)]
    pub subdomain: Option<String>,
    /// 客户端到本地服务这一跳的 TLS（S1；FR-010）
    #[serde(default)]
    pub local_tls: LocalTlsConfig,
}

/// 客户端 → 本地服务 的 TLS 设置（与隧道 TLS 相互独立）
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTlsConfig {
    /// 默认 false，即按明文 HTTP 访问本地服务
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub verify: LocalTlsVerify,
    /// `verify = "fingerprint"` 时必填（hex，本地服务证书的 SHA256）
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTlsVerify {
    /// 系统根证书校验（默认）
    #[default]
    System,
    /// 跳过校验（自签内网服务；启用时日志以 warn 提示）
    Skip,
    /// 指纹固定
    Fingerprint,
}

impl ClientConfig {
    /// 启动期配置校验（S1）。
    ///
    /// 不合法即拒绝启动，而不是等到注册时才失败——契约见
    /// `specs/001-frp-parity/contracts/config-vhost.md` §2.3。
    pub fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for p in &self.proxies {
            if !names.insert(p.name.as_str()) {
                return Err(format!("代理名重复: {}", p.name));
            }
            p.validate()?;
        }
        Ok(())
    }
}

impl ProxyConfig {
    /// 单个代理的启动期校验
    fn validate(&self) -> Result<(), String> {
        let ctx = || format!("代理 `{}`", self.name);
        let is_web = matches!(self.proxy_type, ProxyType::Http | ProxyType::Https);
        let has_domain = !self.custom_domains.is_empty() || self.subdomain.is_some();

        if is_web {
            if self.remote_port.is_some() {
                return Err(format!(
                    "{}：http/https 类型不占用公网端口，remote_port 必须留空",
                    ctx()
                ));
            }
            if !has_domain {
                return Err(format!(
                    "{}：http/https 类型必须声明 custom_domains 或 subdomain",
                    ctx()
                ));
            }
        } else {
            if has_domain {
                return Err(format!(
                    "{}：{} 类型不支持 custom_domains / subdomain",
                    ctx(),
                    type_name(self.proxy_type)
                ));
            }
            if self.remote_port.is_none() {
                return Err(format!(
                    "{}：{} 类型必须声明 remote_port",
                    ctx(),
                    type_name(self.proxy_type)
                ));
            }
        }

        if self.remote_port == Some(0) {
            return Err(format!(
                "{}：remote_port 不能为 0（自动分配端口尚未支持）",
                ctx()
            ));
        }

        if let Some(sub) = &self.subdomain {
            if sub.is_empty() || sub.contains('.') {
                return Err(format!("{}：subdomain `{sub}` 必须是单个不含点的标签", ctx()));
            }
        }

        if self.local_tls.enabled && !is_web {
            return Err(format!(
                "{}：local_tls 仅对 http/https 类型有意义",
                ctx()
            ));
        }
        if self.local_tls.enabled
            && self.local_tls.verify == LocalTlsVerify::Fingerprint
            && self.local_tls.fingerprint.is_none()
        {
            return Err(format!(
                "{}：local_tls.verify = \"fingerprint\" 时必须提供 fingerprint",
                ctx()
            ));
        }
        Ok(())
    }
}

fn type_name(t: ProxyType) -> &'static str {
    match t {
        ProxyType::Tcp => "tcp",
        ProxyType::Udp => "udp",
        ProxyType::Http => "http",
        ProxyType::Https => "https",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_str: &str) -> Result<ClientConfig, String> {
        toml::from_str::<ClientConfig>(toml_str).map_err(|e| e.to_string())
    }

    /// 既有（M1/M2）配置必须零改动继续可用
    #[test]
    fn legacy_tcp_proxy_still_valid() {
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
"#,
        )
        .unwrap();
        assert_eq!(cfg.proxies[0].remote_port, Some(6022));
        assert!(cfg.proxies[0].custom_domains.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn http_proxy_requires_domain_and_no_port() {
        // 合法：只给域名
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
custom_domains = ["app.example.com"]
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());

        // 合法：只给 subdomain
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
subdomain = "app"
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());

        // 非法：http 占用端口
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
remote_port = 8080
custom_domains = ["app.example.com"]
"#,
        )
        .unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("remote_port"), "{err}");

        // 非法：http 既无域名也无 subdomain
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
"#,
        )
        .unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("custom_domains"), "{err}");
    }

    #[test]
    fn tcp_proxy_rejects_domain_fields() {
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
custom_domains = ["app.example.com"]
"#,
        )
        .unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("custom_domains"), "{err}");

        // 缺 remote_port 也拒绝
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
"#,
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("remote_port"));
    }

    #[test]
    fn subdomain_label_and_local_tls_rules() {
        // subdomain 必须是单个标签
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
subdomain = "a.b"
"#,
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("subdomain"));

        // local_tls 用在 tcp 上被拒
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
[proxies.local_tls]
enabled = true
"#,
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("local_tls"));

        // verify = fingerprint 缺指纹被拒
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "https"
local_addr = "127.0.0.1:8443"
custom_domains = ["app.example.com"]
[proxies.local_tls]
enabled = true
verify = "fingerprint"
"#,
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("fingerprint"));

        // 合法：https + local_tls 指纹
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "https"
local_addr = "127.0.0.1:8443"
custom_domains = ["app.example.com"]
[proxies.local_tls]
enabled = true
verify = "fingerprint"
fingerprint = "aa11"
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());
    }

    /// F6 回归（客户端侧）：未知 / 拼错的键当场报错，不静默按默认值跑
    #[test]
    fn unknown_or_misplaced_key_is_rejected() {
        let err = parse(
            r#"
server_addr = "1.2.3.4"
server_prot = 7000
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
"#,
        )
        .unwrap_err();
        assert!(err.contains("server_prot"), "错误信息未点名问题键: {err}");

        // 代理段的键写错位置（放到根级）同样报错
        let err = parse(
            r#"
server_addr = "1.2.3.4"
local_addr = "127.0.0.1:22"
[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 6022
"#,
        )
        .unwrap_err();
        assert!(err.contains("local_addr"), "错误信息未点名问题键: {err}");
    }

    #[test]
    fn duplicate_proxy_names_rejected() {
        let cfg = parse(
            r#"
server_addr = "1.2.3.4"
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3000"
custom_domains = ["a.example.com"]
[[proxies]]
name = "web"
type = "http"
local_addr = "127.0.0.1:3001"
custom_domains = ["b.example.com"]
"#,
        )
        .unwrap();
        assert!(cfg.validate().unwrap_err().contains("重复"));
    }
}
