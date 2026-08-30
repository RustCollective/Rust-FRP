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
}
