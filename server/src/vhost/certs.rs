//! 按 SNI 选证书的 rustls 解析器（S1）。
//!
//! **未命中的 SNI 一律拒绝握手，不回落默认证书**——回落会让攻击者用任意域名
//! 探到不属于它的证书，也会掩盖配置错误（`research.md` D4）。
//!
//! 路由通配（`router::wildcard_match`）与证书通配在这里刻意共用同一套语义，
//! 但**两者相互独立**：证书只覆盖 `[[certs]]` 里声明过的域名，
//! 代理注册不会隐式获得证书。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::CertEntry;
use crate::state::normalize_host;
use crate::vhost::router::wildcard_match;

/// 内存证书表：归一化域名 → 证书 + 私钥
#[derive(Debug)]
pub struct CertTable {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
}

impl CertTable {
    /// 加载并校验 `[[certs]]`。任一项失败即返回错误（启动期拒绝启动，
    /// 契约 `contracts/config-vhost.md` §1.3）。
    pub fn load(entries: &[CertEntry]) -> Result<Self> {
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        for e in entries {
            let domain = normalize_host(&e.domain);
            let ck = Arc::new(load_one(&domain, &e.cert, &e.key)?);
            match domain.strip_prefix("*.") {
                Some(suffix) => {
                    wildcard.insert(suffix.to_string(), ck);
                }
                None => {
                    exact.insert(domain, ck);
                }
            }
        }
        Ok(Self { exact, wildcard })
    }

    /// 已加载的证书条目数（日志用）
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// 是否为空表
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 按 SNI 选证书：精确优先，其次通配（恰好一层左标签）
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = normalize_host(host);
        if host.is_empty() {
            return None;
        }
        if let Some(k) = self.exact.get(&host) {
            return Some(Arc::clone(k));
        }
        let (_, suffix) = host.split_once('.')?;
        if !wildcard_match(&host, suffix) {
            return None;
        }
        self.wildcard.get(suffix).map(Arc::clone)
    }
}

impl ResolvesServerCert for CertTable {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let hit = self.lookup(sni);
        if hit.is_none() {
            tracing::debug!(sni, "SNI 未命中证书表，拒绝握手");
        }
        hit
    }
}

/// 用证书表构建 rustls 服务端配置（ALPN 声明 h1 与 h2）
pub fn server_config(table: Arc<CertTable>) -> Result<Arc<rustls::ServerConfig>> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(table);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// 读取并校验一条证书项；失败信息里带上域名，便于定位是哪个 `[[certs]]`
fn load_one(domain: &str, cert_path: &str, key_path: &str) -> Result<CertifiedKey> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("读取证书失败（域名 {domain}）: {cert_path}"))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("读取私钥失败（域名 {domain}）: {key_path}"))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("解析证书 PEM 失败（域名 {domain}）: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("证书文件不含任何证书（域名 {domain}）: {cert_path}"));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| anyhow!("解析私钥 PEM 失败（域名 {domain}）: {e}"))?
        .ok_or_else(|| anyhow!("私钥文件不含可识别的私钥（域名 {domain}）: {key_path}"))?;

    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow!("私钥类型不受支持（域名 {domain}）: {e}"))?;

    let ck = CertifiedKey::new(certs, signing);
    // 证书与私钥是否配对：rustls 默认到握手时才报错，这里提前暴露配置问题
    ck.keys_match()
        .map_err(|e| anyhow!("证书与私钥不配对（域名 {domain}）: {e}"))?;
    Ok(ck)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成一对自签 PEM 落到临时目录，返回证书项
    fn self_signed(domain: &str, tag: &str) -> (CertEntry, std::path::PathBuf) {
        let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!("rfp-certs-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join(format!("{tag}.crt"));
        let key_path = dir.join(format!("{tag}.key"));
        std::fs::write(&cert_path, ck.cert.pem()).unwrap();
        std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
        (
            CertEntry {
                domain: domain.into(),
                cert: cert_path.display().to_string(),
                key: key_path.display().to_string(),
            },
            dir,
        )
    }

    #[test]
    fn loads_and_resolves_by_sni() {
        let (exact, d1) = self_signed("app.example.com", "exact");
        let (wild, d2) = self_signed("*.alice.dev", "wild");
        let table = CertTable::load(&[exact, wild]).unwrap();
        assert_eq!(table.len(), 2);

        // 精确命中 + 大小写/端口/末尾点归一化
        for host in ["app.example.com", "APP.example.com", "app.example.com:8443"] {
            assert!(table.lookup(host).is_some(), "host={host}");
        }
        // 通配命中恰好一层左标签
        assert!(table.lookup("x.alice.dev").is_some());
        assert!(table.lookup("alice.dev").is_none());
        assert!(table.lookup("a.b.alice.dev").is_none());
        // 未命中：不回落默认证书
        assert!(table.lookup("nope.example.com").is_none());
        assert!(table.lookup("").is_none());

        std::fs::remove_dir_all(d1).ok();
        std::fs::remove_dir_all(d2).ok();
    }

    #[test]
    fn rejects_missing_and_broken_files() {
        // 文件不存在
        let err = CertTable::load(&[CertEntry {
            domain: "a.example.com".into(),
            cert: "/nonexistent/a.crt".into(),
            key: "/nonexistent/a.key".into(),
        }])
        .unwrap_err();
        assert!(err.to_string().contains("读取证书失败"), "{err}");

        // 内容不是 PEM
        let dir = std::env::temp_dir().join(format!("rfp-certs-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.pem");
        std::fs::write(&bad, b"not a pem").unwrap();
        let err = CertTable::load(&[CertEntry {
            domain: "a.example.com".into(),
            cert: bad.display().to_string(),
            key: bad.display().to_string(),
        }])
        .unwrap_err();
        // 先撞上"证书文件不含任何证书"
        let msg = err.to_string();
        assert!(msg.contains("证书文件不含任何证书") || msg.contains("解析证书"), "{msg}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rejects_mismatched_key() {
        // 证书 A + 私钥 B：必须拒绝
        let (a, d1) = self_signed("a.example.com", "mis-a");
        let (b, d2) = self_signed("b.example.com", "mis-b");
        let err = CertTable::load(&[CertEntry {
            domain: "a.example.com".into(),
            cert: a.cert,
            key: b.key,
        }])
        .unwrap_err();
        assert!(err.to_string().contains("不配对"), "{err}");
        std::fs::remove_dir_all(d1).ok();
        std::fs::remove_dir_all(d2).ok();
    }
}
