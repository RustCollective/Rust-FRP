//! server 侧 TLS：证书加载/自动生成 + acceptor 构建。
//!
//! 默认自签：未配置 cert/key 时自动生成并落盘到工作目录
//! （`rfps-auto-cert.der` / `rfps-auto-key.der`），重启复用，
//! fingerprint 稳定供 client pinning。

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;

pub const AUTO_CERT: &str = "rfps-auto-cert.der";
pub const AUTO_KEY: &str = "rfps-auto-key.der";

#[derive(Clone)]
pub struct TlsSetup {
    pub acceptor: tokio_rustls::TlsAcceptor,
    /// 叶子证书 SHA256 fingerprint（hex，供 client pinning）
    pub fingerprint: String,
}

/// 生成自签证书（CN = rust-frp，无 SAN——只用 fingerprint pinning，不做域名验证）
pub fn generate_self_signed() -> Result<(CertificateDer<'static>, Vec<u8>)> {
    let ck = rcgen::generate_simple_self_signed(vec!["rust-frp".into()])
        .context("生成自签证书失败")?;
    let cert = ck.cert.der().clone();
    let key = ck.key_pair.serialize_der();
    Ok((cert, key))
}

/// 加载（路径存在）或生成并落盘
fn load_or_generate(cert_path: Option<&str>, key_path: Option<&str>) -> Result<(CertificateDer<'static>, Vec<u8>, PathBuf, PathBuf)> {
    let (cpath, kpath) = match (cert_path, key_path) {
        (Some(c), Some(k)) => (c.to_string(), k.to_string()),
        (None, None) => (AUTO_CERT.into(), AUTO_KEY.into()),
        _ => return Err(anyhow!("tls.cert 与 tls.key 必须同时配置或同时省略")),
    };
    let (cpath, kpath) = (Path::new(&cpath), Path::new(&kpath));
    if cpath.exists() && kpath.exists() {
        let cert = std::fs::read(cpath).with_context(|| format!("读取证书 {}", cpath.display()))?;
        let key = std::fs::read(kpath).with_context(|| format!("读取私钥 {}", kpath.display()))?;
        let cert = CertificateDer::from(cert);
        let key = PrivateKeyDer::try_from(key)
            .map_err(|e| anyhow!("解析私钥失败: {e}"))?;
        return Ok((cert, key.secret_der().to_vec(), cpath.into(), kpath.into()));
    }
    if cert_path.is_some() {
        return Err(anyhow!(
            "指定了证书路径但文件不存在: {} / {}",
            cpath.display(),
            kpath.display()
        ));
    }
    // 自动生成并落盘（下次启动复用，fingerprint 稳定）
    let (cert, key) = generate_self_signed()?;
    std::fs::write(cpath, cert.as_ref())
        .with_context(|| format!("写入 {}", cpath.display()))?;
    std::fs::write(kpath, &key).with_context(|| format!("写入 {}", kpath.display()))?;
    tracing::info!(cert = %cpath.display(), key = %kpath.display(), "自动生成自签证书");
    Ok((cert, key, cpath.into(), kpath.into()))
}

/// 构建 TLS acceptor；打印 fingerprint
pub fn setup(cert_path: Option<&str>, key_path: Option<&str>) -> Result<TlsSetup> {
    let (cert, key, cpath, _kpath) = load_or_generate(cert_path, key_path)?;
    let fingerprint = rfp_common::sha256_hex(cert.as_ref());
    let key = PrivateKeyDer::try_from(key).map_err(|e| anyhow!("解析私钥失败: {e}"))?;
    let cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| anyhow!("TLS 配置失败: {e}"))?;
    tracing::info!(
        fingerprint = %fingerprint,
        cert_file = %cpath.display(),
        "TLS 就绪（client 配置 server_fingerprint = \"{fingerprint}\"）"
    );
    Ok(TlsSetup {
        acceptor: tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg)),
        fingerprint,
    })
}
