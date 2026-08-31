//! client 侧 TLS：fingerprint pinning 或系统根验证。
//!
//! - 配置 `server_fingerprint`：跳过链验证，直接比对叶子证书 SHA256（自签场景）
//! - 未配置：系统根验证（真证书场景；自签会失败并提示）

use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as crypto_ring;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio_rustls::TlsConnector;

fn ring_algs() -> WebPkiSupportedAlgorithms {
    crypto_ring::default_provider().signature_verification_algorithms
}

/// 握手签名验证（复刻 rustls webpki verifier 逻辑；
/// rustls 0.23.43 未公开 verify_tls12/13_signature 函数）
fn verify_handshake_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    let algs = ring_algs();
    // mapping: (scheme, &[algs])；匹配 scheme 的所有候选算法展平
    let possible: Vec<&dyn rustls_pki_types::SignatureVerificationAlgorithm> = algs
        .mapping
        .iter()
        .filter(|(scheme, _)| *scheme == dss.scheme)
        .flat_map(|(_, algs)| algs.iter())
        .copied()
        .collect();
    if possible.is_empty() {
        return Err(RustlsError::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let ee = webpki::EndEntityCert::try_from(cert)
        .map_err(|_| RustlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    for alg in possible {
        match ee.verify_signature(alg, message, dss.signature()) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)) => continue,
            Err(_) => {
                return Err(RustlsError::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                ))
            }
            Ok(()) => return Ok(HandshakeSignatureValid::assertion()),
        }
    }
    Err(RustlsError::InvalidCertificate(
        rustls::CertificateError::BadSignature,
    ))
}

/// fingerprint 固定校验器（自签证书场景）
#[derive(Debug)]
struct PinningVerifier {
    expected: Vec<u8>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let hash = rfp_common::sha256_hex(end_entity.as_ref());
        if hash.as_bytes() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            // 复用 NotValidForName 错误码；详细指纹差异通过 anyhow 层提示
            Err(RustlsError::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_handshake_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring_algs().supported_schemes()
    }
}

/// 构建 TLS connector。
///
/// `fingerprint`：SHA256 hex（可含冒号/大小写）；None 时用系统根验证。
pub fn connector(fingerprint: Option<&str>) -> Result<TlsConnector> {
    let builder = ClientConfig::builder();
    let cfg = match fingerprint.map(rfp_common::normalize_fingerprint) {
        Some(fp) if fp.len() == 64 => {
            let verifier = PinningVerifier {
                expected: fp.into_bytes(),
            };
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
        Some(_) => {
            return Err(anyhow!(
                "server_fingerprint 格式无效：应为 SHA256（64 个 hex 字符）"
            ))
        }
        None => builder
            .with_root_certificates(root_store())
            .with_no_client_auth(),
    };
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// 系统根证书（读常见 CA bundle；自签场景反正靠 pinning）
fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for path in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ] {
        if let Ok(pem) = std::fs::read_to_string(path) {
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut pem.as_bytes()).flatten().collect();
            for c in certs {
                let _ = roots.add(c);
            }
        }
    }
    roots
}
