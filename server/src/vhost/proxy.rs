//! vhost 网关的请求处理：路由 → 隧道 → 流式双向管道（S1）。
//!
//! 契约见 `specs/001-frp-parity/contracts/rfp1-http-vhost.md`。
//!
//! 关键约束：
//! - 请求体 / 响应体全程流式，**不整体缓冲**（FR-011、SC-007）；
//! - 元数据帧必须是各方向在数据流上的第一条消息（契约 §3.3）；
//! - 逐跳头两个方向都剥离，转发头只追加不覆盖（FR-004、FR-005）。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rfp_common::frame::{read_frame, MAX_FRAME};
use rfp_common::msg::{HttpInit, Message, ProxyType};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::state::{BoxedStream, ServerState, SessionHandle};
use crate::vhost::certs::{self, CertTable};
use crate::vhost::router;

/// 等响应元数据的上限（客户端要拨号 + 拿到本地服务的响应头）
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// 逐跳头：两个方向都必须剥离，不能原样透传（FR-004）
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// 响应体类型：错误响应为空体，正常转发是隧道流
pub type ResBody = UnsyncBoxBody<Bytes, std::io::Error>;

// ---------------------------------------------------------------- 监听装配

/// 启动 vhost 明文 HTTP 监听（h1 与 h2c 自动协商）。
///
/// 不设 hyper 的 timer：auto::Builder 的 http1 子构建器按值消耗自身，
/// 无法在 auto 路径上配置。缺 timer 只影响空闲连接的超时回收，不影响正确性。
pub async fn run_http(state: Arc<ServerState>, addr: String) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr.as_str()).await?;
    info!(addr = %listener.local_addr()?, "vhost http listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "vhost http accept error");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move {
                    Ok::<_, Infallible>(handle(state, req, peer, "http", ProxyType::Http).await)
                }
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), service).await {
                debug!(%peer, error = %e, "vhost http connection error");
            }
        });
    }
}

/// 启动 vhost TLS 监听：按 SNI 选证书终止后，同一套路由与转发（FR-003）
pub async fn run_https(
    state: Arc<ServerState>,
    addr: String,
    table: Arc<CertTable>,
) -> anyhow::Result<()> {
    let config = certs::server_config(table)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let listener = TcpListener::bind(addr.as_str()).await?;
    info!(addr = %listener.local_addr()?, "vhost https listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "vhost https accept error");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                // SNI 未命中证书表会在这里失败：不回落默认证书
                Err(e) => {
                    debug!(%peer, error = %e, "vhost tls handshake failed");
                    return;
                }
            };
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move {
                    Ok::<_, Infallible>(handle(state, req, peer, "https", ProxyType::Https).await)
                }
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(TokioIo::new(tls), service).await {
                debug!(%peer, error = %e, "vhost https connection error");
            }
        });
    }
}

// ---------------------------------------------------------------- 请求处理

/// 单次请求：按 Host / `:authority` 路由，未命中返回 404 且不回落
async fn handle(
    state: Arc<ServerState>,
    req: Request<Incoming>,
    peer: SocketAddr,
    proto: &'static str,
    kind: ProxyType,
) -> Response<ResBody> {
    let Some(host) = request_host(&req) else {
        debug!("请求缺少 Host / :authority，无法路由");
        return plain(StatusCode::BAD_REQUEST);
    };
    let hit = {
        let registry = state.registry.lock().await;
        router::lookup(&registry, &host, kind)
    };
    let Some(hit) = hit else {
        debug!(%host, kind = ?kind, "域名未命中，返回 404");
        return plain(StatusCode::NOT_FOUND);
    };
    bridge(state, hit.session, hit.proxy_name, req, peer, proto, kind).await
}

/// 取请求主机名：优先 `Host` 头（h1），其次 URI 的 authority（h2）
fn request_host(req: &Request<Incoming>) -> Option<String> {
    if let Some(h) = req.headers().get(hyper::header::HOST) {
        if let Ok(s) = h.to_str() {
            return Some(s.to_string());
        }
    }
    req.uri().authority().map(|a| a.to_string())
}

/// 建立隧道并把请求/响应两侧桥接起来
#[allow(clippy::too_many_arguments)]
async fn bridge(
    state: Arc<ServerState>,
    session: Arc<SessionHandle>,
    proxy_name: String,
    req: Request<Incoming>,
    peer: SocketAddr,
    proto: &'static str,
    kind: ProxyType,
) -> Response<ResBody> {
    let (parts, body) = req.into_parts();

    let mut headers = strip_hop_by_hop(&parts.headers);
    append_forwarded(&mut headers, &peer.ip().to_string(), proto);
    let init = HttpInit {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "/".into()),
        version: format!("{:?}", parts.version),
        headers,
    };

    let conn_id = state.next_conn_id();
    // 元数据帧不得超过 64 KiB：超限回 4xx，且不断开控制通道（契约 §3.3）
    let probe = Message::ConnInit {
        conn_id,
        proxy_name: proxy_name.clone(),
        http: Some(init.clone()),
    }
    .encode();
    if probe.len() > MAX_FRAME {
        warn!(
            conn_id,
            proxy = %proxy_name,
            size = probe.len(),
            "请求元数据超出帧上限，拒绝本次转发"
        );
        return plain(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    let Some(tunnel) =
        crate::session::open_tunnel(&state, &session, conn_id, &proxy_name, Some(init)).await
    else {
        warn!(conn_id, proxy = %proxy_name, "隧道建立失败，返回 502");
        return plain(StatusCode::BAD_GATEWAY);
    };

    let (mut rd, wr) = tokio::io::split(tunnel);
    // 请求体泵：读完即半关闭，客户端据此判定请求结束
    let pump = tokio::spawn(pump_request(body, wr));

    // 响应元数据必须是客户端方向的第一条消息
    let first = match tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(&mut rd)).await {
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => {
            debug!(conn_id, error = %e, "读取响应元数据失败");
            pump.abort();
            return plain(StatusCode::BAD_GATEWAY);
        }
        Err(_) => {
            debug!(conn_id, "等待响应元数据超时");
            pump.abort();
            return plain(StatusCode::BAD_GATEWAY);
        }
    };
    let (status, resp_headers) = match Message::parse(&first) {
        Ok(Message::HttpResponseMeta { status, headers, .. }) => (status, headers),
        other => {
            debug!(conn_id, frame = ?other, "响应首帧不是 http_response_meta");
            pump.abort();
            return plain(StatusCode::BAD_GATEWAY);
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (n, v) in resp_headers {
        if is_hop_by_hop(&n) {
            continue;
        }
        match (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(&v)) {
            (Ok(name), Ok(val)) => builder = builder.header(name, val),
            _ => debug!(conn_id, header = %n, "响应头无法表示，已丢弃"),
        }
    }

    let body = TunnelBody { rd, pump };
    match builder.body(UnsyncBoxBody::new(body)) {
        Ok(resp) => {
            info!(conn_id, proxy = %proxy_name, kind = ?kind, %peer, "vhost 转发完成头处理");
            resp
        }
        Err(e) => {
            debug!(conn_id, error = %e, "构造响应失败");
            plain(StatusCode::BAD_GATEWAY)
        }
    }
}

/// 空体响应（400 / 404 / 4xx / 502）
fn plain(status: StatusCode) -> Response<ResBody> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .expect("构建空响应不会失败")
}

/// 空请求体
fn empty_body() -> ResBody {
    UnsyncBoxBody::new(Empty::<Bytes>::new().map_err(|e: Infallible| match e {}))
}

/// 把请求体逐块写进隧道，读完即半关闭。
///
/// **不能整体缓冲**：1GB 上传会把服务端内存撑爆（FR-011、SC-007）。
async fn pump_request(mut body: Incoming, mut wr: tokio::io::WriteHalf<BoxedStream>) {
    loop {
        match body.frame().await {
            None => break,
            Some(Ok(f)) => {
                if let Some(chunk) = f.data_ref() {
                    if wr.write_all(chunk).await.is_err() {
                        break;
                    }
                }
            }
            Some(Err(e)) => {
                debug!(error = %e, "读取请求体失败");
                break;
            }
        }
    }
    let _ = wr.shutdown().await;
}

/// 把隧道读端包成 hyper 的响应体：逐块读取，不缓冲整包。
///
/// 持有请求泵的句柄，响应结束时一并取消——否则客户端提前应答时，
/// 泵会卡在一个没人读的隧道写端上。
struct TunnelBody {
    rd: tokio::io::ReadHalf<BoxedStream>,
    pump: tokio::task::JoinHandle<()>,
}

impl Body for TunnelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let mut buf = [0u8; 16 * 1024];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        match Pin::new(&mut this.rd).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(filled)))))
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        // 长度未知：让 hyper 用分块编码，内容长度以客户端给出的响应头为准
        SizeHint::default()
    }
}

impl Drop for TunnelBody {
    fn drop(&mut self) {
        self.drain();
    }
}

impl TunnelBody {
    /// 响应结束：停掉请求泵（握手的另一半不该继续等一个没人读的对端）
    fn drain(&self) {
        self.pump.abort();
    }
}

// ---------------------------------------------------------------- 头处理

/// 是否逐跳头
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// 把 hyper 的头转成有序 `(name, value)` 列表，剥离逐跳头与 `Connection` 点名的扩展头。
///
/// 重复头逐个保留（`Set-Cookie` 等不可合并）；`HeaderMap` 的迭代顺序不是线上顺序，
/// 协议层只保证「不合并、不丢弃」，不承诺复现 wire order。
pub fn strip_hop_by_hop(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    let mut conn_listed: Vec<String> = Vec::new();
    for v in headers.get_all(hyper::header::CONNECTION).iter() {
        if let Ok(s) = v.to_str() {
            conn_listed.extend(
                s.split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty()),
            );
        }
    }
    let mut out = Vec::new();
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&n) || conn_listed.iter().any(|c| c == &n) {
            continue;
        }
        match value.to_str() {
            Ok(v) => out.push((n, v.to_string())),
            Err(_) => debug!(header = %n, "头值非 ASCII，已丢弃"),
        }
    }
    out
}

/// 追加转发头。`x-forwarded-for` 只在已有值后追加，不覆盖——
/// 访客可能已经过一层 CDN，覆盖会丢失真实链路（research.md D7）。
pub fn append_forwarded(headers: &mut Vec<(String, String)>, peer_ip: &str, proto: &str) {
    match headers.iter_mut().find(|(n, _)| n == "x-forwarded-for") {
        Some((_, v)) => {
            v.push_str(", ");
            v.push_str(peer_ip);
        }
        None => headers.push(("x-forwarded-for".into(), peer_ip.into())),
    }
    if !headers.iter().any(|(n, _)| n == "x-forwarded-proto") {
        headers.push(("x-forwarded-proto".into(), proto.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut m = hyper::HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let m = hm(&[
            ("host", "app.example.com"),
            ("connection", "keep-alive, x-custom-hop"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("te", "trailers"),
            ("x-custom-hop", "should-be-dropped"),
            ("accept", "*/*"),
        ]);
        let out = strip_hop_by_hop(&m);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"host"));
        assert!(names.contains(&"accept"));
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"keep-alive"));
        assert!(!names.contains(&"transfer-encoding"));
        assert!(!names.contains(&"upgrade"));
        assert!(!names.contains(&"te"));
        // Connection 点头的扩展头也必须剥离
        assert!(!names.contains(&"x-custom-hop"), "{names:?}");
    }

    #[test]
    fn duplicate_headers_are_preserved() {
        let m = hm(&[("set-cookie", "a=1"), ("set-cookie", "b=2")]);
        let out = strip_hop_by_hop(&m);
        let cookies: Vec<&str> = out
            .iter()
            .filter(|(n, _)| n == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies.len(), 2, "{out:?}");
        assert!(cookies.contains(&"a=1") && cookies.contains(&"b=2"));
    }

    #[test]
    fn forwarded_headers_append_not_overwrite() {
        // 无既有值时新建
        let mut h = vec![("host".to_string(), "app.example.com".to_string())];
        append_forwarded(&mut h, "203.0.113.7", "https");
        assert_eq!(
            h.iter().find(|(n, _)| n == "x-forwarded-for").unwrap().1,
            "203.0.113.7"
        );
        assert_eq!(
            h.iter().find(|(n, _)| n == "x-forwarded-proto").unwrap().1,
            "https"
        );

        // 已有值时追加（访客可能已经过一层 CDN）
        let mut h = vec![("x-forwarded-for".to_string(), "198.51.100.1".to_string())];
        append_forwarded(&mut h, "203.0.113.7", "http");
        assert_eq!(
            h.iter().find(|(n, _)| n == "x-forwarded-for").unwrap().1,
            "198.51.100.1, 203.0.113.7"
        );
        // 只追加一次
        assert_eq!(h.iter().filter(|(n, _)| n == "x-forwarded-for").count(), 1);
    }

    #[test]
    fn forwarded_proto_is_not_duplicated() {
        let mut h = vec![("x-forwarded-proto".to_string(), "https".to_string())];
        append_forwarded(&mut h, "203.0.113.7", "http");
        assert_eq!(h.iter().filter(|(n, _)| n == "x-forwarded-proto").count(), 1);
        assert_eq!(
            h.iter().find(|(n, _)| n == "x-forwarded-proto").unwrap().1,
            "https"
        );
    }
}
