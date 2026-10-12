//! 面向本地服务的 HTTP 转发（S1）。
//!
//! 承载契约见 `specs/001-frp-parity/contracts/rfp1-http-vhost.md` §3：
//! 请求元数据（M1 来自控制通道的 `new_connection`、M2 来自数据流首帧的
//! `conn_init`）之后是**按帧承载的请求体**（`N 个长度前缀体帧 + 0 长度 EOB 帧`）；
//! 客户端回写时以 `http_response_meta` 作为该方向的**第一条消息**，随后是同样
//! 分帧的响应体。体结束由 EOB 帧表达，不用半关闭（research D11）。
//!
//! 全程流式：请求体由隧道读端按帧驱动 hyper 客户端的请求体（容量 1 的通道，
//! 背压一路传到访客），不落地、不聚合（FR-011、SC-007）。

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::header::{HeaderName, HeaderValue, CONTENT_LENGTH};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rfp_common::frame::{read_frame, write_frame, MAX_FRAME};
use rfp_common::msg::{HttpInit, Message};
use rfp_common::BoxedStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::config::{LocalTlsConfig, LocalTlsVerify, ProxyConfig};

/// UDP 数据报读取缓冲：UDP 理论最大载荷 65507，取 64 KiB 足够
const DATAGRAM_MAX: usize = 64 * 1024;

/// 体帧的单帧载荷上限：帧协议允许 64 KiB，实现取 16 KiB
/// （与服务端 `vhost::proxy` 保持一致，背压粒度更细）
const BODY_CHUNK: usize = 16 * 1024;

/// 关序等待上限：写完响应后等对端读完并关闭隧道（服务端读完响应即关闭）
const CLOSE_WAIT: Duration = Duration::from_secs(30);

/// 隧道的请求元数据 → 本地服务 → 响应回写。
///
/// `stream` 是已就绪的隧道（M1 回连连接 / M2 bi-stream），元数据帧已由调用方读完；
/// `init` 是随元数据下发的 method / path / headers。
///
/// 体是**显式分帧**的（`N 个长度前缀体帧 + 0 长度 EOB 帧`，契约 §3.3）：
/// 请求体读到 EOB 才结束，响应体写完补 EOB，**不靠半关闭表达体结束**。
/// 写完响应后还要等读方向结束（服务端读完响应并关闭隧道）才释放 socket——
/// 否则内核会用 RST 丢掉在途数据（research D11 的 F3）。
pub async fn forward_http<S>(
    conn_id: u64,
    proxy: &ProxyConfig,
    init: &HttpInit,
    stream: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let local_addr = proxy.local_addr.clone();
    let (rd, mut wr) = tokio::io::split(stream);

    // 1. 请求体：由独立任务按帧读取，经容量 1 的通道交给 hyper。
    //
    //    容量 1 是有意的：它把「隧道读」与「本地服务消费」耦合起来，形成端到端
    //    背压（不引入无界缓冲，FR-011、SC-007）。请求体读到 EOB 后该任务继续把
    //    读方向排空到 EOF——服务端读完响应才会关闭隧道，这就是关序确认。
    let (tx, rx) = mpsc::channel::<Bytes>(1);
    let reader = tokio::spawn(read_body_frames(rd, tx));

    // 2. 拨号本地服务（隧道 TLS 与本地 TLS 是两跳，策略独立）
    let tcp = TcpStream::connect(local_addr.as_str())
        .await
        .with_context(|| format!("连接本地服务 {local_addr} 失败"))?;
    let _ = tcp.set_nodelay(true);
    let io: BoxedStream = if proxy.local_tls.enabled {
        let connector = local_tls_connector(&proxy.local_tls)?;
        let (host, _) = local_addr
            .rsplit_once(':')
            .unwrap_or((local_addr.as_str(), ""));
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("本地服务地址 `{host}` 不能作为 TLS 服务器名: {e}"))?;
        Box::new(connector.connect(name, tcp).await?)
    } else {
        Box::new(tcp)
    };

    // 3. 请求行与请求头由服务端经隧道元数据下发，这里只负责还原成 h1 请求
    let mut builder = Request::builder();
    for (name, value) in &init.headers {
        match (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            (Ok(n), Ok(v)) => builder = builder.header(n, v),
            _ => debug!(conn_id, header = %name, "请求头无法表示，已丢弃"),
        }
    }
    let length = content_length(&init.headers);
    let req = builder
        .method(init.method.as_str())
        .uri(init.path.as_str())
        .body(ChannelBody::new(rx, length))
        .with_context(|| format!("构造本地请求 {} {} 失败", init.method, init.path))?;

    // 4. h1 客户端连本地服务
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("与本地服务完成 HTTP/1.1 握手失败")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "本地 h1 连接结束");
        }
    });

    let resp = sender.send_request(req).await.context("本地服务请求失败")?;

    // 5. 响应元数据必须是客户端方向的第一条消息
    let (parts, body) = resp.into_parts();
    let headers = strip_hop_by_hop(&parts.headers);
    let meta = Message::HttpResponseMeta {
        conn_id,
        status: parts.status.as_u16(),
        headers,
    };
    write_frame(&mut wr, &meta.encode())
        .await
        .context("回写响应元数据失败")?;

    // 6. 响应体流式分帧回写，最后补 0 长度 EOB 帧表达体结束
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.context("读取本地服务响应体失败")?;
        let Some(chunk) = frame.data_ref() else { continue };
        for part in chunk.chunks(BODY_CHUNK) {
            write_frame(&mut wr, part).await.context("回写响应体失败")?;
        }
    }
    write_frame(&mut wr, &[])
        .await
        .context("写入响应体结束帧失败")?;
    // 关掉写方向（对端仍可继续读），随后等它读完并关闭隧道
    let _ = wr.shutdown().await;

    // 7. 关序：服务端读完响应（读到 EOB）后才会关闭隧道并把剩余字节排空，
    //    这里等它——提前释放 socket 会以 RST 丢掉尚未送达的尾部（F3）。
    match tokio::time::timeout(CLOSE_WAIT, reader).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!(conn_id, error = %e, "请求体读取任务异常结束"),
        Err(_) => warn!(conn_id, "等待服务端读完响应超时，隧道将直接释放"),
    }
    Ok(())
}

/// 按帧读取请求体，交给 hyper 的请求体消费。
///
/// 读到 0 长度帧（EOB）即请求体结束，随后**继续把读方向排空到 EOF**：
/// 服务端读完响应、关闭隧道后这里才会返回，这个「读到结束」就是响应已送达的
/// 确认（契约 §3.3 的关序约束）。本地服务提前应答（不再消费请求体）时同样转入
/// 排空——带着未读数据关闭 socket 会让内核发 RST，把在途响应丢掉。
async fn read_body_frames<S>(mut rd: tokio::io::ReadHalf<S>, tx: mpsc::Sender<Bytes>)
where
    S: AsyncRead + Unpin,
{
    loop {
        match read_frame(&mut rd).await {
            Ok(f) if f.is_empty() => break, // EOB：请求体结束
            Ok(f) => {
                if tx.send(Bytes::from(f)).await.is_err() {
                    // 消费方已退出（本地服务提前应答）
                    break;
                }
            }
            Err(e) => {
                debug!(error = %e, "读取请求体帧失败");
                return; // 隧道已断，无需排空
            }
        }
    }
    drop(tx); // 请求体结束：让 hyper 看到 body 结束而不是继续等
    drain_until_eof(rd).await;
}

/// 把读方向排空到 EOF / 错误为止（不做解析，只消费字节）
async fn drain_until_eof<S>(mut rd: tokio::io::ReadHalf<S>)
where
    S: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4096];
    while let Ok(n) = rd.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
}

/// UDP 代理的转发：每个会话一个本地 UDP socket，隧道内数据报保持边界（S2）。
///
/// 承载见 `specs/001-frp-parity/research.md` D10：一条会话对应一条隧道流，
/// 流内每个数据报是一个 RFP/1 长度前缀帧——与请求/响应元数据帧同一套编解码，
/// 不引入新的协议层。
pub async fn forward_udp<S>(proxy: &ProxyConfig, stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let local = tokio::net::UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("绑定本地 UDP socket 失败")?;
    local
        .connect(proxy.local_addr.as_str())
        .await
        .with_context(|| format!("连接本地 UDP 服务 {} 失败", proxy.local_addr))?;

    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf = vec![0u8; DATAGRAM_MAX];

    // 本地 → 隧道
    let up = async {
        // 零长数据报是合法的：`while let Ok` 不会把它当成结束
        while let Ok(n) = local.recv(&mut buf).await {
            // 与 server 侧同款防御：超上限明确丢弃并告警，不截断（FR-016）
            if n > MAX_FRAME {
                warn!(len = n, "数据报超出单帧上限，已丢弃（不截断）");
                continue;
            }
            if write_frame(&mut wr, &buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };
    // 隧道 → 本地
    let down = async {
        while let Ok(payload) = read_frame(&mut rd).await {
            if local.send(&payload).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

/// 按 `local_tls` 配置构建到本地服务的 TLS connector
fn local_tls_connector(cfg: &LocalTlsConfig) -> Result<TlsConnector> {
    let config = match cfg.verify {
        LocalTlsVerify::System => crate::tls::rustls_client_config(None)?,
        LocalTlsVerify::Fingerprint => {
            crate::tls::rustls_client_config(cfg.fingerprint.as_deref())?
        }
        LocalTlsVerify::Skip => {
            warn!("local_tls.verify = \"skip\"：不校验本地服务证书");
            crate::tls::rustls_insecure_config()
        }
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// hyper 请求体：消费请求体帧通道，通道关闭（EOB 到达）即体结束。
///
/// 通道是容量 1 的有界通道——`read_body_frames` 因此不会跑在本地服务前面，
/// 隧道层的背压一路传到访客（FR-011、SC-007）。
struct ChannelBody {
    rx: mpsc::Receiver<Bytes>,
    /// 已知的内容长度（来自元数据里的 `content-length`）。
    ///
    /// 给出确切长度能让 hyper 用 Content-Length 而非 chunked 编码发往本地服务——
    /// 部分简易 origin（如 `python3 -m http.server`）不认 chunked。
    expected: Option<u64>,
    done: bool,
}

impl ChannelBody {
    fn new(rx: mpsc::Receiver<Bytes>, expected: Option<u64>) -> Self {
        Self {
            rx,
            expected,
            done: false,
        }
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.done || this.expected == Some(0) {
            return Poll::Ready(None);
        }
        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(chunk)) => {
                if let Some(rest) = this.expected.as_mut() {
                    *rest = rest.saturating_sub(chunk.len() as u64);
                }
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            // 通道关闭 = 读到 EOB，请求体结束
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.expected {
            Some(n) => SizeHint::with_exact(n),
            None => SizeHint::default(),
        }
    }
}

/// 从元数据结构里取出内容长度（若有）
pub fn content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .and_then(|(_, v)| v.parse::<u64>().ok())
}

// ---------------------------------------------------------------- 头处理
//
// 与服务端 `vhost::proxy` 的同名实现保持一致。两处各有自己的依赖边界
// （server 侧经 hyper 的 HeaderMap，client 侧经协议里的有序列表），
// 因此不强行合并到 common——common 不依赖 hyper。

/// 逐跳头：不能带到本地服务
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

/// 是否逐跳头
pub fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// 剥离逐跳头与 `Connection` 点名的扩展头，重复头逐个保留
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
            Err(_) => debug!(header = %n, "响应头值非 ASCII，已丢弃"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_parsed_from_meta() {
        let h = vec![
            ("host".to_string(), "app.example.com".to_string()),
            ("content-length".to_string(), "1234".to_string()),
        ];
        assert_eq!(content_length(&h), Some(1234));
        // 大小写不敏感
        let h = vec![("Content-Length".to_string(), "7".to_string())];
        assert_eq!(content_length(&h), Some(7));
        // 缺失或非法
        assert_eq!(content_length(&[]), None);
        let h = vec![("content-length".to_string(), "abc".to_string())];
        assert_eq!(content_length(&h), None);
    }

    #[test]
    fn response_hop_by_hop_is_stripped() {
        let mut m = hyper::HeaderMap::new();
        m.append(
            HeaderName::from_bytes(b"connection").unwrap(),
            HeaderValue::from_str("close, x-extra").unwrap(),
        );
        m.append(
            HeaderName::from_bytes(b"x-extra").unwrap(),
            HeaderValue::from_str("drop-me").unwrap(),
        );
        m.append(
            HeaderName::from_bytes(b"content-type").unwrap(),
            HeaderValue::from_str("text/html").unwrap(),
        );
        let out = strip_hop_by_hop(&m);
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"content-type"));
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"x-extra"));
    }
}
