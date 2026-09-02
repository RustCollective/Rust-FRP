//! QUIC 传输公共设施：ALPN 常量与双向流封装。
//!
//! quinn 的 `SendStream`/`RecvStream` 分别实现 AsyncWrite/AsyncRead，
//! 此处合并为单一 `QuicStream`，使既有帧协议与 `copy_bidirectional`
//! 桥接代码在 TCP/TLS/QUIC 之间完全复用。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::{RecvStream, SendStream};

/// QUIC 握手 ALPN；TCP/TLS 路径不校验（M1 兼容）
pub const ALPN: &[u8] = b"rfp/1";

/// QUIC 双向流（open_bi/accept_bi 的两个半流合并）
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl From<(SendStream, RecvStream)> for QuicStream {
    fn from((send, recv): (SendStream, RecvStream)) -> Self {
        Self { send, recv }
    }
}

impl tokio::io::AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        <RecvStream as tokio::io::AsyncRead>::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <SendStream as tokio::io::AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <SendStream as tokio::io::AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <SendStream as tokio::io::AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
