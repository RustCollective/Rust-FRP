//! 帧编解码：u32 大端长度前缀 + payload，单帧上限 64 KiB。
//!
//! 控制通道用 `Framed`（读侧 cancel-safe，适配 select!）；
//! 数据连接首帧用手工 `read_frame`/`write_frame`，避免 `Framed`
//! 内部读缓冲残留导致透传字节丢失。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_stream::StreamExt;
pub use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::msg::{Message, ParseError};

/// 单帧 payload 上限
pub const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
}

/// 控制通道类型
pub type Control<T> = Framed<T, LengthDelimitedCodec>;

/// 包装为控制通道（读走 `Framed`，写经底层流手工组帧，二者线上格式一致）
pub fn control_framed<T: AsyncRead + AsyncWrite>(io: T) -> Control<T> {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME)
        .new_framed(io)
}

/// 手工写一帧（u32 大端长度前缀 + payload）
pub async fn write_frame<W: AsyncWrite + Unpin>(
    io: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame exceeds 64 KiB",
        ));
    }
    io.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    io.write_all(payload).await?;
    io.flush().await
}

/// 手工读一帧（数据连接首帧用）
pub async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds 64 KiB",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

/// 控制通道发送一条消息
pub async fn send_msg<T: AsyncRead + AsyncWrite + Unpin>(
    framed: &mut Control<T>,
    msg: &Message,
) -> Result<(), FrameError> {
    write_frame(framed.get_mut(), &msg.encode()).await?;
    Ok(())
}

/// 控制通道接收一条消息；`Ok(None)` 表示对端关闭
pub async fn recv_msg<T: AsyncRead + AsyncWrite + Unpin>(
    framed: &mut Control<T>,
) -> Result<Option<Message>, FrameError> {
    match framed.next().await {
        None => Ok(None),
        Some(Ok(buf)) => Ok(Some(Message::parse(&buf)?)),
        Some(Err(e)) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_frame(&mut a, b"hello").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn oversize_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn framed_reads_manual_format() {
        // 手工写的帧必须能被 Framed 读出（控制通道写路径绕开了 codec 编码器）
        let (mut a, b) = tokio::io::duplex(4096);
        let payload = br#"{"type":"ping","ts":1}"#;
        write_frame(&mut a, payload).await.unwrap();
        let mut framed = control_framed(b);
        let buf = framed.next().await.unwrap().unwrap();
        assert_eq!(&buf[..], payload);
    }
}
