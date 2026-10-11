//! UDP 代理（S2）：以「外部源地址 + 源端口」为会话键，会话内保持数据报边界。
//!
//! 承载见 `specs/001-frp-parity/research.md` D10：一条 UDP 会话对应一条隧道流，
//! 流内每个数据报用 RFP/1 既有的长度前缀帧承载（`u32 BE + payload`）——
//! 不引入新的编解码层，也不把 UDP 语义污染到控制通道。
//!
//! 两个方向的读写分别跑在独立任务里，再用 `select!` 汇合：隧道上的
//! `read_frame` 不是 cancel-safe（读到一半被取消会丢字节），不能直接放进
//! `select!` 的候选分支。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rfp_common::frame::{read_frame, write_frame, MAX_FRAME};
use rfp_common::now_ms;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::state::{ServerState, SessionHandle};

/// 单会话的出站队列上限：满了就丢包（UDP 本身可丢，不做无界堆积）
const SESSION_QUEUE: usize = 64;
/// 数据报读取缓冲：UDP 理论最大载荷 65507，取 64 KiB 足够
const DATAGRAM_MAX: usize = 64 * 1024;
/// 空闲检查的轮询间隔
const IDLE_TICK: Duration = Duration::from_secs(1);

/// UDP 代理的监听任务：绑定在 `socket` 上，按源地址分发到会话。
///
/// 返回值为 `()`；监听任务的存活由 `RegisteredProxy.listener` 的 abort 控制。
pub async fn serve(
    state: Arc<ServerState>,
    session: Arc<SessionHandle>,
    name: String,
    socket: Arc<UdpSocket>,
) {
    let idle_timeout = state.udp.idle_timeout;
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    // 会话结束时回报源地址，由本循环摘除表项——会话任务不持有表的所有权
    let (closed_tx, mut closed_rx) = mpsc::channel::<SocketAddr>(SESSION_QUEUE);
    let mut buf = vec![0u8; DATAGRAM_MAX];

    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(proxy = %name, error = %e, "udp recv error");
                        continue;
                    }
                };
                let payload = buf[..n].to_vec();
                match sessions.get(&src) {
                    Some(tx) => {
                        // 队列满即丢包：宁可丢也不无界堆积（UDP 语义允许）
                        if tx.try_send(payload).is_err() {
                            debug!(proxy = %name, %src, "udp 会话队列已满，丢包");
                        }
                    }
                    None => {
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(SESSION_QUEUE);
                        let _ = tx.try_send(payload);
                        sessions.insert(src, tx);
                        info!(proxy = %name, %src, "udp 会话建立");
                        let (st, se, sk, nm, closed) = (
                            Arc::clone(&state),
                            Arc::clone(&session),
                            Arc::clone(&socket),
                            name.clone(),
                            closed_tx.clone(),
                        );
                        tokio::spawn(async move {
                            run_session(st, se, nm, sk, src, idle_timeout, rx).await;
                            let _ = closed.send(src).await;
                        });
                    }
                }
            }
            Some(src) = closed_rx.recv() => {
                sessions.remove(&src);
                debug!(proxy = %name, %src, "udp 会话回收");
            }
        }
    }
}

/// 单条 UDP 会话：外部 ↔ 隧道双向搬运数据报
async fn run_session(
    state: Arc<ServerState>,
    session: Arc<SessionHandle>,
    name: String,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    idle_timeout: Duration,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    let conn_id = state.next_conn_id();
    let Some(tunnel) = crate::session::open_tunnel(&state, &session, conn_id, &name, None).await
    else {
        debug!(%peer, conn_id, "udp 会话取隧道失败");
        return;
    };
    let (mut rd, mut wr) = tokio::io::split(tunnel);
    let last_active = Arc::new(AtomicU64::new(now_ms() as u64));

    // 外部 → 隧道
    let up_active = Arc::clone(&last_active);
    let up_name = name.clone();
    let up = async move {
        while let Some(payload) = rx.recv().await {
            if payload.len() > MAX_FRAME {
                // 防御性分支：UDP 理论最大载荷 65507 小于 64 KiB 帧上限，
                // 正常路径到不了这里。明确丢弃并告警，绝不截断（FR-016）。
                warn!(
                    proxy = %up_name,
                    len = payload.len(),
                    "数据报超出单帧上限，已丢弃（不截断）"
                );
                continue;
            }
            if write_frame(&mut wr, &payload).await.is_err() {
                break;
            }
            up_active.store(now_ms() as u64, Ordering::Relaxed);
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut wr).await;
    };

    // 隧道 → 外部
    let down_active = Arc::clone(&last_active);
    let down = async move {
        while let Ok(payload) = read_frame(&mut rd).await {
            if let Err(e) = socket.send_to(&payload, peer).await {
                debug!(%peer, error = %e, "udp 回写外部失败");
                break;
            }
            down_active.store(now_ms() as u64, Ordering::Relaxed);
        }
    };

    tokio::select! {
        _ = up => debug!(%peer, conn_id, "udp 上行结束"),
        _ = down => debug!(%peer, conn_id, "udp 下行结束"),
        _ = idle_watch(Arc::clone(&last_active), idle_timeout) => {
            debug!(%peer, conn_id, "udp 会话空闲回收");
        }
    }
}

/// 空闲监视：两个方向都静默超过阈值即结束会话
async fn idle_watch(last_active: Arc<AtomicU64>, idle_timeout: Duration) {
    let idle_ms = idle_timeout.as_millis() as i64;
    loop {
        tokio::time::sleep(IDLE_TICK).await;
        let idle = now_ms() - last_active.load(Ordering::Relaxed) as i64;
        if idle >= idle_ms {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn idle_watch_returns_after_timeout() {
        let last = Arc::new(AtomicU64::new(now_ms() as u64));
        let start = Instant::now();
        // 阈值 1s、轮询 1s：应在 2s 内返回
        tokio::time::timeout(Duration::from_secs(4), idle_watch(Arc::clone(&last), Duration::from_secs(1)))
            .await
            .expect("idle_watch 未按时返回");
        assert!(start.elapsed() >= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn idle_watch_survives_activity() {
        let last = Arc::new(AtomicU64::new(now_ms() as u64));
        let bump = Arc::clone(&last);
        tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(700)).await;
                bump.store(now_ms() as u64, Ordering::Relaxed);
            }
        });
        // 阈值 1s：持续有活动时不应提前返回，这里只验证它没有在 2s 内误判
        let r = tokio::time::timeout(
            Duration::from_secs(2),
            idle_watch(Arc::clone(&last), Duration::from_secs(1)),
        )
        .await;
        assert!(r.is_err(), "有活动时不应判定空闲");
    }
}
