# Changelog

## M2 — QUIC 传输（2026-09-02）

- 控制与数据通道新增 QUIC（quinn 0.11），与 TCP（M1）共存：
  - server `[quic]` 显式开启，UDP 缺省复用 `bind_port`；第一条 bi-stream 为控制通道（帧协议不变）
  - 数据隧道由 server 在同一连接上 `open_bi` 下发（首帧 ConnInit），消除 M1 的 new_connection 通知 + client 回连
  - client `transport = "quic"` 切换（默认 tcp）
- 0-RTT 断线重连：endpoint 跨重连复用（rustls 会话票据保留），`into_0rtt` 携带 Hello 早发；0-RTT 被拒自动降级 1-RTT 流（仅同进程内重连生效，票据不落盘）
- TLS 复用：同一证书与 fingerprint pinning 体系，ALPN `rfp/1`；QUIC 内生 TLS 1.3 无明文模式
- 传输层：15s keepalive、并发 bi-stream 上限 256（两侧）
- 修复（QUIC 流语义）：quinn 流 drop 即 reset，拒绝路径（认证失败/版本不匹配）改为显式 shutdown + 等待对端读完，避免 Error 帧被丢弃
- 测试：QUIC 全链路 / 同 endpoint 断线重连（0-RTT 路径）/ 认证失败 三个 e2e，全部通过；TCP 用例零改动
- 部署：tryanderror.cn rfps 已升级（TCP+UDP 10085 双监听，jyutyu.cn 生产隧道自动恢复验证通过）；公网 QUIC 验证待安全组放行 UDP 10085

## M1.5 — 每用户授权模型

- token 即身份（协议零改动）；`[[users]]` 用户模式优先于全局 token（legacy）
- 端口区间授权（`"6000-6100"` / 单端口）、vhost 通配授权（恰好一个左标签）
- legacy 模式拒绝系统临时端口区间 32768-60999

## M1 — TCP 隧道 MVP

- TCP 控制连接 + u32 长度前缀帧协议（JSON 控制消息，单帧上限 64 KiB）
- TCP 代理全链路：认证、注册、转发、断线自动重连
- TLS 默认加密（rustls TLS 1.3）：server 自动生成自签证书落盘复用，client fingerprint pinning / 系统根验证；明文需显式 `enabled = false`
