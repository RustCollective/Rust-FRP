//! 面向本地服务的转发（S1）。
//!
//! 承载契约见 `specs/001-frp-parity/contracts/rfp1-http-vhost.md` §3：
//! 收到请求元数据（M1 来自控制通道的 `new_connection`、M2 来自数据流首帧的
//! `conn_init`）后，客户端按元数据构造请求打向 `local_addr`，再以
//! `http_response_meta` 作为响应方向的第一条消息回传，其余为裸字节。
