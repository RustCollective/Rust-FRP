# Rust-FRP 开发规范

## 工作流

1. **每轮任务完成即提交**：一个功能/修复/文档独立成笔，不积压
2. **按功能拆分提交**：docs、feat、fix 分开，一笔提交只做一件事
3. **提交后立即推送**：`git push` 到 origin/main，不留在本地
4. **提交信息格式**：`<type>: <摘要>` + 空行 + 详情（动机/关键决策），中文书写
   - type：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`
5. **禁止推送前询问是否提交**：任务验收通过（测试绿/冒烟过）即提交推送，除非用户另有指示

## 代码约定

- workspace 三 crate：`common`（协议）、`client`（rfpc）、`server`（rfps）
- 二进制命名：`rfps` / `rfpc`
- 默认端口：7000（控制+数据共用，对齐 frp 迁移习惯）
- 配置：TOML，结构与 frp v0.52+ 风格对齐（`[[proxies]]`）
- 依赖新增走 `workspace.dependencies` 统一管理
- 日志：tracing，info 记会话/注册/连接生命周期，debug 记帧级细节
- 错误：库代码 thiserror，应用层 anyhow；client 会话错误分 Fatal（不重试）/ Retry（退避重连）
- 注释与文档使用中文

## 测试要求

- 协议层（common）：单元测试覆盖消息 roundtrip、边界帧
- 端到端（server/tests）：真实 TCP 链路，含认证失败路径
- 冒烟：release 二进制 + 真实 origin（http.server 等）跑通才算验收
- 公网验证环境：tryanderror.cn（103.119.1.117，SSH 端口 60304，
  rfps 部署于 /opt/rust-frp，systemd 托管 `rfps.service`，
  控制端口 10085、测试代理端口 65533 —— 安全组已放行）
- 本机 rfpc：systemd 托管 `rfpc.service`（/usr/local/bin/rfpc +
  /etc/rust-frp/rfpc.toml），承载 jyutyu.cn 生产隧道

## 设计决策记录（勿回退）

- M1 TLS 已默认开启（rustls TLS 1.3）：未配置证书时 server 自动生成自签并落盘复用；client 用 fingerprint pinning（自签）或系统根验证（真证书）；明文必须显式 `enabled = false`。协议层不变，TLS 在帧格式之下
- M1.5 授权模型：token 即身份（协议零改动）；`[[users]]` 用户模式优先于全局 token（legacy）；通配 vhost 匹配恰好一个左标签；legacy 模式拒绝临时端口区间 32768-60999
- M2 QUIC 传输：与 TCP 共存而非替换——server `[quic]` 显式开启（UDP 缺省复用 bind_port）、client `transport = "quic"`（默认 tcp，生产稳定优先）；数据隧道由 server 在同一连接 open_bi 下发（首帧 ConnInit），M1 回连机制仅保留给 TCP 路径
- M2 QUIC 流语义陷阱：quinn 流 drop 即 reset（丢弃未发出数据）——拒绝路径必须显式 shutdown 并等对端读完，否则 Error 帧被丢；同理 server 不主动 close 连接（CONNECTION_CLOSE 会抢占末帧）
- M2 0-RTT 仅同进程内重连生效（rustls 会话票据在 endpoint 内存中，不落盘）；被拒自动降级 1-RTT，不做重试死循环
- M3 H3 采用边缘终止（Cloudflare 模式），不做端到端 QUIC 透传
- conn_id 由 server 全局自增分配
- ping/pong 仅做延迟统计，连接活性交给传输层

## 公网部署状态

- tryanderror.cn（103.119.1.117，SSH 见 ~/.ssh/tryanderror.cn）：rfps M2 版已部署（/opt/rust-frp，
  systemd `rfps.service`），TCP+UDP 10085 双监听，`[quic] enabled = true`，
  旧版备份 rfps.bak-m1。fingerprint：603d904eb2beebbe2b60a3735191275b27907609deecf5d4cfcb3fa58e9363a5
- 生产隧道：jyutyu.cn（discourse-https，端口 65533，本机 rfpc systemd 服务，TCP 传输）
- 公网 QUIC 验证：**待安全组放行 UDP 10085**（tcpdump 确认当前被拦截；该机为 Cloudie 香港 VPS，
  无阿里云 API 可用——Rock5B 上的 acme.sh 阿里云密钥已失效）
- 安全组已放行：TCP 10085（控制）、TCP 65533（代理）
