# Rust-FRP 开发规范

> 规则的权威来源是项目宪法 [`.specify/memory/constitution.md`](../.specify/memory/constitution.md)。
> 本文件只保留两类内容：
> ① 宪法显式引用本文件作为**唯一权威来源**的部分（设计决策记录、公网部署状态）；
> ② 宪法未展开的**环境事实与速查**。
> 与宪法冲突时以宪法为准。

## 工作流

规则见宪法 **原则 I：提交纪律（收尾即提交，NON-NEGOTIABLE）** 与 **Governance**。速查：

- 每轮收尾，只要涉及追踪文件的新增/修改 → `git commit` 并推送到 `origin/main`，不积压
- 按功能拆分：`docs` / `feat` / `fix` 分开，一笔提交只做一件事
- 提交信息：`<type>: <摘要>` + 空行 + 详情（动机/关键决策），中文书写
  - type：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`
- 验收通过（测试绿 / 冒烟过）即提交推送，不再询问是否提交
- 推送失败先试本机代理 `127.0.0.1:10809`，不得直接放弃

## 代码约定

规则见宪法 **附加约束（技术栈与代码约定）**。本文件只补充宪法未列的环境细节：

- 二进制命名：`rfps`（服务端）/ `rfpc`（客户端）
- 默认端口：7000（控制+数据共用，对齐 frp 迁移习惯）

## 测试要求

测试分层与验收标准见宪法 **原则 II：验证拓扑（本机客户端、上游服务端，NON-NEGOTIABLE）**
与 **附加约束 → 测试**。本文件维护验证环境事实：

- **上游 = 服务端侧**：tryanderror.cn（103.119.1.117，SSH 端口 60304），rfps 部署于
  /opt/rust-frp，systemd 托管 `rfps.service`，控制端口 10085、测试代理端口 65533
- **本机 = 客户端侧**：systemd 托管 `rfpc.service`（/usr/local/bin/rfpc +
  /etc/rust-frp/rfpc.toml），承载 jyutyu.cn 生产隧道

## 设计决策记录（勿回退）

宪法 **原则 V：既有设计决策不可静默回退** 将本清单列为强制约束——改动前必须走宪法修订流程，
且先证伪原决策的理由。**清单本身以本文件为唯一权威来源**。

- M1 TLS 已默认开启（rustls TLS 1.3）：未配置证书时 server 自动生成自签并落盘复用；client 用 fingerprint pinning（自签）或系统根验证（真证书）；明文必须显式 `enabled = false`。协议层不变，TLS 在帧格式之下
- M1.5 授权模型：token 即身份（协议零改动）；`[[users]]` 用户模式优先于全局 token（legacy）；通配 vhost 匹配恰好一个左标签；legacy 模式拒绝临时端口区间 32768-60999
- M2 QUIC 传输：与 TCP 共存而非替换——server `[quic]` 显式开启（UDP 缺省复用 bind_port）、client `transport = "quic"`（默认 tcp，生产稳定优先）；数据隧道由 server 在同一连接 open_bi 下发（首帧 ConnInit），M1 回连机制仅保留给 TCP 路径
- M2 QUIC 流语义陷阱：quinn 流 drop 即 reset（丢弃未发出数据）——拒绝路径必须显式 shutdown 并等对端读完，否则 Error 帧被丢；同理 server 不主动 close 连接（CONNECTION_CLOSE 会抢占末帧）
- M2 0-RTT 仅同进程内重连生效（rustls 会话票据在 endpoint 内存中，不落盘）；被拒自动降级 1-RTT，不做重试死循环
- M3 H3 采用边缘终止（Cloudflare 模式），不做端到端 QUIC 透传
- conn_id 由 server 全局自增分配
- ping/pong 仅做延迟统计，连接活性交给传输层

## 公网部署状态

宪法「开发工作流与验证环境」声明**本节是部署事实的唯一权威来源**，任何部署变更必须同轮更新本节。

- tryanderror.cn（103.119.1.117，SSH 见 `~/.ssh/tryanderror.cn`，端口 60304）：
  rfps **S1 版**已部署（/opt/rust-frp，systemd `rfps.service`），
  TCP+UDP 10085 双监听，`[quic] enabled = true`，`[http] 8080` + `[https] 18443`，
  `subdomain_host = "tryanderror.cn"`。备份：`rfps.bak-m2`、`rfps.bak-m1`（+ 对应 toml）
  fingerprint（未变）：603d904eb2beebbe2b60a3735191275b27907609deecf5d4cfcb3fa58e9363a5
- vhost 证书：`/opt/rust-frp/certs/rfp-test.crt|.key`（自签，CN/SAN = rfp-test.tryanderror.cn）
- **安全组只放行这些端口**（2026-10-12 实测；其余一律 TIMEOUT 被上游设备丢弃）：
  TCP 60304（SSH）、TCP 10085（控制）、TCP 65533（生产代理）、TCP 80、TCP 443。
  **8080 / 18443 未放行**，因此 vhost 验收经上游 nginx 前端转发：
  `/www/server/panel/vhost/nginx/rfp-test.tryanderror.cn.conf`（临时文件，验收结束删除并 reload）。
  注意 80/443/8443 均被 nginx 占用（BT 面板托管，主配置 /www/server/nginx/conf/nginx.conf）
- 通配 DNS：`*.tryanderror.cn` → 103.119.1.117（子域名可直接解析）
- 测试用户 `msi-main` 端口授权为 `["65533", "65532"]`（65532 供 tcp 对照组用）
- 生产隧道：jyutyu.cn（discourse-https，端口 65533，本机 rfpc systemd 服务，TCP 传输）
- 公网 QUIC 验证：**仍待安全组放行 UDP 10085**（tcpdump 实测 3 个探测包 0 命中；
  该机为 Cloudie 香港 VPS 面板管控，无 API 可用）
- 本机验收客户端：`/tmp/rfpc-s1-accept.toml`（独立进程，不经过 `rfpc.service`）
