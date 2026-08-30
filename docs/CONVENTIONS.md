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

## 设计决策记录（勿回退）

- M1 明文 TCP 先行，TLS 默认开启随后合入（明文需显式声明）
- M1.5 授权模型：token 即身份（协议零改动）；`[[users]]` 用户模式优先于全局 token（legacy）；通配 vhost 匹配恰好一个左标签；legacy 模式拒绝临时端口区间 32768-60999
- M3 H3 采用边缘终止（Cloudflare 模式），不做端到端 QUIC 透传
- conn_id 由 server 全局自增分配
- ping/pong 仅做延迟统计，连接活性交给传输层
