# Quickstart: 验收 frp 功能对等 S1（域名路由型 HTTP/HTTPS 代理）

**Feature**: `001-frp-parity` | **Date**: 2026-10-11

本文件是**验收手册**，不是实现文档。实现细节见 [plan.md](./plan.md)、
[data-model.md](./data-model.md) 与 [contracts/](./contracts/)。

> **宪法原则 II 的硬性要求**：验收必须走 **本机 rfpc（客户端）↔ 上游 rfps（服务端）** 的真实公网
> 链路，release 二进制 + 真实 origin 服务。第 3 节的 loopback 自环**只作回归**，不得作为验收依据。
>
> 部署事实（主机、路径、端口、安全组）以 `docs/CONVENTIONS.md` 的「公网部署状态」为唯一权威来源；
> 下文出现的具体地址以该节为准，此处只为可读性复述。

## 1. 环境前置

| 前置 | 说明 |
|---|---|
| 上游安全组放行 vhost 端口 | 新增 `TCP <http_bind_port>` 与 `TCP <https_bind_port>`；未放行则第 4 节无从验证 |
| 上游证书 | `https` 场景需要一个真实证书文件对（自签即可，用 `openssl` 为 `app.example.com` 生成） |
| 域名解析 | 本轮**不依赖真实 DNS**：明文用 `Host` 头、TLS 用 `curl --resolve` 覆盖 |
| 本机 origin | 任意内网服务，例如 `python3 -m http.server 3000` |
| 本地构建 | `export PATH="/root/.cargo/bin:$PATH"`（rustup 装在此目录，不在默认 PATH） |

## 2. 构建与回归门禁

```bash
export PATH="/root/.cargo/bin:$PATH"
cargo build --release
cargo test --workspace        # 门禁：全绿（当前基线 23 项，S1 会新增）
```

**通过标准**：既有 23 项测试无回归，且新增的 vhost 相关用例通过（SC-003）。

## 3. 本地快速回归（不算验收）

本机同时起 rfps 与 rfpc 自环，仅用于开发期间的快速反馈：

```bash
# 终端 1：服务端（配置启用 [http] bind_port 与 [[certs]]）
./target/release/rfps -c /tmp/qa/rfps.toml
# 终端 2：客户端
./target/release/rfpc -c /tmp/qa/rfpc.toml
# 终端 3：origin
python3 -m http.server 3000
```

**通过标准**：`curl -H 'Host: app.example.com' http://127.0.0.1:8080/` 拿到 origin 的内容。
**此步通过不构成验收。**

## 4. 真实链路验收（宪法原则 II）

### 4.1 部署与启动

```bash
# 上游：更新二进制并重启（保留旧版备份，便于回滚）
# 路径 /opt/rust-frp，systemd rfps.service —— 见 docs/CONVENTIONS.md
scp target/release/rfps <upstream>:/opt/rust-frp/rfps.new
ssh <upstream> 'cp /opt/rust-frp/rfps /opt/rust-frp/rfps.bak-s1-pre \
  && mv /opt/rust-frp/rfps.new /opt/rust-frp/rfps \
  && systemctl restart rfps && systemctl status rfps --no-pager'

# 本机：更新客户端并重启
sudo install -m755 target/release/rfpc /usr/local/bin/rfpc
sudo systemctl restart rfpc && systemctl status rfpc --no-pager
```

**通过标准**：两侧 `systemctl status` 均为 active；上游日志出现 `[http]`/`[https]` 监听与证书加载
记录；本机 rfpc 日志出现两条新代理的注册成功记录。

### 4.2 场景 A —— 明文 HTTP 按 Host 路由（US1 / 场景 1）

```bash
curl -sv -H 'Host: app.example.com' http://<upstream_ip>:<http_port>/ 2>&1 | tail -20
```

**通过标准**：状态 200 且内容来自本机 origin；origin 侧日志显示收到了请求。

### 4.3 场景 B —— HTTPS 按 SNI 终止（US1 / 场景 2）

```bash
curl -sv --resolve app.example.com:<https_port>:<upstream_ip> \
     --cacert /tmp/qa/app.crt https://app.example.com:<https_port>/ 2>&1 | tail -20
```

**通过标准**：**不关闭证书校验**的前提下握手成功、返回 200。这是 FR-003 的核心判据——
证书校验必须真的通过，`-k` 跳过校验不能算通过。

### 4.4 场景 C —— 转发头（US1 / 场景 1 的附加判据）

在本机 origin 侧打印请求头（例如 `python3 -c` 起一个回显服务），确认：
`X-Forwarded-For` 为**访客**地址（非 127.0.0.1）、`X-Forwarded-Proto` 与入口一致
（明文本 `http`、TLS 入口 `https`）。

### 4.5 场景 D —— 未注册域名返回 404（US1 / 场景 3）

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: nope.example.com' \
     http://<upstream_ip>:<http_port>/
```

**通过标准**：`404`，且本机 rfpc 日志中**没有**任何转发记录（证明没有回落到其他代理）。

### 4.6 场景 E —— 域名冲突被拒（US1 / 场景 4）

在本机用第二份配置（第二个 token / 同一域名）启动第二个 rfpc 实例：

**通过标准**：第二个实例的日志出现明确的注册失败原因（含冲突域名），
且第一个实例的访问（场景 A）仍然正常。

### 4.7 场景 F —— 流式转发不缓冲（SC-007）

```bash
# 从本机 origin 暴露一个大文件，经隧道下载并观察上游 rfps 的常驻内存
dd if=/dev/urandom of=/tmp/qa/big.bin bs=1M count=1024
curl -s -o /dev/null -H 'Host: app.example.com' \
     http://<upstream_ip>:<http_port>/big.bin
# 下载期间在上游采样：
ssh <upstream> 'for i in $(seq 1 10); do \
  ps -o rss= -C rfps; sleep 1; done'
```

**通过标准**：下载成功且内容校验一致；上游 rfps 的 RSS 增量在 1GB 与 1MB 两次下载之间处于
**同一量级**（不随载荷线性增长）。

### 4.8 场景 G —— 延迟基线（SC-004）

对同一本机 origin，分别直连与经隧道各取 200 次请求的 P95，比较差值。

**通过标准**：P95 附加延迟 < 50ms（上游与本机同城部署时）。

## 5. 与 spec 验收场景的对应

| spec 场景 | 本文件章节 |
|---|---|
| US1/场景 1（Host 路由 + 转发头） | 4.2 + 4.4 |
| US1/场景 2（SNI 终止） | 4.3 |
| US1/场景 3（404 不回退） | 4.5 |
| US1/场景 4（域名冲突） | 4.6 |
| US1/场景 5（子域名模式） | 4.2 的变体：客户端改配 `subdomain = "app"`，服务端配 `subdomain_host` |
| FR-011 / SC-007（流式） | 4.7 |
| SC-003（测试无回归） | 2 |
| SC-004（延迟） | 4.8 |

## 6. 回滚

```bash
ssh <upstream> 'cp /opt/rust-frp/rfps.bak-s1-pre /opt/rust-frp/rfps && systemctl restart rfps'
```

滚动回滚后必须重跑 4.2，确认生产隧道（jyutyu.cn）与 vhost 入口均恢复。

## 7. 不通过的处置

任一场景不通过 → **不提交、不推送**，先修复。宪法原则 I 的"验收通过即提交"以本节全部场景
通过为验收定义；未通过的改动留在工作区继续修，不得以"先提交后面修"的方式绕过。
