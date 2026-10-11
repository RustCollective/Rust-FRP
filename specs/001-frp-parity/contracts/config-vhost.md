# Contract: 配置文件扩展（S1）

**Feature**: `001-frp-parity` | **Date**: 2026-10-11 | **消费者**: `rfps`（服务端）、`rfpc`（客户端）

配置沿用 TOML 与 frp v0.52+ 风格（宪法附加约束）。本契约只列 S1 新增/变化的部分。

## 1. 服务端 `rfps.toml`

### 1.1 新增段

```toml
# vhost 明文 HTTP 监听（显式声明才启用，符合宪法原则 III 的"明文必须显式"）
[http]
bind_port = 8080          # 缺省不启用
# bind_addr = "0.0.0.0"   # 可选，缺省复用全局 bind 地址

# vhost TLS 监听（按 SNI 选证书后终止，转发明文 HTTP 给客户端）
[https]
bind_port = 8443          # 缺省不启用
# bind_addr = "0.0.0.0"

# 子域名模式（FR-008）：配置后客户端只需声明 subdomain 标签
subdomain_host = "example.com"

# 域名证书表（FR-003）；未列出的 SNI 一律拒绝握手
[[certs]]
domain = "app.example.com"
cert = "/etc/rust-frp/certs/app.crt"
key  = "/etc/rust-frp/certs/app.key"

[[certs]]
domain = "*.example.com"       # 通配证书，匹配语义由 rustls 决定
cert = "/etc/rust-frp/certs/wildcard.crt"
key  = "/etc/rust-frp/certs/wildcard.key"
```

### 1.2 既有段的变化

`[[users]]` 的 `vhosts` 字段**语义不变**，但 S1 起真正生效——此前 `Http`/`Https` 类型被拒绝，
该字段形同占位（`docs/CONVENTIONS.md` 记为 M1.5 决策，本契约是兑现它）。

```toml
[[users]]
name = "alice"
token = "alice-token"
ports = ["6000-6100"]
vhosts = ["*.alice.dev", "alice.example.com"]   # 现在真正参与 http/https 注册的授权检查
```

### 1.3 启动期校验（失败即拒绝启动）

| 检查 | 失败行为 | 实现位置 |
|---|---|---|
| `[https]` 启用但 `[[certs]]` 为空 | 拒绝启动，提示 TLS 监听无可用证书 | `server/src/config.rs::validate` |
| 监听端口互斥：`bind_port` / `[http]` / `[https]` 三者两两不同 | 拒绝启动，指明冲突的端口 | `server/src/config.rs::validate` |
| `[[certs]]` 的 `domain` 归一化后为空或重复（大小写不敏感） | 拒绝启动，指明重复的域名 | `server/src/config.rs::validate` |
| `[[certs]]` 的 `cert` / `key` 路径为空 | 拒绝启动 | `server/src/config.rs::validate` |
| `subdomain_host` 为空或含通配符 | 拒绝启动（通配后缀会让路由匹配歧义） | `server/src/config.rs::validate` |
| 证书文件不存在 / PEM 解析失败 / 证书与私钥不配对 | 拒绝启动，指明出问题的 `domain` | `server/src/vhost/certs.rs`（S1/T034） |

校验分两处但同属"启动期"：结构性问题在 `config.rs` 的解析后校验里拦，
需要真实读取 PEM 的问题在 `vhost/certs.rs` 构建证书表时拦。

**不属启动期校验**：`subdomain_host` 展开后的域名与另一会话的精确域名同形——
注册时才知道有哪些域名，因此由**运行期注册冲突检查**捕获（§1.2 的域名冲突路径），
不在启动期做。

## 2. 客户端 `rfpc.toml`

### 2.1 新增代理类型

```toml
[[proxies]]
name = "web"
type = "http"                       # 新增可用值
local_addr = "127.0.0.1:3000"
custom_domains = ["app.example.com"]  # 对齐 frp 的字段名，映射到 register_proxy.vhosts
# subdomain = "app"                 # 二选一：服务端配置了 subdomain_host 时可用

[[proxies]]
name = "web-tls"
type = "https"
local_addr = "127.0.0.1:8443"
custom_domains = ["secure.example.com"]
[proxies.local_tls]                 # FR-010：客户端到本地服务这一段
enabled = true                      # 缺省 false，即按 http 访问本地
verify = "system"                   # system（缺省）| skip | fingerprint
# fingerprint = "..."               # verify = "fingerprint" 时必填
```

### 2.2 字段约束

| 字段 | 约束 |
|---|---|
| `custom_domains` | `http`/`https` 类型下与 `subdomain` 至少一项非空；`tcp`/`udp` 类型下必须为空 |
| `remote_port` | `http`/`https` 类型下必须为空（配置了就报错，而非忽略） |
| `subdomain` | 单个标签，不含 `.`；需服务端配置 `subdomain_host` |
| `[proxies.local_tls]` | 仅 `https` 有意义；`verify = "skip"` 必须在日志中以 warn 级别提示 |

### 2.3 启动期校验

客户端在启动时对配置做本地校验，**不合法即拒绝启动**（而非注册时才发现）：
类型与入口标识的搭配、`subdomain` 与 `custom_domains` 的互斥与必需、`local_tls` 的完整性。
这与 `client/src/main.rs` 现有的启动期 `proxy_type` 检查是同一条路径。

## 3. 与 frp 的配置对照（迁移判据，SC-002）

| frp | Rust-FRP | 说明 |
|---|---|---|
| `type = "http"` + `customDomains` | `type = "http"` + `custom_domains` | 同形 |
| `type = "https"` + `customDomains` | `type = "https"` + `custom_domains` | 同形 |
| `type = "https"` + `plugin = "https2http"` | `type = "http"` + `[proxies.local_tls]` | frp 用插件表达"外 TLS 内明文"，本项目用 `local_tls` 表达逆方向 |
| `subdomain` + 服务端 `subdomainHost` | 同名 | 同形 |
| 服务端 `vhostHTTPPort` | `[http] bind_port` | 命名不同，语义一致 |
| 服务端 `vhostHTTPSPort` | `[https] bind_port` | 命名不同，语义一致 |
| 服务端 TLS 证书（`frps.toml` 的 `[transport.tls]`） | `[[certs]]` | frp 只有单证书；本项目按域名一表，是同能力的超集 |

**迁移成本声明**：`vhostHTTPPort`/`vhostHTTPSPort` 是服务端配置结构的变化，spec 的 SC-002 已把
"新增的 vhost 监听端口"列为可接受的差异；其余代理侧配置保持同形。
