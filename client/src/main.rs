use anyhow::{bail, Context, Result};
use clap::Parser;
use rfp_common::msg::ProxyType;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rfp_client::config::ClientConfig;

/// Rust-FRP 客户端
#[derive(Parser)]
#[command(name = "rfpc", version, about)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "rfpc.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let raw =
        std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config))?;
    let cfg: ClientConfig =
        toml::from_str(&raw).with_context(|| format!("parse {}", args.config))?;

    // 启动期校验
    let mut names = std::collections::HashSet::new();
    for p in &cfg.proxies {
        if p.proxy_type != ProxyType::Tcp {
            bail!("proxy `{}`: M1 仅支持 type = \"tcp\"", p.name);
        }
        if p.remote_port == 0 {
            bail!("proxy `{}`: remote_port 不能为 0", p.name);
        }
        if !names.insert(p.name.as_str()) {
            bail!("proxy 名称重复: {}", p.name);
        }
    }

    info!(
        server = %format!("{}:{}", cfg.server_addr, cfg.server_port),
        proxies = cfg.proxies.len(),
        "rfpc starting"
    );

    tokio::select! {
        r = rfp_client::run(cfg) => r,
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c, exit");
            Ok(())
        }
    }
}
