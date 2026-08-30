use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rfp_server::ServerConfig;

/// Rust-FRP 服务端
#[derive(Parser)]
#[command(name = "rfps", version, about)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "rfps.toml")]
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
    let cfg: ServerConfig =
        toml::from_str(&raw).with_context(|| format!("parse {}", args.config))?;

    info!(
        bind = %format!("{}:{}", cfg.bind_addr, cfg.bind_port),
        "rfps starting"
    );

    tokio::select! {
        r = rfp_server::run(cfg) => r,
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c, exit");
            Ok(())
        }
    }
}
