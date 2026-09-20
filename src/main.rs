// src/main.rs
mod alerting;
mod api;
mod core;
mod integrations;
mod malware;
mod mcp;
mod plugins;

use anyhow::Result;
use clap::Parser;

/// Sentinel 2.0 — The Ultimate Homelab Security Platform
#[derive(Parser)]
#[command(version = "2.0.0")]
struct Cli {
    /// Run as a daemon (continuous monitoring)
    #[arg(short, long)]
    daemon: bool,

    /// Scan a specific target
    #[arg(short, long)]
    target: Option<String>,

    /// Limit to specific stages
    #[arg(short, long)]
    stages: Option<String>,

    /// Output findings as JSON
    #[arg(long)]
    json: bool,

    /// Write findings to file
    #[arg(long)]
    output: Option<String>,

    /// Path to config file
    #[arg(short, long, default_value = "/etc/sentinel/config.toml")]
    config: String,

    /// Start the MCP server
    #[arg(long)]
    mcp_server: bool,

    /// Start the Nginx UI dashboard
    #[arg(long)]
    dashboard: bool,

    /// Check system status
    #[arg(long)]
    status: bool,

    /// Block an IP address via nftables
    #[arg(long)]
    block_ip: Option<String>,

    /// Run compliance scan
    #[arg(long)]
    compliance: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("sentinel=info")
        .init();

    let cli = Cli::parse();
    tracing::info!("Sentinel 2.0 initializing...");

    if cli.daemon {
        core::daemon::start(&cli.config).await?;
    } else if cli.mcp_server {
        mcp::start(&cli.config).await?;
    } else if cli.dashboard {
        api::start_dashboard(&cli.config).await?;
    } else if cli.status {
        core::status::show().await?;
    } else if let Some(ip) = &cli.block_ip {
        core::firewall::block(ip)?;
    } else if cli.compliance {
        core::compliance::scan().await?;
    } else if let Some(target) = &cli.target {
        let stages = cli.stages.map(|s| s.split(',').map(String::from).collect());
        let findings = core::orchestrator::scan(target, stages).await?;

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        } else {
            println!("Sentinel: {} findings", findings.len());
            for f in findings.iter().take(80) {
                println!(
                    "  [{:<8}] {:<14} {}  ({})",
                    f.severity, f.finding_type, f.value, f.tool
                );
            }
        }

        if let Some(path) = &cli.output {
            std::fs::write(path, serde_json::to_string_pretty(&findings)?)?;
        }
    } else {
        println!("Sentinel 2.0 — Use --help for commands");
        println!("Commands:");
        println!("  --daemon         Run as continuous monitoring daemon");
        println!("  --mcp-server     Start MCP server for AI agents");
        println!("  --dashboard      Start Nginx UI dashboard");
        println!("  --scan DOMAIN    Scan a target");
        println!("  --status         System status");
        println!("  --block-ip IP    Block IP via nftables");
        println!("  --compliance     Run CIS benchmark scan");
    }

    Ok(())
}
