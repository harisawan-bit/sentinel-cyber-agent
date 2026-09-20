pub mod server;

use anyhow::Result;
use tracing;

/// Start the MCP server for AI agent integration
pub async fn start(config_path: &str) -> Result<()> {
    tracing::info!("Starting MCP server...");
    
    let server = server::SentinelMcpServer::new();
    server.serve_stdio().await?;
    
    tracing::info!("MCP server listening");
    Ok(())
}
