// src/security/firewall.rs - Firewall management
use anyhow::Result;
use tracing;

/// Setup nftables rules
pub async fn setup_nftables() -> Result<()> {
    tracing::info!("Setting up nftables...");
    
    // Create table
    run_nft(&["add", "table", "inet", "sentinel"]).await?;
    
    // Create chain
    run_nft(&["add", "chain", "inet", "sentinel", "input", 
        "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"]).await?;
    
    // Create blocklist set
    run_nft(&["add", "set", "inet", "sentinel", "blocklist", 
        "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "timeout", "24h", ";", "}"]).await?;
    
    // Add blocklist rule
    run_nft(&["add", "rule", "inet", "sentinel", "input", 
        "ip", "saddr", "@blocklist", "counter", "drop"]).await?;
    
    tracing::info!("nftables setup complete");
    Ok(())
}

/// Block an IP address
pub async fn block_ip(ip: &str) -> Result<()> {
    tracing::info!(ip = ip, "Blocking IP");
    
    run_nft(&["add", "element", "inet", "sentinel", "blocklist", 
        "{", ip, "}"]).await?;
    
    Ok(())
}

/// Unblock an IP address
pub async fn unblock_ip(ip: &str) -> Result<()> {
    tracing::info!(ip = ip, "Unblocking IP");
    
    run_nft(&["delete", "element", "inet", "sentinel", "blocklist", 
        "{", ip, "}"]).await?;
    
    Ok(())
}

/// Run nft command
async fn run_nft(args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new("nft")
        .args(args)
        .output()
        .await?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("nft command failed: {}", stderr);
    }
    
    Ok(())
}
