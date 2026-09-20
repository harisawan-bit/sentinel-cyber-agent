use anyhow::Result;

/// Block an IP via nftables
pub fn block(ip: &str) -> Result<()> {
    tracing::info!(ip = ip, "Blocking IP via nftables...");

    // Add to nftables set
    // sentinel blocklist add ip

    Ok(())
}

/// Unblock an IP
pub fn unblock(ip: &str) -> Result<()> {
    tracing::info!(ip = ip, "Unblocking IP...");
    Ok(())
}

/// Parse current nftables ruleset
pub fn parse_rules() -> Result<Vec<String>> {
    Ok(vec![])
}

/// Detect permissive rules (e.g., accept all)
pub fn audit_rules() -> Result<Vec<String>> {
    Ok(vec![])
}
