// src/security/audit.rs - Audit logging
use anyhow::Result;
use tracing;

/// Initialize audit subsystem
pub async fn init() -> Result<()> {
    tracing::info!("Initializing audit subsystem...");
    
    // Check if auditd is running
    let output = tokio::process::Command::new("systemctl")
        .args(&["is-active", "auditd"])
        .output()
        .await?;
    
    if !output.status.success() {
        tracing::warn!("auditd not running, audit logging may be limited");
    }
    
    Ok(())
}

/// Check if audit is running
pub async fn is_running() -> bool {
    tokio::process::Command::new("systemctl")
        .args(&["is-active", "auditd"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Log security event
pub async fn log_event(event: &str, details: &str) -> Result<()> {
    tracing::info!(event = event, details = details, "Security event");
    
    // Also log to audit
    let _ = tokio::process::Command::new("auditctl")
        .args(&["-m", event, "-p", "rwxa", "-k", "sentinel"])
        .output()
        .await;
    
    Ok(())
}
