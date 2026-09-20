// src/security/mod.rs - Security hardening module
pub mod audit;
pub mod capabilities;
pub mod firewall;
pub mod hardening;
pub mod seccomp;
pub mod selinux;

use anyhow::Result;
use tracing;

/// Initialize security hardening
pub async fn init() -> Result<()> {
    tracing::info!("Initializing security hardening...");

    // Drop capabilities
    capabilities::drop().await?;

    // Setup seccomp
    seccomp::setup().await?;

    // Initialize audit
    audit::init().await?;

    tracing::info!("Security hardening initialized");
    Ok(())
}

/// Get security status
pub async fn status() -> serde_json::Value {
    serde_json::json!({
        "capabilities_dropped": capabilities::check().await,
        "seccomp_enabled": seccomp::is_enabled().await,
        "audit_running": audit::is_running().await,
        "hardening_level": "high",
    })
}
