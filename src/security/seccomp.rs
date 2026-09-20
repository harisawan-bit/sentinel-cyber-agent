// src/security/seccomp.rs - Seccomp filter management
use anyhow::Result;
use tracing;

/// Setup seccomp filter
pub async fn setup() -> Result<()> {
    tracing::info!("Setting up seccomp filter...");
    
    // Seccomp is applied via systemd service file
    // This function verifies it's active
    
    if is_enabled().await {
        tracing::info!("Seccomp filter active");
    } else {
        tracing::warn!("Seccomp filter not active - apply via systemd");
    }
    
    Ok(())
}

/// Check if seccomp is enabled
pub async fn is_enabled() -> bool {
    tokio::process::Command::new("grep")
        .args(&["Seccomp", "/proc/self/status"])
        .output()
        .await
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("2") // SECCOMP_MODE_FILTER
        })
        .unwrap_or(false)
}
