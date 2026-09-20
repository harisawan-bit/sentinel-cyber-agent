// src/security/selinux.rs - SELinux/AppArmor management
use anyhow::Result;
use tracing;

/// Check if SELinux is enforcing
pub async fn is_selinux_enforcing() -> bool {
    tokio::process::Command::new("getenforce")
        .output()
        .await
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim() == "Enforcing"
        })
        .unwrap_or(false)
}

/// Check if AppArmor is enabled
pub async fn is_apparmor_enabled() -> bool {
    tokio::process::Command::new("aa-status")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get security module status
pub async fn status() -> serde_json::Value {
    serde_json::json!({
        "selinux_enforcing": is_selinux_enforcing().await,
        "apparmor_enabled": is_apparmor_enabled().await,
    })
}
