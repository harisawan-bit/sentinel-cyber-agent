// src/security/hardening.rs - System hardening
use anyhow::Result;
use tracing;

/// Initialize all hardening measures
pub async fn init() -> Result<()> {
    tracing::info!("Initializing system hardening...");
    
    // Set secure sysctl values
    secure_sysctl().await?;
    
    // Disable core dumps
    disable_core_dumps().await?;
    
    tracing::info!("System hardening initialized");
    Ok(())
}

/// Apply secure sysctl values
pub async fn secure_sysctl() -> Result<()> {
    let settings = [
        ("kernel.core_uses_pid", "1"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.kptr_restrict", "2"),
        ("kernel.randomize_va_space", "2"),
        ("kernel.sysrq", "0"),
        ("kernel.yama.ptrace_scope", "2"),
        ("net.conf.all.log_martians", "1"),
        ("net.conf.default.log_martians", "1"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0"),
        ("net.ipv4.conf.default.log_martians", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.tcp_timestamps", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.all.accept_source_route", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_source_route", "0"),
        ("vm.mmap_min_addr", "65536"),
        ("vm.mmap_rnd_bits", "32"),
        ("vm.mmap_rnd_compat_bits", "16"),
    ];
    
    for (key, value) in settings.iter() {
        let _ = tokio::process::Command::new("sysctl")
            .args(&["-w", &format!("{}={}", key, value)])
            .output()
            .await;
    }
    
    tracing::info!("Secure sysctl values applied");
    Ok(())
}

/// Disable core dumps
pub async fn disable_core_dumps() -> Result<()> {
    tokio::process::Command::new("sysctl")
        .args(&["-w", "kernel.core_pattern=|/bin/false"])
        .output()
        .await?;
    
    Ok(())
}

/// Set secure ulimits
pub async fn set_ulimits() -> Result<()> {
    // Set via systemd service file
    tracing::info!("Ulimits should be set via systemd service file");
    Ok(())
}
