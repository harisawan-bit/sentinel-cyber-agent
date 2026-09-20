# Sentinel 2.0

**The Ultimate Homelab Security Platform**

Sentinel is a single MIT-licensed security orchestration agent that unifies the best permissively-licensed cyber-security engines behind one plugin API, one shared finding model, and a bulletproof Rust core.

## Features

- **Memory-safe Rust core** — ~50MB RAM, <1% CPU idle
- **MCP server** — 10 tools for AI agent integration (Claude Code, Codex, Kimi, OpenCode, Hermes, Antigravity)
- **Nginx UI dashboard** — Real-time security monitoring
- **Malware scanning** — ClamAV + YARA integration
- **Firewall** — nftables with auto-blocking
- **Multi-channel alerts** — Telegram, Slack, Discord, Email, PagerDuty, Matrix, Signal, ntfy
- **Compliance** — CIS Benchmark scanning
- **Incident response** — Automated playbooks for ransomware, brute force, data exfiltration
- **Universal distro support** — 40+ Linux distributions
- **Omarchy integration** — Btrfs snapshots, Hyprland notifications

## Quick Install

```bash
curl -fsSL sentinel.security/install.sh | bash
```

## Manual Install

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y build-essential pkg-config libssl-dev nftables clamav yara

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release

# Install
sudo cp target/release/sentinel /usr/local/bin/
sudo mkdir -p /etc/sentinel /var/lib/sentinel /usr/share/sentinel/dashboard
sudo cp config.example.toml /etc/sentinel/config.toml
sudo cp dashboard/index.html /usr/share/sentinel/dashboard/

# Start
sudo systemctl enable --now sentinel
```

## Commands

```bash
sentinel --status           # System status
sentinel --dashboard        # Start Nginx UI dashboard
sentinel --mcp-server       # Start MCP server for AI agents
sentinel --scan DOMAIN      # Scan a target
sentinel --compliance       # Run CIS benchmark scan
sentinel --block-ip IP      # Block IP via nftables
sentinel --init-security    # Initialize security hardening
sentinel --security-status  # Show security status
sentinel --respond THREAT   # Run incident response playbook
sentinel --stress-test      # Run stress test
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/status | System health |
| GET | /api/findings | List findings |
| POST | /api/findings/scan | Trigger scan |
| POST | /api/block | Block IP |
| GET | /api/compliance | Compliance checks |
| WS | /ws | Real-time findings stream |
| WS | /ws/terminal | SSH terminal (xterm.js) |

## MCP Tools

| Tool | Description |
|------|-------------|
| sentinel_scan_target | Run recon/scan on domain/IP |
| sentinel_get_findings | Query findings with filters |
| sentinel_get_system_status | CPU/RAM/disk/network |
| sentinel_block_ip | Add IP to nftables blocklist |
| sentinel_isolate_container | Stop/quarantine Docker container |
| sentinel_rollback_config | Restore config from backup |
| sentinel_get_logs | Fetch auth/syslog/nginx/docker logs |
| sentinel_remediate | Auto-fix finding (dry-run default) |
| sentinel_threat_intel | Query OTX/AbuseIPDB for IP/domain |
| sentinel_compliance_check | Run CIS benchmark scan |

## Configuration

Edit `/etc/sentinel/config.toml`:

```toml
[general]
daemon = true
schedule = "0 */6 * * *"
data_dir = "/var/lib/sentinel"

[dashboard]
enabled = true
listen = "0.0.0.0:8080"

[mcp]
enabled = true
transport = "stdio"

[malware]
clamav_enabled = true
yara_enabled = true

[firewall]
nftables_enabled = true
auto_block = true

[alerts]
channels = "telegram"
min_severity = "high"
```

## Supported Distributions

- Ubuntu 20.04/22.04/24.04
- Debian 11/12
- Fedora 39/40
- RHEL 8/9, Rocky Linux 8/9, AlmaLinux 8/9
- Arch Linux, Manjaro, Omarchy
- openSUSE Leap/Tumbleweed
- Alpine Linux 3.18+
- And 30+ more

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL 2.0                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  eBPF Probes │  │  WASM Plugin│  │    MCP Server (rmcp)    │  │
│  │  (kernel)    │  │  Runtime    │  │  ┌─────┐ ┌─────┐       │  │
│  │  • syscalls  │  │  • recon    │  │  │Tools│ │Resources│    │  │
│  │  • network   │  │  • scan     │  │  └─────┘ └─────┘       │  │
│  │  • file ops  │  │  • osint    │  │  Claude/Codex/Kimi/     │  │
│  │  • processes │  │  • cloud    │  │  OpenCode/Hermes/Anti   │  │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘  │
│         │                │                      │                │
│  ┌──────┴────────────────┴──────────────────────┴─────────────┐  │
│  │                    Findings Bus (tokio async)                │  │
│  └──────┬────────────────┬──────────────────────┬─────────────┘  │
│         │                │                      │                │
│  ┌──────┴──────┐  ┌──────┴──────┐  ┌───────────┴─────────────┐  │
│  │  SQLite DB  │  │  Alert Mgr  │  │  Nginx UI (Svelte)      │  │
│  │  (findings) │  │  • Telegram │  │  • Dashboard            │  │
│  │  (baseline) │  │  • Slack    │  │  • Live findings        │  │
│  │  (history)  │  │  • Discord  │  │  • Network map          │  │
│  └─────────────┘  │  • Email    │  │  • Config management    │  │
│                    │  • Webhook  │  │  • SSH terminal (xterm) │  │
│                    │  • PagerDuty│  └─────────────────────────┘  │
│                    └─────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## Security

- **Memory safety** — Rust with `#[forbid(unsafe_code)]`
- **Supply chain** — cargo-audit + cargo-deny + cargo-vet
- **Service hardening** — Full systemd sandbox
- **Firewall** — nftables with default deny
- **Audit logging** — auditd + immutable logs
- **Secrets** — systemd-credentials + ring encryption
- **Backup** — Encrypted, tested, automated
- **Incident response** — Automated playbooks

## License

MIT
