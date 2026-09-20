#!/bin/bash
# Sentinel 2.0 — Homelab Security Platform Installer
# Usage: curl -fsSL sentinel.security/install.sh | bash

set -euo pipefail

SENTINEL_VERSION="2.0.0"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sentinel"
DATA_DIR="/var/lib/sentinel"
DASHBOARD_DIR="/usr/share/sentinel/dashboard"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[SENTINEL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Cannot detect OS"
        exit 1
    fi
}

# Install dependencies
install_deps() {
    log "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                build-essential \
                pkg-config \
                libssl-dev \
                curl \
                git \
                nftables \
                clamav \
                clamav-daemon \
                yara \
                2>/dev/null || true
            ;;
        fedora|rhel|centos)
            dnf install -y \
                gcc \
                gcc-c++ \
                openssl-devel \
                curl \
                git \
                nftables \
                clamav \
                yara \
                2>/dev/null || true
            ;;
        arch)
            pacman -S --noconfirm \
                base-devel \
                openssl \
                curl \
                git \
                nftables \
                clamav \
                yara \
                2>/dev/null || true
            ;;
    esac
}

# Install Rust if needed
install_rust() {
    if ! command -v cargo &> /dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
}

# Configure build
configure_build() {
    log "Configure your Sentinel build"
    echo ""
    
    # Dashboard
    read -p "Enable Nginx UI dashboard? [Y/n]: " enable_dashboard
    enable_dashboard=${enable_dashboard:-Y}
    
    # MCP Server
    read -p "Enable MCP server for AI agents? [Y/n]: " enable_mcp
    enable_mcp=${enable_mcp:-Y}
    
    # Malware scanning
    read -p "Enable malware scanning (ClamAV + YARA)? [Y/n]: " enable_malware
    enable_malware=${enable_malware:-Y}
    
    # Firewall
    read -p "Enable nftables firewall integration? [Y/n]: " enable_firewall
    enable_firewall=${enable_firewall:-Y}
    
    # Alerts
    echo ""
    echo "Alert channels (comma-separated):"
    echo "  telegram, slack, discord, email, pagerduty, matrix, signal, ntfy"
    read -p "Alert channels [telegram]: " alert_channels
    alert_channels=${alert_channels:-telegram}
    
    # Telegram config
    if [[ "$alert_channels" == *"telegram"* ]]; then
        read -p "Telegram bot token: " telegram_token
        read -p "Telegram chat ID: " telegram_chat_id
    fi
    
    # Dashboard port
    read -p "Dashboard port [8080]: " dashboard_port
    dashboard_port=${dashboard_port:-8080}
    
    # Install type
    echo ""
    echo "Install type:"
    echo "  1) Binary (pre-compiled, faster)"
    echo "  2) Source (compile from source, optimized)"
    read -p "Choose [1]: " install_type
    install_type=${install_type:-1}
    
    # Generate config
    generate_config
}

generate_config() {
    log "Generating configuration..."
    
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR
    
    cat > $CONFIG_DIR/config.toml << EOF
# Sentinel 2.0 Configuration
# Generated on $(date)

[general]
daemon = true
schedule = "0 */6 * * *"
jitter_seconds = 300
data_dir = "$DATA_DIR"
log_level = "info"

[dashboard]
enabled = $([ "$enable_dashboard" = "Y" ] && echo "true" || echo "false")
listen = "0.0.0.0:$dashboard_port"
domain = ""
jwt_secret = ""
allowed_origins = ""
mtls_ca_cert = ""
mtls_key = ""

[mcp]
enabled = $([ "$enable_mcp" = "Y" ] && echo "true" || echo "false")
transport = "stdio"
listen = "127.0.0.1:9000"
auth_token = ""
mtls_enabled = false

[malware]
clamav_enabled = $([ "$enable_malware" = "Y" ] && echo "true" || echo "false")
yara_enabled = $([ "$enable_malware" = "Y" ] && echo "true" || echo "false")
yara_rules_dir = "$CONFIG_DIR/yara-rules"
on_access_enabled = false
daily_scan = "0 2 * * *"
max_scan_size_mb = 100

[firewall]
nftables_enabled = $([ "$enable_firewall" = "Y" ] && echo "true" || echo "false")
auto_block = true
block_duration = "24h"
rate_limit_per_minute = 100
crowdsec_enabled = false

[alerts]
channels = "$alert_channels"
min_severity = "high"
dedup_window_seconds = 3600

[alerts.telegram]
bot_token = "${telegram_token:-}"
chat_id = "${telegram_chat_id:-}"
parse_mode = "Markdown"

[alerts.slack]
webhook_url = ""

[alerts.discord]
webhook_url = ""

[alerts.email]
smtp_host = ""
smtp_port = 587
smtp_user = ""
smtp_password = ""
from = ""
to = ""

[alerts.pagerduty]
integration_key = ""

[alerts.matrix]
homeserver = ""
access_token = ""
room_id = ""

[alerts.signal]
cli_path = "/usr/local/bin/signal-cli"
number = ""
group_id = ""

[alerts.ntfy]
topic = "sentinel-alerts"
server = "https://ntfy.sh"

[integrations]
docker_enabled = true
proxy_enabled = true
proxmox_enabled = false
proxmox_host = ""
proxmox_user = ""
proxmox_token = ""
homeassistant_enabled = false
homeassistant_url = ""
homeassistant_token = ""
dns_filter_enabled = false
dns_filter_url = ""
wireguard_enabled = true

[threat_intel]
cisa_kev_enabled = true
cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
otx_enabled = false
otx_api_key = ""
abuseipdb_enabled = false
abuseipdb_api_key = ""

[compliance]
cis_enabled = true
cis_profile = "ubuntu"
auto_harden = false
dry_run = true

[zero_day]
baseline_learning_days = 7
anomaly_sensitivity = 0.85
model_path = "$DATA_DIR/models"
honeypot_enabled = false

[plugins]
plugin_dir = "$CONFIG_DIR/plugins"
enabled_plugins = "subfinder,httpx,nuclei,sherlock,prowler,crtsh,http-probe,osv-correlate"

[ssh]
enabled = true
host = "127.0.0.1"
port = 22
key_path = "/root/.ssh/id_rsa"
session_timeout = 30
mfa_enabled = false
EOF

    chmod 600 $CONFIG_DIR/config.toml
}

# Build from source
build_from_source {
    log "Building Sentinel from source..."
    
    # Clone repo
    cd /tmp
    rm -rf sentinel-cyber-agent
    git clone --depth 1 https://github.com/harisawan-bit/sentinel-cyber-agent.git
    
    cd sentinel-cyber-agent
    
    # Build release binary
    cargo build --release
    
    # Install binary
    cp target/release/sentinel $INSTALL_DIR/sentinel
    chmod 755 $INSTALL_DIR/sentinel
    
    # Install dashboard
    mkdir -p $DASHBOARD_DIR
    cp dashboard/index.html $DASHBOARD_DIR/
    
    # Install config example
    cp config.example.toml $CONFIG_DIR/config.example.toml
}

# Install pre-compiled binary
install_binary {
    log "Downloading pre-compiled binary..."
    
    # In production, this would download from GitHub releases
    # For now, build from source
    build_from_source
}

# Setup systemd
setup_systemd {
    log "Setting up systemd service..."
    
    cat > /etc/systemd/system/sentinel.service << 'EOF'
[Unit]
Description=Sentinel 2.0 - Homelab Security Platform
Documentation=https://github.com/harisawan-bit/sentinel-cyber-agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel --daemon --config /etc/sentinel/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
User=root
Group=root

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false

# Resource limits
MemoryMax=200M
CPUQuota=10%
TasksMax=50

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sentinel
}

# Setup nftables
setup_nftables {
    log "Setting up nftables..."
    
    # Create sentinel table and chain
    nft add table inet sentinel 2>/dev/null || true
    nft add chain inet sentinel input { type filter hook input priority 0\; policy accept\; } 2>/dev/null || true
    nft add set inet sentinel blocklist { type ipv4_addr\; flags timeout\; } 2>/dev/null || true
    nft add rule inet sentinel input ip saddr @blocklist counter drop 2>/dev/null || true
}

# Main
main {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SENTINEL 2.0 — Homelab Security Platform          ║${NC}"
    echo -e "${BLUE}║                        Installer                            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    detect_os
    log "Detected OS: $OS $VER"
    
    install_deps
    install_rust
    configure_build
    
    if [[ "$install_type" == "1" ]]; then
        install_binary
    else
        build_from_source
    fi
    
    setup_systemd
    setup_nftables
    
    echo ""
    log "Installation complete!"
    echo ""
    echo "Commands:"
    echo "  sentinel --status          Check system status"
    echo "  sentinel --dashboard       Start Nginx UI dashboard"
    echo "  sentinel --mcp-server      Start MCP server for AI agents"
    echo "  sentinel --scan DOMAIN     Scan a target"
    echo "  sentinel --compliance      Run CIS benchmark scan"
    echo "  sentinel --block-ip IP     Block an IP via nftables"
    echo ""
    echo "Systemd:"
    echo "  systemctl start sentinel   Start the daemon"
    echo "  systemctl stop sentinel    Stop the daemon"
    echo "  journalctl -u sentinel -f  View logs"
    echo ""
    echo "Dashboard: http://localhost:$dashboard_port"
    echo "Config: $CONFIG_DIR/config.toml"
    echo ""
}

main "$@"
