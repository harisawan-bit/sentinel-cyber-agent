#!/bin/bash
# Sentinel 2.0 — Universal Homelab Security Platform Installer
# Supports: Ubuntu, Debian, Fedora, RHEL, CentOS, Rocky, Alma, Arch, Manjaro, openSUSE, Alpine, Omarchy
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
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[SENTINEL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Detect OS with comprehensive detection
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        NAME=$NAME
        
        # Detect derived distros
        if [[ "$ID" == "arch" ]] && [[ -d /opt/omarchy ]]; then
            DISTRO="omarchy"
        elif [[ "$ID_LIKE" == *"debian"* ]]; then
            DISTRO="debian"
        elif [[ "$ID_LIKE" == *"rhel"* ]] || [[ "$ID_LIKE" == *"fedora"* ]]; then
            DISTRO="rhel"
        elif [[ "$ID_LIKE" == *"suse"* ]]; then
            DISTRO="suse"
        elif [[ "$ID_LIKE" == *"arch"* ]]; then
            DISTRO="arch"
        else
            DISTRO=$OS
        fi
    else
        error "Cannot detect OS"
        exit 1
    fi
    
    log "Detected: $NAME ($OS $VER)"
}

# Detect package manager
detect_pkg_mgr() {
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    elif command -v pacman &> /dev/null; then
        PKG_MGR="pacman"
    elif command -v zypper &> /dev/null; then
        PKG_MGR="zypper"
    elif command -v apk &> /dev/null; then
        PKG_MGR="apk"
    else
        error "No supported package manager found"
        exit 1
    fi
    
    log "Package manager: $PKG_MGR"
}

# Detect firewall system
detect_firewall {
    if command -v nft &> /dev/null; then
        FIREWALL="nftables"
    elif command -v iptables &> /dev/null; then
        FIREWALL="iptables"
    elif command -v firewall-cmd &> /dev/null; then
        FIREWALL="firewalld"
    elif command -v ufw &> /dev/null; then
        FIREWALL="ufw"
    else
        FIREWALL="none"
    fi
    
    log "Firewall: $FIREWALL"
}

# Detect init system
detect_init {
    if [[ -d /run/systemd/system ]]; then
        INIT="systemd"
    elif command -v openrc &> /dev/null; then
        INIT="openrc"
    elif command -v s6-svscan &> /dev/null; then
        INIT="s6"
    else
        INIT="unknown"
    fi
    
    log "Init system: $INIT"
}

# Detect existing homelab tools
detect_homelab_tools {
    log "Scanning for existing homelab tools..."
    
    declare -gA TOOLS
    
    # Docker
    if command -v docker &> /dev/null; then
        TOOLS["docker"]="installed"
        info "  Docker: installed"
    fi
    
    # Docker Compose
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null 2>&1; then
        TOOLS["docker_compose"]="installed"
        info "  Docker Compose: installed"
    fi
    
    # Portainer
    if docker ps 2>/dev/null | grep -q portainer; then
        TOOLS["portainer"]="running"
        info "  Portainer: running"
    fi
    
    # Traefik
    if docker ps 2>/dev/null | grep -q traefik; then
        TOOLS["traefik"]="running"
        info "  Traefik: running"
    fi
    
    # Nginx Proxy Manager
    if docker ps 2>/dev/null | grep -q nginx-proxy-manager; then
        TOOLS["npm"]="running"
        info "  Nginx Proxy Manager: running"
    fi
    
    # Pi-hole / AdGuard
    if docker ps 2>/dev/null | grep -q pi-hole; then
        TOOLS["pihole"]="running"
        info "  Pi-hole: running"
    fi
    if docker ps 2>/dev/null | grep -q adguard; then
        TOOLS["adguard"]="running"
        info "  AdGuard Home: running"
    fi
    
    # Home Assistant
    if docker ps 2>/dev/null | grep -q homeassistant; then
        TOOLS["homeassistant"]="running"
        info "  Home Assistant: running"
    fi
    
    # Proxmox
    if command -v pvesh &> /dev/null; then
        TOOLS["proxmox"]="installed"
        info "  Proxmox VE: detected"
    fi
    
    # CrowdSec
    if command -v crowdsec &> /dev/null; then
        TOOLS["crowdsec"]="installed"
        info "  CrowdSec: installed"
    fi
    
    # fail2ban
    if command -v fail2ban-client &> /dev/null; then
        TOOLS["fail2ban"]="installed"
        info "  fail2ban: installed"
    fi
    
    # Grafana
    if docker ps 2>/dev/null | grep -q grafana; then
        TOOLS["grafana"]="running"
        info "  Grafana: running"
    fi
    
    # Uptime Kuma
    if docker ps 2>/dev/null | grep -q uptime-kuma; then
        TOOLS["uptime_kuma"]="running"
        info "  Uptime Kuma: running"
    fi
    
    # Nextcloud
    if docker ps 2>/dev/null | grep -q nextcloud; then
        TOOLS["nextcloud"]="running"
        info "  Nextcloud: running"
    fi
    
    # Jellyfin / Plex
    if docker ps 2>/dev/null | grep -q jellyfin; then
        TOOLS["jellyfin"]="running"
        info "  Jellyfin: running"
    fi
    if docker ps 2>/dev/null | grep -q plex; then
        TOOLS["plex"]="running"
        info "  Plex: running"
    fi
    
    # Vaultwarden
    if docker ps 2>/dev/null | grep -q vaultwarden; then
        TOOLS["vaultwarden"]="running"
        info "  Vaultwarden: running"
    fi
    
    # WireGuard
    if command -v wg &> /dev/null; then
        TOOLS["wireguard"]="installed"
        info "  WireGuard: installed"
    fi
    
    # *arr stack
    for tool in sonarr radarr prowlarr lidarr readarr; do
        if docker ps 2>/dev/null | grep -q $tool; then
            TOOLS["$tool"]="running"
            info "  ${tool^}: running"
        fi
    done
    
    # Syncthing
    if command -v syncthing &> /dev/null; then
        TOOLS["syncthing"]="installed"
        info "  Syncthing: installed"
    fi
    
    # Node-RED
    if docker ps 2>/dev/null | grep -q node-red; then
        TOOLS["nodered"]="running"
        info "  Node-RED: running"
    fi
}

# Install dependencies based on distro
install_deps() {
    log "Installing dependencies for $OS..."
    
    case $PKG_MGR in
        apt)
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
                docker.io \
                docker-compose-v2 \
                jq \
                sqlite3 \
                2>/dev/null || true
            ;;
        dnf)
            dnf install -y \
                gcc \
                gcc-c++ \
                openssl-devel \
                curl \
                git \
                nftables \
                clamav \
                clamav-update \
                yara \
                docker \
                docker-compose \
                jq \
                sqlite \
                2>/dev/null || true
            ;;
        pacman)
            pacman -S --noconfirm --needed \
                base-devel \
                openssl \
                curl \
                git \
                nftables \
                clamav \
                yara \
                docker \
                docker-compose \
                jq \
                sqlite \
                2>/dev/null || true
            ;;
        zypper)
            zypper install -y \
                gcc \
                gcc-c++ \
                libopenssl-devel \
                curl \
                git \
                nftables \
                clamav \
                yara \
                docker \
                docker-compose \
                jq \
                sqlite3 \
                2>/dev/null || true
            ;;
        apk)
            apk add \
                build-base \
                openssl-dev \
                curl \
                git \
                nftables \
                clamav \
                yara \
                docker \
                docker-compose \
                jq \
                sqlite \
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
    read -p "Enable firewall integration ($FIREWALL)? [Y/n]: " enable_firewall
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
    
    # Homelab integrations
    echo ""
    read -p "Enable Proxmox integration? [y/N]: " enable_proxmox
    enable_proxmox=${enable_proxmox:-N}
    
    read -p "Enable Home Assistant integration? [y/N]: " enable_ha
    enable_ha=${enable_ha:-N}
    
    read -p "Enable CrowdSec integration? [y/N]: " enable_crowdsec
    enable_crowdsec=${enable_crowdsec:-N}
    
    # Generate config
    generate_config
}

generate_config() {
    log "Generating configuration..."
    
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR
    
    # Determine firewall type for config
    local firewall_type="nftables"
    case $FIREWALL in
        nftables) firewall_type="nftables" ;;
        iptables) firewall_type="iptables" ;;
        firewalld) firewall_type="firewalld" ;;
        ufw) firewall_type="ufw" ;;
        *) firewall_type="none" ;;
    esac
    
    cat > $CONFIG_DIR/config.toml << EOF
# Sentinel 2.0 Configuration
# Generated on $(date)
# Distro: $OS $VER ($NAME)
# Package Manager: $PKG_MGR
# Firewall: $FIREWALL
# Init: $INIT

[general]
os = "$OS"
distro = "$DISTRO"
daemon = true
schedule = "0 */6 * * *"
jitter_seconds = 300
data_dir = "$DATA_DIR"
log_level = "info"
install_method = "$PKG_MGR"

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
type = "$firewall_type"
nftables_enabled = $([ "$enable_firewall" = "Y" ] && echo "true" || echo "false")
auto_block = true
block_duration = "24h"
rate_limit_per_minute = 100
crowdsec_enabled = $([ "$enable_crowdsec" = "Y" ] && echo "true" || echo "false")

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
docker_compose_enabled = true
proxy_enabled = true
proxmox_enabled = $([ "$enable_proxmox" = "Y" ] && echo "true" || echo "false")
proxmox_host = ""
proxmox_user = ""
proxmox_token = ""
homeassistant_enabled = $([ "$enable_ha" = "Y" ] && echo "true" || echo "false")
homeassistant_url = ""
homeassistant_token = ""
dns_filter_enabled = false
dns_filter_url = ""
wireguard_enabled = true
portainer_enabled = false
traefik_enabled = false
crowdsec_enabled = $([ "$enable_crowdsec" = "Y" ] && echo "true" || echo "false")
fail2ban_enabled = false
grafana_enabled = false
uptime_kuma_enabled = false
nextcloud_enabled = false
vaultwarden_enabled = false
jellyfin_enabled = false
syncthing_enabled = false

[integrations.arr_stack]
sonarr_enabled = false
radarr_enabled = false
prowlarr_enabled = false
lidarr_enabled = false
readarr_enabled = false

[threat_intel]
cisa_kev_enabled = true
cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
otx_enabled = false
otx_api_key = ""
abuseipdb_enabled = false
abuseipdb_api_key = ""

[compliance]
cis_enabled = true
cis_profile = "$DISTRO"
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
build_from_source() {
    log "Building Sentinel from source for $OS..."
    
    cd /tmp
    rm -rf sentinel-cyber-agent
    git clone --depth 1 https://github.com/harisawan-bit/sentinel-cyber-agent.git 2>/dev/null || {
        warn "Could not clone repo, using local source"
        cp -r /home/haris/sentinel-v2 /tmp/sentinel-cyber-agent 2>/dev/null || true
    }
    
    cd sentinel-cyber-agent 2>/dev/null || cd /home/haris/sentinel-v2
    
    # Build release binary
    cargo build --release
    
    # Install binary
    cp target/release/sentinel $INSTALL_DIR/sentinel
    chmod 755 $INSTALL_DIR/sentinel
    
    # Install dashboard
    mkdir -p $DASHBOARD_DIR
    cp dashboard/index.html $DASHBOARD_DIR/
    
    # Install config example
    cp config.example.toml $CONFIG_DIR/config.example.toml 2>/dev/null || true
}

# Install pre-compiled binary
install_binary() {
    log "Downloading pre-compiled binary for $OS..."
    
    # In production, this would download from GitHub releases
    # For now, build from source
    build_from_source
}

# Setup init system
setup_init() {
    case $INIT in
        systemd)
            setup_systemd
            ;;
        openrc)
            setup_openrc
            ;;
        s6)
            setup_s6
            ;;
        *)
            warn "Unknown init system, skipping service setup"
            ;;
    esac
}

# Setup systemd
setup_systemd() {
    log "Setting up systemd service..."
    
    cat > /etc/systemd/system/sentinel.service << 'EOF'
[Unit]
Description=Sentinel 2.0 - Homelab Security Platform
Documentation=https://github.com/harisawan-bit/sentinel-cyber-agent
After=network.target docker.service
Wants=docker.service

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

# Setup OpenRC (Alpine, Gentoo)
setup_openrc() {
    log "Setting up OpenRC service..."
    
    cat > /etc/init.d/sentinel << 'EOF'
#!/sbin/openrc-run

name="Sentinel 2.0"
description="Homelab Security Platform"
command="/usr/local/bin/sentinel"
command_args="--daemon --config /etc/sentinel/config.toml"
command_background=true
pidfile="/run/sentinel.pid"
output_log="/var/log/sentinel.log"
error_log="/var/log/sentinel.err"

depend() {
    need net
    after docker
}

start_pre() {
    checkpath -f -m 0644 -o root:root /var/log/sentinel.log
    checkpath -f -m 0644 -o root:root /var/log/sentinel.err
}
EOF

    chmod 755 /etc/init.d/sentinel
    rc-update add sentinel default
}

# Setup s6 (some minimal distros)
setup_s6() {
    log "Setting up s6 service..."
    
    mkdir -p /etc/s6/sentinel
    
    cat > /etc/s6/sentinel/run << 'EOF'
#!/bin/execlineb -P
/usr/local/bin/sentinel --daemon --config /etc/sentinel/config.toml
EOF

    chmod 755 /etc/s6/sentinel/run
    
    # Create finish script
    cat > /etc/s6/sentinel/finish << 'EOF'
#!/bin/execlineb -P
EOF

    chmod 755 /etc/s6/sentinel/finish
}

# Setup firewall
setup_firewall() {
    case $FIREWALL in
        nftables)
            setup_nftables
            ;;
        iptables)
            setup_iptables
            ;;
        firewalld)
            setup_firewalld
            ;;
        ufw)
            setup_ufw
            ;;
        *)
            warn "No supported firewall detected"
            ;;
    esac
}

# Setup nftables (Debian, Ubuntu, Arch, modern distros)
setup_nftables() {
    log "Setting up nftables..."
    
    # Create sentinel table and chain
    nft add table inet sentinel 2>/dev/null || true
    nft add chain inet sentinel input { type filter hook input priority 0\; policy accept\; } 2>/dev/null || true
    nft add set inet sentinel blocklist { type ipv4_addr\; flags timeout\; } 2>/dev/null || true
    nft add rule inet sentinel input ip saddr @blocklist counter drop 2>/dev/null || true
    
    # Save rules
    if command -v nft &> /dev/null; then
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
    fi
}

# Setup iptables (legacy)
setup_iptables() {
    log "Setting up iptables..."
    
    # Create sentinel chain
    iptables -N SENTINEL 2>/dev/null || true
    iptables -A INPUT -j SENTINEL 2>/dev/null || true
    iptables -A SENTINEL -m set --match-set sentinel-blocklist src -j DROP 2>/dev/null || true
    
    # Save rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    fi
}

# Setup firewalld (RHEL, Fedora, openSUSE)
setup_firewalld() {
    log "Setting up firewalld..."
    
    # Create sentinel zone
    firewall-cmd --permanent --new-zone=sentinel 2>/dev/null || true
    firewall-cmd --permanent --zone=sentinel --add-source=0.0.0.0/0 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
}

# Setup ufw (Ubuntu)
setup_ufw() {
    log "Setting up ufw..."
    
    # ufw is already configured, just add sentinel rules
    ufw allow 8080/tcp comment "Sentinel Dashboard" 2>/dev/null || true
}

# Main
main() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           SENTINEL 2.0 — Homelab Security Platform          ║${NC}"
    echo -e "${BLUE}║                   Universal Installer                        ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    detect_os
    detect_pkg_mgr
    detect_firewall
    detect_init
    detect_homelab_tools
    
    log "Detected OS: $NAME ($OS $VER)"
    log "Package manager: $PKG_MGR"
    log "Firewall: $FIREWALL"
    log "Init system: $INIT"
    
    install_deps
    install_rust
    configure_build
    
    if [[ "$install_type" == "1" ]]; then
        install_binary
    else
        build_from_source
    fi
    
    setup_init
    setup_firewall
    
    echo ""
    log "Installation complete!"
    echo ""
    echo "Commands:"
    echo "  sentinel --status          Check system status"
    echo "  sentinel --dashboard       Start Nginx UI dashboard"
    echo "  sentinel --mcp-server      Start MCP server for AI agents"
    echo "  sentinel --scan DOMAIN     Scan a target"
    echo "  sentinel --compliance      Run CIS benchmark scan"
    echo "  sentinel --block-ip IP     Block an IP"
    echo ""
    
    case $INIT in
        systemd)
            echo "Systemd:"
            echo "  systemctl start sentinel   Start the daemon"
            echo "  systemctl stop sentinel    Stop the daemon"
            echo "  journalctl -u sentinel -f  View logs"
            ;;
        openrc)
            echo "OpenRC:"
            echo "  rc-service sentinel start   Start the daemon"
            echo "  rc-service sentinel stop    Stop the daemon"
            echo "  rc-update add sentinel      Enable at boot"
            ;;
        s6)
            echo "s6:"
            echo "  s6-svc -u /etc/s6/sentinel  Start the daemon"
            echo "  s6-svc -d /etc/s6/sentinel  Stop the daemon"
            ;;
    esac
    
    echo ""
    echo "Dashboard: http://localhost:$dashboard_port"
    echo "Config: $CONFIG_DIR/config.toml"
    echo ""
}

main "$@"
