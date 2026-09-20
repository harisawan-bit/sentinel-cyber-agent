# Sentinel 2.0 — Distribution Support Matrix

## Supported Linux Distributions

### Tier 1 — Full Support (Tested)

| Distro | Version | Package Manager | Firewall | Init | Status |
|--------|---------|-----------------|----------|------|--------|
| Ubuntu | 20.04, 22.04, 24.04 | apt | nftables/ufw | systemd | ✅ Fully Tested |
| Debian | 11, 12 | apt | nftables | systemd | ✅ Fully Tested |
| Fedora | 39, 40 | dnf | nftables/firewalld | systemd | ✅ Fully Tested |
| Rocky Linux | 8, 9 | dnf | nftables/firewalld | systemd | ✅ Fully Tested |
| AlmaLinux | 8, 9 | dnf | nftables/firewalld | systemd | ✅ Fully Tested |
| Arch Linux | Rolling | pacman | nftables | systemd | ✅ Fully Tested |
| Omarchy | Rolling | pacman | nftables | systemd | ✅ Fully Tested |
| Manjaro | Rolling | pacman | nftables | systemd | ✅ Fully Tested |

### Tier 2 — Community Support

| Distro | Version | Package Manager | Firewall | Init | Status |
|--------|---------|-----------------|----------|------|--------|
| openSUSE Leap | 15.5, 15.6 | zypper | nftables/firewalld | systemd | ⚠️ Community |
| openSUSE Tumbleweed | Rolling | zypper | nftables/firewalld | systemd | ⚠️ Community |
| Alpine Linux | 3.18+ | apk | nftables/iptables | openrc | ⚠️ Community |
| Gentoo | Rolling | portage | nftables/iptables | openrc | ⚠️ Community |
| NixOS | Rolling | nix | nftables | systemd | ⚠️ Community |
| Pop!_OS | 22.04, 24.04 | apt | nftables/ufw | systemd | ⚠️ Community |
| Linux Mint | 21, 22 | apt | nftables/ufw | systemd | ⚠️ Community |
| Elementary OS | 7, 8 | apt | nftables/ufw | systemd | ⚠️ Community |
| Zorin OS | 16, 17 | apt | nftables/ufw | systemd | ⚠️ Community |
| Kubuntu | 22.04, 24.04 | apt | nftables/ufw | systemd | ⚠️ Community |
| KDE Neon | 6.x | apt | nftables/ufw | systemd | ⚠️ Community |
| MX Linux | 23 | apt | nftables | systemd | ⚠️ Community |
| antiX | 23 | apt | iptables | systemd | ⚠️ Community |
| SparkyLinux | 7.x | apt | nftables | systemd | ⚠️ Community |
| Q4OS | 5.x | apt | nftables | systemd | ⚠️ Community |
| Devuan | 5.x | apt | nftables | sysvinit | ⚠️ Community |
| Void Linux | Rolling | xbps | nftables | runit | ⚠️ Community |
| Artix Linux | Rolling | pacman | nftables | openrc/s6/runit | ⚠️ Community |
| EndeavourOS | Rolling | pacman | nftables | systemd | ⚠️ Community |
| Garuda Linux | Rolling | pacman | nftables | systemd | ⚠️ Community |
| CachyOS | Rolling | pacman | nftables | systemd | ⚠️ Community |
| Bazzite | Rolling | rpm-ostree | nftables | systemd | ⚠️ Community |
| Universal Blue | Rolling | rpm-ostree | nftables | systemd | ⚠️ Community |
| Nobara | Rolling | dnf | nftables/firewalld | systemd | ⚠️ Community |
| Ultramarine Linux | Rolling | dnf | nftables/firewalld | systemd | ⚠️ Community |
| AerOS | Rolling | dnf | nftables/firewalld | systemd | ⚠️ Community |

### Tier 3 — Experimental

| Distro | Version | Package Manager | Firewall | Init | Status |
|--------|---------|-----------------|----------|------|--------|
| Slackware | 15.0 | pkgtools | iptables | sysvinit | 🔬 Experimental |
| CRUX | 3.x | prt-get | iptables | sysvinit | 🔬 Experimental |
| Source Mage | Rolling | sorcery | iptables | sysvinit | 🔬 Experimental |
| Lunar Linux | Rolling | lin | iptables | sysvinit | 🔬 Experimental |
| PCLinuxOS | Rolling | apt-rpm | nftables/firewalld | systemd | 🔬 Experimental |
| Mageia | 9 | urpmi | nftables/firewalld | systemd | 🔬 Experimental |
| ROSA | Rolling | urpmi | nftables/firewalld | systemd | 🔬 Experimental |
| OpenMandriva | Rolling | dnf | nftables/firewalld | systemd | 🔬 Experimental |
| Clear Linux | Rolling | swupd | nftables | systemd | 🔬 Experimental |
| Solus | 4.x | eopkg | nftables | systemd | 🔬 Experimental |
| KaOS | Rolling | pacman | nftables | systemd | 🔬 Experimental |
| Bluestar Linux | Rolling | pacman | nftables | systemd | 🔬 Experimental |
| Archcraft | Rolling | pacman | nftables | systemd | 🔬 Experimental |
| Archman | Rolling | pacman | nftables | systemd | 🔬 Experimental |
| Salix OS | 15.0 | pkgtools | iptables | sysvinit | 🔬 Experimental |
| Porteus | 5.x | pkgtools | iptables | sysvinit | 🔬 Experimental |
| Slax | 9.x | apt | iptables | sysvinit | 🔬 Experimental |
| Tiny Core Linux | 15.x | tcz | iptables | busybox | 🔬 Experimental |
| Puppy Linux | 9.x | pkg | iptables | busybox | 🔬 Experimental |
| Bodhi Linux | 7.x | apt | nftables/ufw | systemd | 🔬 Experimental |

---

## Omarchy Special Support

### What is Omarchy?

Omarchy is an opinionated Arch Linux distribution by DHH (David Heinemeier Hansson) featuring:
- **Hyprland** tiling window manager
- **Quickshell** desktop construction kit
- **Btrfs** filesystem with snapshot-safe operations
- **AI agentic** development environment
- **Curated applications**: Neovim, Spotify, Chromium, Typora, Alacritty, LibreOffice, Zoom
- **ISO-based installer** with full-disk encryption

### Omarchy-Specific Sentinel Integration

#### 1. Btrfs Snapshot Integration

```toml
[integrations.omarchy]
enabled = true
btrfs_snapshots = true
snapshot_before_scan = true
snapshot_on_remediation = true
snapshot_path = "/.snapshots/sentinel"
```

#### 2. Hyprland Notification Integration

```bash
# Send notifications via Hyprland's notification daemon
notify-send "Sentinel Alert" "Critical vulnerability detected"
```

#### 3. Omarchy Package Manager Wrapper

```bash
# Install Sentinel via Omarchy's package wrapper
omarchy install sentinel
```

#### 4. Omarchy Systemd Service

```ini
# /etc/systemd/system/sentinel.service (Omarchy variant)
[Unit]
Description=Sentinel 2.0 — Omarchy Security Platform
After=network.target hyprland-session.target

[Service]
Type=simple
Environment="HYPRLAND_INSTANCE_SIGNATURE=$HYPRLAND_INSTANCE_SIGNATURE"
ExecStart=/usr/local/bin/sentinel --daemon --config /etc/sentinel/config.toml
ExecStartPost=/usr/bin/notify-send "Sentinel" "Security monitoring started"

[Install]
WantedBy=graphical-session.target
```

#### 5. Omarchy CLI Wrapper

```bash
#!/bin/bash
# /usr/local/bin/sentinel-omarchy

case "$1" in
    status)
        sentinel --status
        ;;
    scan)
        sentinel --scan "$2"
        notify-send "Sentinel" "Scan complete for $2"
        ;;
    dashboard)
        sentinel --dashboard &
        notify-send "Sentinel" "Dashboard started on http://localhost:8080"
        ;;
    *)
        sentinel "$@"
        ;;
esac
```

---

## Firewall Support Matrix

| Distro | Default Firewall | Sentinel Support | Notes |
|--------|-----------------|------------------|-------|
| Ubuntu 22.04+ | nftables (ufw frontend) | ✅ Full | ufw commands mapped to nftables |
| Ubuntu 20.04 | nftables (ufw frontend) | ✅ Full | |
| Debian 11+ | nftables | ✅ Full | |
| Debian 10 | iptables | ✅ Full | iptables-nft available |
| Fedora 39+ | nftables (firewalld frontend) | ✅ Full | firewalld zones supported |
| RHEL 8/9 | nftables (firewalld frontend) | ✅ Full | |
| Rocky/Alma 8/9 | nftables (firewalld frontend) | ✅ Full | |
| Arch Linux | nftables | ✅ Full | |
| Omarchy | nftables | ✅ Full | |
| openSUSE | nftables (firewalld frontend) | ✅ Full | |
| Alpine | nftables/iptables | ✅ Full | |
| Gentoo | User choice | ✅ Full | Detects at install |

---

## Homelab Tool Integration Matrix

### Core Infrastructure

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Docker** | Container runtime | Full audit | docker socket / CLI |
| **Docker Compose** | Multi-container | Config parsing | YAML analysis |
| **Portainer** | Container management | API integration | HTTP API |
| **Traefik** | Reverse proxy | Config audit | File parsing |
| **Nginx Proxy Manager** | Reverse proxy | Config audit | File parsing |
| **Caddy** | Web server | Config audit | File parsing |

### Networking

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Pi-hole** | DNS + ad blocking | Blocklist correlation | API + logs |
| **AdGuard Home** | DNS + ad blocking | Blocklist correlation | API + logs |
| **Unbound** | Recursive DNS | Config audit | File parsing |
| **Bind9** | DNS server | Config audit | File parsing |
| **WireGuard** | VPN | Peer monitoring | wg CLI |
| **Headscale** | WireGuard mesh | Peer monitoring | API |
| **Tailscale** | Mesh VPN | Status monitoring | CLI |
| **OpenVPN** | VPN | Config audit | File parsing |
| **IPsec** | VPN | Config audit | File parsing |
| **Nginx** | Web server | Config audit | File parsing |
| **Apache** | Web server | Config audit | File parsing |
| **HAProxy** | Load balancer | Config audit | File parsing |
| **pfSense** | Firewall | Log correlation | Syslog |
| **OPNsense** | Firewall | Log correlation | Syslog |

### Virtualization

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Proxmox VE** | Hypervisor | Full audit | API |
| **XCP-ng** | Hypervisor | VM monitoring | API |
| **KVM/QEMU** | Hypervisor | Config audit | File parsing |
| **VirtualBox** | Hypervisor | VM monitoring | CLI |
| **VMware ESXi** | Hypervisor | VM monitoring | API |
| **LXC** | Containers | Config audit | File parsing |
| **Incus** | Containers | Config audit | API |
| **Podman** | Containers | Full audit | socket / CLI |

### Monitoring

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Grafana** | Dashboards | Dashboard integration | API |
| **Prometheus** | Metrics | Alert correlation | API |
| **Uptime Kuma** | Uptime monitoring | Status correlation | API |
| **Zabbix** | Monitoring | Alert correlation | API |
| **Nagios** | Monitoring | Alert correlation | API |
| **Netdata** | Real-time metrics | Metric correlation | API |
| **Glances** | System monitor | Metric correlation | API |
| **Cockpit** | Server management | Status correlation | API |
| **Webmin** | Server management | Status correlation | API |

### Storage

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **TrueNAS Scale** | NAS | Storage monitoring | API |
| **TrueNAS Core** | NAS | Storage monitoring | API |
| **OpenMediaVault** | NAS | Storage monitoring | API |
| **Syncthing** | File sync | Config audit | API |
| **Nextcloud** | File sync/share | Security audit | API |
| **Seafile** | File sync/share | Security audit | API |
| **ownCloud** | File sync/share | Security audit | API |
| **MinIO** | Object storage | Config audit | API |
| **Ceph** | Distributed storage | Health monitoring | CLI |
| **GlusterFS** | Distributed storage | Health monitoring | CLI |
| **ZFS** | Filesystem | Health monitoring | CLI |
| **Btrfs** | Filesystem | Health monitoring | CLI |
| **Samba** | File sharing | Config audit | File parsing |
| **NFS** | File sharing | Config audit | File parsing |

### Media

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Jellyfin** | Media server | Security audit | API |
| **Plex** | Media server | Security audit | API |
| **Emby** | Media server | Security audit | API |
| **Kodi** | Media center | Config audit | File parsing |
| **Navidrome** | Music server | Security audit | API |
| **Airsonic** | Music server | Security audit | API |
| **Nymphcast** | Media streamer | Config audit | File parsing |

### *arr Stack

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Sonarr** | TV shows | Config audit | API |
| **Radarr** | Movies | Config audit | API |
| **Prowlarr** | Indexer manager | Config audit | API |
| **Lidarr** | Music | Config audit | API |
| **Readarr** | Books | Config audit | API |
| **Whisparr** | Adult content | Config audit | API |
| **Bazarr** | Subtitles | Config audit | API |
| **LunaSea** | Mobile manager | Config audit | API |

### Automation

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Home Assistant** | Home automation | Full integration | API |
| **Node-RED** | Flow automation | Config audit | API |
| **n8n** | Workflow automation | Config audit | API |
| **Huginn** | Automation | Config audit | API |
| **Activepieces** | Automation | Config audit | API |
| **Automatisch** | Automation | Config audit | API |

### Password Management

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Vaultwarden** | Password manager | Security audit | API |
| **Bitwarden** | Password manager | Security audit | API |
| **Passbolt** | Password manager | Security audit | API |
| **Padloc** | Password manager | Security audit | API |
| **TeamPass** | Password manager | Security audit | API |

### Communication

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Matrix** | Messaging | Server monitoring | API |
| **Synapse** | Matrix server | Server monitoring | API |
| **Dendrite** | Matrix server | Server monitoring | API |
| **Element** | Matrix client | Config audit | File parsing |
| **Mattermost** | Messaging | Server monitoring | API |
| **Rocket.Chat** | Messaging | Server monitoring | API |
| **Zulip** | Messaging | Server monitoring | API |
| **Discord** | Messaging | Bot integration | Webhook |
| **Slack** | Messaging | Bot integration | Webhook |
| **Telegram** | Messaging | Bot integration | Bot API |

### Development

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Gitea** | Git hosting | Security audit | API |
| **Forgejo** | Git hosting | Security audit | API |
| **GitLab** | Git hosting | Security audit | API |
| **Gogs** | Git hosting | Security audit | API |
| **Drone CI** | CI/CD | Config audit | API |
| **Woodpecker CI** | CI/CD | Config audit | API |
| **Jenkins** | CI/CD | Config audit | API |
| **Forgejo Actions** | CI/CD | Config audit | API |

### Database

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **PostgreSQL** | Database | Config audit | File parsing |
| **MySQL/MariaDB** | Database | Config audit | File parsing |
| **MongoDB** | Database | Config audit | File parsing |
| **Redis** | Cache | Config audit | File parsing |
| **Memcached** | Cache | Config audit | File parsing |
| **CouchDB** | Database | Config audit | File parsing |
| **InfluxDB** | Time series | Config audit | API |
| **TimescaleDB** | Time series | Config audit | File parsing |

### Security Tools

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **CrowdSec** | IPS | Full integration | API |
| **fail2ban** | IPS | Log correlation | CLI |
| **Wazuh** | SIEM/XDR | Alert correlation | API |
| **OSSEC** | HIDS | Alert correlation | API |
| **Snort** | NIDS | Alert correlation | Unified2 |
| **Suricata** | NIDS | Alert correlation | EVE JSON |
| **Zeek** | NIDS | Alert correlation | Logs |
| **ModSecurity** | WAF | Alert correlation | Audit logs |
| **Nessus** | Vuln scanner | Scan import | API |
| **OpenVAS** | Vuln scanner | Scan import | API |
| **Greenbone** | Vuln scanner | Scan import | API |
| **ClamAV** | Antivirus | Full integration | clamd |
| **YARA** | Pattern matching | Full integration | CLI |
| **CrowdStrike** | EDR | Alert correlation | API |
| **SentinelOne** | EDR | Alert correlation | API |

### Backup

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Proxmox Backup** | VM backup | Status monitoring | API |
| **Borg** | Deduplicating backup | Status monitoring | CLI |
| **Restic** | Deduplicating backup | Status monitoring | CLI |
| **Duplicati** | Cloud backup | Status monitoring | API |
| **Urbackup** | File backup | Status monitoring | API |
| **Bareos** | Enterprise backup | Status monitoring | API |
| **Bacula** | Enterprise backup | Status monitoring | API |
| **Kopia** | Backup | Status monitoring | CLI |
| **Syncthing** | File sync | Config audit | API |
| **Rsync** | File sync | Config audit | File parsing |

### Dashboards

| Tool | Purpose | Sentinel Integration | Detection Method |
|------|---------|---------------------|------------------|
| **Homepage** | Dashboard | Widget integration | API |
| **Homarr** | Dashboard | Widget integration | API |
| **Dashy** | Dashboard | Widget integration | API |
| **Glance** | Dashboard | Widget integration | API |
| **Heimdall** | Dashboard | Widget integration | API |
| **Flame** | Dashboard | Widget integration | API |
| **Homer** | Dashboard | Widget integration | API |
| **Fenrus** | Dashboard | Widget integration | API |
| **Organizr** | Dashboard | Widget integration | API |
| **Mozaik** | Dashboard | Widget integration | API |

---

## Installation by Distro

### Ubuntu/Debian

```bash
curl -fsSL sentinel.security/install.sh | bash
```

Or manual:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
sudo systemctl enable --now sentinel
```

### Fedora/RHEL/Rocky/Alma

```bash
curl -fsSL sentinel.security/install.sh | bash
```

Or manual:

```bash
sudo dnf install -y gcc gcc-c++ openssl-devel nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
sudo systemctl enable --now sentinel
```

### Arch Linux / Omarchy / Manjaro

```bash
curl -fsSL sentinel.security/install.sh | bash
```

Or manual:

```bash
sudo pacman -S --needed base-devel openssl nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
sudo systemctl enable --now sentinel
```

### Omarchy (Special)

```bash
# Omarchy uses the same Arch commands, but with Btrfs snapshot support
sudo pacman -S --needed base-devel openssl nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/

# Create Btrfs snapshot before first run
sudo btrfs subvolume snapshot / //.snapshots/sentinel-pre-install

sudo systemctl enable --now sentinel
```

### openSUSE

```bash
curl -fsSL sentinel.security/install.sh | bash
```

Or manual:

```bash
sudo zypper install -y gcc gcc-c++ libopenssl-devel nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
sudo systemctl enable --now sentinel
```

### Alpine Linux

```bash
curl -fsSL sentinel.security/install.sh | bash
```

Or manual:

```bash
apk add build-base openssl-dev curl git nftables clamav yara docker
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
rc-update add sentinel default
rc-service sentinel start
```

### NixOS

```nix
# configuration.nix
{ config, pkgs, ... }:

{
  environment.systemPackages = with pkgs; [
    sentinel
  ];

  systemd.services.sentinel = {
    description = "Sentinel 2.0 — Homelab Security Platform";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.sentinel}/bin/sentinel --daemon --config /etc/sentinel/config.toml";
      Restart = "always";
      RestartSec = "10";
    };
  };
}
```

### Void Linux

```bash
sudo xbps-install -S base-devel openssl-devel curl git nftables clamav yara
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
sudo cp target/release/sentinel /usr/local/bin/
sudo ln -s /etc/sv/sentinel /var/service/
```

---

## Troubleshooting by Distro

### Ubuntu/Debian

**Issue**: `nft: command not found`
```bash
sudo apt-get install nftables
sudo systemctl enable nftables
```

**Issue**: `clamd: command not found`
```bash
sudo apt-get install clamav-daemon
sudo systemctl enable clamav-daemon
sudo freshclam
```

### Fedora/RHEL

**Issue**: `firewalld conflicts with nftables`
```bash
# Sentinel uses nftables directly, firewalld is optional
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl enable nftables
```

### Arch/Omarchy

**Issue**: `pacman: target not found`
```bash
sudo pacman -Syu
# Some packages may be in AUR
yay -S yara
```

### Alpine

**Issue**: `musl vs glibc`
```bash
# Sentinel compiles against musl on Alpine
# No action needed, Rust handles this automatically
```

### openSUSE

**Issue**: `zypper: package not found`
```bash
sudo zypper refresh
sudo zypper install -y gcc-c++ libopenssl-devel
```

---

## Contributing Distro Support

To add support for a new distribution:

1. Add detection to `install.sh`
2. Add package mapping
3. Add firewall detection
4. Add init system detection
5. Test in VM
6. Update this document
7. Submit PR

---

## Notes

- All distros use the same Rust binary (compiled from source)
- Pre-compiled binaries available for x86_64
- ARM64 support planned (Raspberry Pi, Apple Silicon)
- musl support for Alpine and other musl-based distros
- systemd is preferred but OpenRC and s6 are supported
