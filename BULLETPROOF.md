# Sentinel 2.0 — Bulletproof Security Architecture

## Research-Based Hardening Guide

---

## 1. Memory Safety (Rust Advantage)

### Why Rust is the Foundation

| Vulnerability Class | C/C++ | Rust | Impact |
|---------------------|-------|------|--------|
| Buffer Overflow | Common | Impossible | Critical |
| Use-After-Free | Common | Impossible | Critical |
| Double Free | Common | Impossible | Critical |
| Null Pointer Dereference | Common | Impossible (Option<T>) | High |
| Data Races | Common | Impossible (Send/Sync) | High |
| Integer Overflow | Common | Debug: panic, Release: wrap | Medium |
| Format String Attacks | Common | Impossible (compile-time) | Critical |

### Rust Security Best Practices for Sentinel

```rust
// 1. Minimize unsafe blocks
// BAD
unsafe { libc::some_function() }
// GOOD
// Use safe abstractions from crates like `nix` or `libc` wrappers

// 2. Use compile-time checks
const fn validate_config() -> bool {
    // Compile-time validation
    true
}

// 3. Leverage the type system
struct NonEmptyVec<T>(Vec<T>);
impl<T> NonEmptyVec<T> {
    fn new(first: T) -> Self {
        NonEmptyVec(vec![first])
    }
}

// 4. Use #[deny(unsafe_code)] in security-critical modules
#[deny(unsafe_code)]
mod crypto {
    // Only safe Rust allowed
}
```

### Unsafe Code Audit

```bash
# Count unsafe blocks
grep -r "unsafe" src/ | wc -l

# Find all unsafe blocks with context
grep -r -B 2 -A 5 "unsafe" src/

# Use cargo-geiger for comprehensive audit
cargo install cargo-geiger
cargo geiger --all-features
```

---

## 2. Supply Chain Security

### The Threat Landscape (2025-2026)

- **DPRK supply chain attacks** on Rust crates (arrayref incident)
- **Typosquatting** attacks on crates.io
- **AI-generated malicious crates**
- **Dependency confusion** attacks
- **Maintainer account takeovers**

### Defense in Depth

#### Layer 1: Dependency Auditing

```toml
# Cargo.toml - Pin exact versions
[dependencies]
tokio = { version = "=1.53.1", features = ["full"] }
serde = { version = "=1.0.229" }
```

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit

# Continuous monitoring in CI
cargo audit --deny warnings
```

#### Layer 2: Policy Enforcement with cargo-deny

```toml
# deny.toml
[advisories]
db-urls = ["https://github.com/rustsec/advisory-db"]
db-path = "~/.cargo/advisory-dbs"
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"
allow = []
deny = []
skip = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

#### Layer 3: Dependency Verification with cargo-vet

```bash
# Install cargo-vet
cargo install cargo-vet

# Initialize
cargo vet init

# Import audits from trusted sources
cargo vet import "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"

# Verify all dependencies
cargo vet
```

#### Layer 4: SBOM Generation

```bash
# Install cargo-sbom
cargo install cargo-sbom

# Generate SBOM
cargo spdx > sentinel-sbom.json
cargo cyclonedx > sentinel-cyclonedx.json
```

#### Layer 5: Checksum Verification

```bash
# Verify Cargo.lock integrity
cargo generate-lockfile
cargo verify-package

# Pin checksums in CI
sha256sum Cargo.lock > Cargo.lock.sha256
```

### Supply Chain CI/CD Integration

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          components: clippy
      
      - name: Install cargo-audit
        run: cargo install cargo-audit
      
      - name: Run cargo audit
        run: cargo audit --deny warnings
      
      - name: Install cargo-deny
        run: cargo install cargo-deny
      
      - name: Run cargo deny
        run: cargo deny check
      
      - name: Install cargo-vet
        run: cargo install cargo-vet
      
      - name: Run cargo vet
        run: cargo vet
      
      - name: Generate SBOM
        run: |
          cargo install cargo-spdx
          cargo spdx > sentinel-sbom.json
      
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sentinel-sbom.json
```

---

## 3. Service Hardening (systemd)

### Security Hardening Options

```ini
# /etc/systemd/system/sentinel.service
[Unit]
Description=Sentinel 2.0 — Homelab Security Platform
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel --daemon --config /etc/sentinel/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
User=sentinel
Group=sentinel

# === PRIVILEGE DROPPING ===
# Run as non-root user
User=sentinel
Group=sentinel

# === FILESYSTEM PROTECTION ===
# Read-only root filesystem
ProtectSystem=strict
# Read-write paths
ReadWritePaths=/var/lib/sentinel /etc/sentinel /tmp
# Read-only paths
ReadOnlyPaths=/usr/share/sentinel
# No write to /usr
ProtectHome=true
# Private /tmp
PrivateTmp=true
# Private /dev
PrivateDevices=true
# Private /run
PrivateRuntime=true

# === KERNEL CAPABILITIES ===
# Drop all capabilities
CapabilityBoundingSet=
# Ambient capabilities
AmbientCapabilities=
# Secure bits
NoNewPrivileges=true
# File system capabilities
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

# === NAMESPACE ISOLATION ===
# Private network namespace (if not needed)
# PrivateNetwork=true
# Private users
PrivateUsers=true
# Protect control groups
ProtectControlGroups=true
# Protect clock
ProtectClock=true
# Protect kernel logs
ProtectKernelLogs=true
# Protect kernel modules
ProtectKernelModules=true
# Protect kernel tunables
ProtectKernelTunables=true
# Protect hostname
ProtectHostname=true
# Protect home
ProtectHome=true
# Protect proc
ProtectProc=invisible
# Protect system
ProtectSystem=strict
# Restrict address families
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Restrict namespaces
RestrictNamespaces=true
# Restrict realtime
RestrictRealtime=true
# Restrict SUID/SGID
RestrictSUIDSGID=true
# System call filter
SystemCallFilter=@system-service
SystemCallArchitectures=native

# === RESOURCE LIMITS ===
# Memory limit
MemoryMax=200M
MemoryHigh=150M
# CPU limit
CPUQuota=10%
# Task limit
TasksMax=50
# File descriptor limit
LimitNOFILE=1024:4096
# Process limit
LimitNPROC=50
# Core dump limit
LimitCORE=0
# File size limit
LimitFSIZE=100M
# Stack size limit
LimitSTACK=8M

# === LOGGING ===
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel
# Log level
Environment=RUST_LOG=info

# === ENVIRONMENT ===
# Minimal environment
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
Environment="HOME=/var/lib/sentinel"
# Remove environment
UnsetEnvironment=LD_PRELOAD,LD_LIBRARY_PATH

[Install]
WantedBy=multi-user.target
```

### Dedicated User Setup

```bash
# Create sentinel user
useradd --system --no-create-home --shell /usr/sbin/nologin sentinel

# Create directories
mkdir -p /var/lib/sentinel
mkdir -p /etc/sentinel
mkdir -p /usr/share/sentinel/dashboard

# Set ownership
chown -R sentinel:sentinel /var/lib/sentinel
chown -R sentinel:sentinel /etc/sentinel
chown -R sentinel:sentinel /usr/share/sentinel

# Set permissions
chmod 750 /var/lib/sentinel
chmod 750 /etc/sentinel
chmod 755 /usr/share/sentinel/dashboard

# Set ACL for binary
setfacl -m u:sentinel:rx /usr/local/bin/sentinel
```

---

## 4. Network Security

### Firewall Rules (nftables)

```bash
#!/bin/bash
# /etc/nftables.d/sentinel.nft

#!/usr/sbin/nft -f

# Flush existing rules
flush ruleset

table inet sentinel {
    # Blocklist with automatic timeout
    set blocklist {
        type ipv4_addr
        flags timeout
        timeout 24h
    }
    
    # Rate limiting set
    set rate_limit {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1m
    }
    
    # Whitelisted IPs
    set whitelist {
        type ipv4_addr
        flags interval
        elements = { 127.0.0.1, 192.168.1.0/24, 10.0.0.0/8 }
    }
    
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow loopback
        iif "lo" accept
        
        # Allow established/related
        ct state established,related accept
        
        # Drop invalid
        ct state invalid drop
        
        # Allow whitelist
        ip saddr @whitelist accept
        
        # Drop blocklist
        ip saddr @blocklist counter drop
        
        # Rate limiting
        tcp dport { 22, 8080 } \
            add @rate_limit { ip saddr limit rate 10/minute } \
            accept
        
        # Allow SSH (rate limited)
        tcp dport 22 \
            ct state new \
            limit rate 5/minute \
            accept
        
        # Allow dashboard (rate limited)
        tcp dport 8080 \
            ct state new \
            limit rate 20/minute \
            accept
        
        # Allow ICMP (rate limited)
        ip protocol icmp \
            icmp type echo-request \
            limit rate 5/second \
            accept
        
        # Log and drop everything else
        counter log prefix "sentinel-drop: " drop
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Allow loopback
        oif "lo" accept
        
        # Allow established/related
        ct state established,related accept
        
        # Allow DNS
        udp dport 53 accept
        tcp dport 53 accept
        
        # Allow HTTP/HTTPS
        tcp dport { 80, 443 } accept
        
        # Allow NTP
        udp dport 123 accept
        
        # Log and drop everything else
        counter log prefix "sentinel-output-drop: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Log and drop everything else
        counter log prefix "sentinel-forward-drop: " drop
    }
}
```

### VLAN Segmentation Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                        INTERNET                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    OPNsense/pfSense                           │
│                    (Firewall/Router)                         │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   VLAN 10    │    │   VLAN 20    │    │   VLAN 30    │
│   MGMT       │    │   SERVERS    │    │   CLIENTS    │
│   10.0.10/24 │    │   10.0.20/24 │    │   10.0.30/24 │
├──────────────┤    ├──────────────┤    ├──────────────┤
│ Proxmox      │    │ Docker Host  │    │ Laptops      │
│ OPNsense     │    │ NAS          │    │ Phones       │
│ Sentinel     │    │ Pi-hole      │    │ Tablets      │
│ Monitoring   │    │ Services     │    │ IoT          │
└──────────────┘    └──────────────┘    └──────────────┘
```

---

## 5. Docker Security

### Docker Daemon Hardening

```json
// /etc/docker/daemon.json
{
    "icc": false,
    "iptables": true,
    "userns-remap": "default",
    "no-new-privileges": true,
    "userland-proxy": false,
    "live-restore": true,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "default-address-pools": [
        {
            "base": "172.17.0.0/16",
            "size": 24
        }
    ],
    "tls": true,
    "tlscacert": "/etc/docker/ca.pem",
    "tlscert": "/etc/docker/server-cert.pem",
    "tlskey": "/etc/docker/server-key.pem",
    "tlsverify": true
}
```

### Container Security Scanning

```bash
# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list
apt-get update && apt-get install -y trivy

# Scan image
trivy image --severity HIGH,CRITICAL sentinel:latest

# Scan filesystem
trivy fs --severity HIGH,CRITICAL /

# Scan config
trivy config --severity HIGH,CRITICAL Dockerfile
```

### Docker Compose Security

```yaml
# docker-compose.yml with security hardening
version: '3.8'

services:
  sentinel:
    image: sentinel:latest
    read_only: true
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
    security_opt:
      - no-new-privileges:true
      - apparmor=sentinel-profile
      - seccomp=sentinel-seccomp.json
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    volumes:
      - sentinel-data:/var/lib/sentinel
      - /etc/sentinel:/etc/sentinel:ro
    networks:
      - sentinel-net
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 200M
        reservations:
          cpus: '0.25'
          memory: 100M
    healthcheck:
      test: ["CMD", "sentinel", "--status"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    restart: unless-stopped

volumes:
  sentinel-data:
    driver: local

networks:
  sentinel-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

---

## 6. SSH Hardening

### Server Configuration

```bash
# /etc/ssh/sshd_config.d/sentinel.conf

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30

# Cryptography
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Access control
AllowUsers sentinel
DenyUsers root
AllowGroups sentinel

# Banner
Banner /etc/ssh/banner

# SFTP
Subsystem sftp internal-sftp -f AUTH -l INFO
```

### Client Configuration

```bash
# ~/.ssh/config
Host sentinel
    HostName sentinel.local
    User sentinel
    Port 22
    IdentityFile ~/.ssh/sentinel_ed25519
    IdentitiesOnly yes
    AddKeysToAgent yes
    ForwardAgent no
    ForwardX11 no
    ServerAliveInterval 60
    ServerAliveCountMax 3
    StrictHostKeyChecking yes
    VisualHostKey yes
```

---

## 7. Secrets Management

### Encryption at Rest

```rust
// Use ring for encryption
use ring::aead;
use ring::rand;

// Generate key
let rng = rand::SystemRandom::new();
let mut key_bytes = vec![0u8; 32];
rng.fill(&mut key_bytes)?;

// Encrypt
let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
let sealing_key = aead::SealingKey::new(
    aead::AES_256_GCM,
    &key_bytes,
)?;

// Store key in kernel keyring (Linux)
// Or use systemd-credentials
```

### systemd-Credentials Integration

```bash
# Store credential
systemd-creds encrypt --name=sentinel-telegram-token - /etc/sentinel/creds/telegram.token < token.txt

# Load in service
LoadCredential=sentinel-telegram-token:/etc/sentinel/creds/telegram.token
```

### HashiCorp Vault Integration (Optional)

```rust
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::secret::kv2;

let client = VaultClient::new(
    VaultClientSettingsBuilder::default()
        .address("https://vault.local:8200")
        .token(std::env::var("VAULT_TOKEN")?)
        .build()?
)?;

let secret: String = kv2::read(&client, "secret", "sentinel/telegram").await?;
```

---

## 8. Audit Logging

### Comprehensive Audit Configuration

```bash
# /etc/audit/rules.d/sentinel.rules

# Monitor sentinel binary
-w /usr/local/bin/sentinel -p wa -k sentinel-binary
-w /etc/sentinel/ -p wa -k sentinel-config
-w /var/lib/sentinel/ -p wa -k sentinel-data

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/nftables.conf -p wa -k firewall

# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity

# Monitor systemd
-w /etc/systemd/ -p wa -k systemd
-w /run/systemd/ -p wa -k systemd

# Monitor Docker
-w /etc/docker/ -p wa -k docker
-w /var/run/docker.sock -p wa -k docker

# Monitor SSH
-w /etc/ssh/ -p wa -k ssh
-w /root/.ssh/ -p wa -k ssh

# Make rules immutable
-e 2
```

### Log Forwarding

```yaml
# /etc/promtail/config.yml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: sentinel
    static_configs:
      - targets:
          - localhost
        labels:
          job: sentinel
          __path__: /var/log/sentinel/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            message: msg
            timestamp: timestamp
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: RFC3339
```

---

## 9. Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# /usr/local/bin/sentinel-backup.sh

set -euo pipefail

BACKUP_DIR="/var/backups/sentinel"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration
tar czf "$BACKUP_DIR/config-$DATE.tar.gz" \
    /etc/sentinel/ \
    /usr/local/bin/sentinel \
    /etc/systemd/system/sentinel.service

# Backup database
sqlite3 /var/lib/sentinel/findings.db ".backup '$BACKUP_DIR/findings-$DATE.db'"

# Encrypt backup
gpg --symmetric --cipher-algo AES256 \
    --output "$BACKUP_DIR/config-$DATE.tar.gz.gpg" \
    "$BACKUP_DIR/config-$DATE.tar.gz"

# Remove unencrypted backup
rm "$BACKUP_DIR/config-$DATE.tar.gz"

# Upload to remote (optional)
rclone copy "$BACKUP_DIR/config-$DATE.tar.gz.gpg" remote:sentinel-backups/

# Clean old backups
find "$BACKUP_DIR" -type f -mtime +$RETENTION_DAYS -delete

# Verify backup
gpg --decrypt "$BACKUP_DIR/config-$DATE.tar.gz.gpg" | tar tzf - > /dev/null
```

### Disaster Recovery

```bash
#!/bin/bash
# /usr/local/bin/sentinel-restore.sh

set -euo pipefail

BACKUP_FILE="$1"

# Decrypt backup
gpg --decrypt "$BACKUP_FILE" | tar xzf - -C /

# Restore database
cp /var/lib/sentinel/findings.db /var/lib/sentinel/findings.db.bak
sqlite3 /var/lib/sentinel/findings.db ".restore '/var/lib/sentinel/findings.db'"

# Restart service
systemctl daemon-reload
systemctl restart sentinel

# Verify
sentinel --status
```

---

## 10. Incident Response

### Automated Response Playbook

```rust
// src/response/playbook.rs

pub async fn handle_critical_finding(finding: &Finding) -> Result<()> {
    match finding.finding_type.as_str() {
        "ransomware_detected" => {
            // 1. Isolate affected container/host
            isolate_container(&finding.target).await?;
            // 2. Create Btrfs snapshot
            create_snapshot("pre-incident").await?;
            // 3. Block malicious IPs
            block_ip(&finding.value).await?;
            // 4. Alert admin
            send_alert("CRITICAL", "Ransomware detected", &finding.detail).await?;
            // 5. Preserve evidence
            preserve_logs(&finding.target).await?;
        }
        "brute_force" => {
            // 1. Block attacker IP
            block_ip(&finding.value).await?;
            // 2. Rate limit source
            rate_limit(&finding.value).await?;
            // 3. Alert if persistent
            if is_persistent_attack(&finding.value).await? {
                send_alert("HIGH", "Persistent brute force", &finding.detail).await?;
            }
        }
        "data_exfiltration" => {
            // 1. Block outbound connection
            block_outbound(&finding.value).await?;
            // 2. Capture traffic
            capture_traffic(&finding.target).await?;
            // 3. Alert immediately
            send_alert("CRITICAL", "Data exfiltration detected", &finding.detail).await?;
        }
        _ => {}
    }
    Ok(())
}
```

---

## 11. Compliance Mapping

### CIS Benchmark Alignment

| CIS Control | Sentinel Implementation |
|-------------|------------------------|
| 1.1 | Filesystem integrity monitoring (AIDE/Tripwire) |
| 1.2 | Secure boot verification |
| 2.1 | Service enumeration and hardening |
| 3.1 | Network parameter tuning (sysctl) |
| 3.2 | Firewall configuration (nftables) |
| 3.3 | Wireless disable |
| 4.1 | Audit configuration (auditd) |
| 4.2 | Log forwarding (Promtail/Loki) |
| 5.1 | SSH hardening |
| 5.2 | PAM configuration |
| 6.1 | User account management |
| 6.2 | Sudo configuration |
| 7.1 | Password policies |
| 7.2 | Failed login monitoring |
| 8.1 | Malware scanning (ClamAV/YARA) |
| 8.2 | Application whitelisting |
| 9.1 | Vulnerability scanning |
| 9.2 | Patch management |
| 10.1 | Data encryption |
| 10.2 | Backup verification |
| 11.1 | Network segmentation |
| 11.2 | DNS filtering |
| 12.1 | Incident response plan |
| 12.2 | Incident response testing |
| 13.1 | Security awareness |
| 13.2 | Data classification |
| 14.1 | Access control |
| 14.2 | Session management |
| 15.1 | Asset management |
| 15.2 | Software inventory |
| 16.1 | Account monitoring |
| 16.2 | Privileged access |
| 17.1 | Continuous monitoring |
| 17.2 | Threat intelligence |
| 18.1 | Penetration testing |
| 18.2 | Red team exercises |

---

## 12. Security Testing

### Penetration Testing Checklist

```bash
# 1. Port scanning
nmap -sS -sV -O -p- sentinel.local

# 2. Vulnerability scanning
openvas --target=sentinel.local

# 3. SSL/TLS testing
testssl.sh sentinel.local:8080

# 4. HTTP security headers
curl -I http://sentinel.local:8080

# 5. Authentication testing
hydra -l sentinel -P wordlist.txt sentinel.local ssh

# 6. SQL injection testing
sqlmap -u "http://sentinel.local:8080/api/findings?id=1"

# 7. XSS testing
xsstrike -u "http://sentinel.local:8080/search?q="

# 8. Fuzzing
ffuf -u http://sentinel.local:8080/FUZZ -w wordlist.txt

# 9. Dependency scanning
cargo audit
cargo deny check

# 10. Container scanning
trivy image sentinel:latest

# 11. Configuration review
lynis audit system

# 12. File integrity
aide --check
```

### Fuzzing

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Initialize fuzzing
cargo fuzz init

# Run fuzzer
cargo fuzz run parser_fuzz
```

---

## 13. Monitoring and Alerting

### Security Metrics to Track

| Metric | Threshold | Alert |
|--------|-----------|-------|
| Failed SSH logins | > 5/min | HIGH |
| New listening ports | Any change | MEDIUM |
| File integrity changes | Any change | HIGH |
| Privilege escalation | Any | CRITICAL |
| Container escape | Any | CRITICAL |
| Data exfiltration | Any | CRITICAL |
| Ransomware indicators | Any | CRITICAL |
| Brute force attempts | > 10/min | HIGH |
| SQL injection attempts | Any | HIGH |
| XSS attempts | Any | MEDIUM |
| Dependency vulnerabilities | Any HIGH | MEDIUM |
| Certificate expiry | < 30 days | MEDIUM |
| Backup failure | Any | HIGH |
| Disk usage | > 90% | MEDIUM |
| Memory usage | > 90% | MEDIUM |
| CPU usage | > 95% | LOW |

### Prometheus Alerting Rules

```yaml
# /etc/prometheus/rules/sentinel.yml
groups:
  - name: sentinel-security
    rules:
      - alert: SentinelHighFailedSSH
        expr: rate(sentinel_ssh_failed_total[5m]) > 5
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "High rate of failed SSH logins"
          
      - alert: SentinelFileIntegrityViolation
        expr: sentinel_file_integrity_violations_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "File integrity violation detected"
          
      - alert: SentinelContainerEscape
        expr: sentinel_container_escape_attempts_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Container escape attempt detected"
          
      - alert: SentinelDataExfiltration
        expr: sentinel_data_exfiltration_bytes > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Potential data exfiltration detected"
          
      - alert: SentinelRansomwareDetected
        expr: sentinel_ransomware_indicators_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Ransomware indicators detected"
          
      - alert: SentinelVulnerabilityFound
        expr: sentinel_vulnerabilities_total{severity="critical"} > 0
        for: 0m
        labels:
          severity: high
        annotations:
          summary: "Critical vulnerability found"
          
      - alert: SentinelBackupFailed
        expr: sentinel_backup_status != 1
        for: 1h
        labels:
          severity: high
        annotations:
          summary: "Backup failed"
          
      - alert: SentinelCertificateExpiring
        expr: sentinel_certificate_expiry_days < 30
        for: 1d
        labels:
          severity: medium
        annotations:
          summary: "Certificate expiring in {{ $value }} days"
```

---

## 14. Update and Patch Management

### Automated Updates

```bash
#!/bin/bash
# /usr/local/bin/sentinel-update.sh

set -euo pipefail

# Update system packages
case $(cat /etc/os-release | grep ^ID= | cut -d= -f2) in
    ubuntu|debian)
        apt-get update
        apt-get upgrade -y
        apt-get autoremove -y
        ;;
    fedora)
        dnf upgrade -y
        dnf autoremove -y
        ;;
    arch)
        pacman -Syu --noconfirm
        ;;
esac

# Update Rust toolchain
rustup update

# Update cargo tools
cargo install cargo-audit --force
cargo install cargo-deny --force
cargo install cargo-vet --force

# Update Sentinel
cd /tmp
rm -rf sentinel-cyber-agent
git clone --depth 1 https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent
cargo build --release
systemctl stop sentinel
cp target/release/sentinel /usr/local/bin/sentinel
systemctl start sentinel

# Verify
sentinel --status

# Update ClamAV signatures
freshclam

# Update YARA rules
cd /etc/sentinel/yara-rules
git pull

# Update threat intelligence
sentinel --update-threat-intel
```

---

## 15. Security Checklist

### Pre-Deployment

- [ ] Memory safety audit (cargo-geiger)
- [ ] Dependency audit (cargo-audit)
- [ ] License compliance (cargo-deny)
- [ ] Dependency verification (cargo-vet)
- [ ] SBOM generation
- [ ] Static analysis (clippy)
- [ ] Fuzz testing
- [ ] Penetration testing
- [ ] Configuration review
- [ ] Firewall rules review
- [ ] SSH hardening verification
- [ ] Backup verification
- [ ] Incident response plan
- [ ] Monitoring setup
- [ ] Alert channels tested

### Runtime

- [ ] Service running as non-root
- [ ] Filesystem read-only where possible
- [ ] Capabilities dropped
- [ ] Seccomp filter active
- [ ] AppArmor/SELinux profile loaded
- [ ] Resource limits enforced
- [ ] Audit logging active
- [ ] Log forwarding working
- [ ] Backup running
- [ ] Monitoring active
- [ ] Alert channels working
- [ ] Certificate valid
- [ ] Dependencies up to date
- [ ] Threat intel updated
- [ ] Firewall rules active

### Periodic

- [ ] Weekly: Dependency audit
- [ ] Weekly: Vulnerability scan
- [ ] Weekly: Backup test
- [ ] Monthly: Penetration test
- [ ] Monthly: Configuration review
- [ ] Monthly: Access review
- [ ] Quarterly: Disaster recovery test
- [ ] Quarterly: Incident response drill
- [ ] Annually: Full security audit

---

## 16. References

### Standards

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- RustSec Advisory Database: https://rustsec.org/
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Tools

- cargo-audit: https://github.com/rustsec/rustsec
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny
- cargo-vet: https://github.com/mozilla/cargo-vet
- cargo-geiger: https://github.com/rust-secure-code/cargo-geiger
- Trivy: https://github.com/aquasecurity/trivy
- Lynis: https://github.com/CISOfy/lynis
- OpenVAS: https://github.com/greenbone/openvas

### Research

- Memory Safe Languages (DoD): https://media.defense.gov/2025/Jun/23/2003742198/-1/-1/0/CSI_MEMORY_SAFE_LANGUAGES_REDUCING_VULNERABILITIES_IN_MODERN_SOFTWARE_DEVELOPMENT.PDF
- Rust Security Practices: https://corrode.dev/blog/memory-safety/
- Supply Chain Security: https://tuxcare.com/blog/cargo-audit-rust-security/
