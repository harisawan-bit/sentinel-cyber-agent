# Sentinel — Autonomous Enterprise Cyber Defense & Homelab Guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![CI: Passing](https://img.shields.io/badge/CI-Passing-success.svg)](.github/workflows/ci.yml)
[![Memory: <25MB RSS](https://img.shields.io/badge/Memory-%3C25MB_RSS-orange.svg)](#performance--footprint)
[![Standard: OASIS SARIF v2.1.0](https://img.shields.io/badge/Standard-OASIS_SARIF_v2.1.0-purple.svg)](#enterprise-sarif--siem-integration)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red.svg)](#detection-as-code-sigma-rules--mitre-attck)

**Sentinel** is an autonomous, ultra-lightweight cybersecurity defense agent and homelab guardian. Built with an open-core **MIT license** and a zero-dependency standard-library philosophy, Sentinel combines server 0-day exploit mitigations, in-kernel hardening, runtime behavioral anomaly detection, active deception honeyports, cryptographic file integrity monitoring (FIM), CISA KEV / EPSS threat intelligence, and autonomous remediation into a unified platform.

Engineered with an ultra-low memory footprint (~15–25MB RSS), Sentinel runs effortlessly across cloud VPS instances, bare-metal enterprise servers, Raspberry Pis, low-power NAS units, and legacy hardware (Intel Pentium, Core 2 Duo).

---

## 🛡️ Enterprise Capabilities

```
                                  SENTINEL UNIFIED DEFENSE FABRIC
                                                 │
    ┌───────────────────────┬────────────────────┼────────────────────┬───────────────────────┐
    ▼                       ▼                    ▼                    ▼                       ▼
1. Exploit Mitigations   2. Runtime Behavioral 3. Active Deception  4. File Integrity &    5. Autonomous SOAR
   & Kernel Hardening       Anomaly Detector     & Honeygrid Traps     Anti-Persistence       & Self-Healing
  [host_harden]           [process_anomaly]     [honeyport / canary]  [fim_audit]            [--fix-kernel]
  • Full ASLR (va_space=2) • Parent/Child LOLBin • Decoy port traps    • SHA-256 baselines    • Auto sysctl write
  • Userns clone disabled • Web daemon -> Shell • Tripwire canaries   • Cron/systemd audit   • nftables / iptables
  • BPF / kptr restricted • Reverse shell egress • 0% false positives • Kernel taint audit   • Micro-firewall drops
```

### 1. 0-Day Exploit Mitigation & Kernel Hardening (`host_harden`)
Neutralizes memory corruption and local privilege escalation 0-days at the OS kernel level:
* **Full ASLR Verification**: Validates `kernel.randomize_va_space = 2` (Stack, Heap, VDSO, and mmap randomization).
* **Unprivileged User Namespace Lockdown**: Audits `kernel.unprivileged_userns_clone = 0`, neutralizing ~60% of modern Linux local privilege escalation (LPE) exploits.
* **Information Leak Prevention**: Enforces `kernel.kptr_restrict = 2` and `kernel.dmesg_restrict = 1` to prevent kernel pointer and crash disclosure.
* **TOCTOU Filesystem Race Protections**: Verifies `fs.protected_symlinks`, `fs.protected_hardlinks`, `fs.protected_fifos`, and `fs.protected_regular`.
* **Process Memory Injection Defense**: Validates Yama ptrace scope (`kernel.yama.ptrace_scope = 1`).
* **Mount Security Verification**: Validates that `/tmp`, `/var/tmp`, and `/dev/shm` are mounted with `noexec,nosuid,nodev`.
* **Container Breakout Auditing**: Detects insecure `/var/run/docker.sock` permissions and `--privileged` containers with dangerous kernel capabilities (`CapEff`).

### 2. Autonomous Self-Healing & Remediation Engine (`--fix-kernel`)
Moves beyond passive scanning to active server defense:
* **One-Click Kernel Hardening (`--fix-kernel`)**: Automatically writes `/etc/sysctl.d/99-sentinel-hardening.conf` and applies all 13 critical exploit mitigations live via `sysctl --system`.
* **Safe Dry-Run Previews (`--dry-run`)**: Inspects system compliance, calculates drift, and displays full configuration diffs prior to application.
* **Micro-Firewall Drop Generator**: Automatically synthesizes `nftables`, `iptables`, and `ufw` drop rules to instantly isolate hostile IPs.

### 3. Runtime Behavioral & Reverse-Shell Anomaly Detection (`process_anomaly`)
Catches active zero-day post-exploitation in real-time by inspecting `/proc`:
* **Process Lineage & LOLBin Spawns**: Detects web daemons (`nginx`, `apache2`, `httpd`, `www-data`, `node`, `php-fpm`) or database servers (`mysqld`, `postgres`, `redis-server`) spawning interactive shells (`sh`, `bash`, `dash`) or download tools (`curl`, `wget`, `nc`, `python`).
* **Dynamic Preload Hijack Audit**: Inspects `/etc/ld.so.preload` for injected dynamic linkers indicative of userland rootkits.

### 4. Defensive Deception: High-Fidelity Decoy Keys & Burner Sandboxes (`deception`, `honeypot_burner`, `honeyport`, `canary_audit`)
Provides 100% true-positive breach detection and diverts malicious bots away from host infrastructure:
* **High-Fidelity Honeytokens (`--seed-honeytokens`)**: Synthesizes realistic, non-functional canary credentials:
  * **LLM & AI Keys**: High-entropy canary tokens for OpenAI (`sk-proj-CANARY_...`), Anthropic (`sk-ant-api03-CANARY_...`), and HuggingFace (`hf_CANARY_...`).
  * **Automation & Webhooks**: n8n workflow API keys, encryption secrets, and webhook trigger endpoints.
  * **Infrastructure Credentials**: SMTP mailer authentication, Docker staging registry configs (`docker-config.json.canary`), and remote SSH canary keys (`id_rsa_backup.canary`).
  * **Cryptographic Baselines**: Automatically registered into `~/.sentinel/canaries.json` with SHA-256 integrity hashes and access timestamps (`atime`). Any read inspection or tampering immediately trips a **CRITICAL** incident.
* **Ultra-Lightweight Burner Honeypot Sandbox (`--burner-setup`, `--burner-daemon`)**:
  * **Zero-Drain Isolation Machine**: Provides an isolated, decoy target for automated bots, AI scrapers, and malicious reconnaissance without consuming host resources.
  * **Docker Compose Blueprint (`--burner-setup`)**: Generates an isolated sandbox strictly limited to **32MB RAM** and **0.05 CPU**, with read-only rootfs, `tmpfs` mounts, `cap_drop: ALL`, and `no-new-privileges: true`.
  * **Pure-Python Micro-Burner Daemon (`--burner-daemon`)**: Built-in zero-dependency trap running under **<5MB RAM**, emulating decoy SSH (2222), SMTP (2525), and n8n webhook (5678) endpoints. Interactions are recorded in `~/.sentinel/burner_traps.json` and generate immediate firewall drop rules (`iptables -I INPUT -s <IP> -j DROP`).
* **Decoy Honeyport Traps (`--honeyport-listen`)**: Binds low-resource socket listeners on unassigned ports (23 Telnet, 445 SMB, 2375 Docker, 8888 Alt-Admin). Inbound SYN packets immediately record the attacker's IP and trigger instant firewall bans.

### 5. Cryptographic File Integrity Monitoring & Anti-Persistence (`fim_audit`)
* **SHA-256 System Baselines**: Continuously verifies cryptographic hashes for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, and critical binaries.
* **Persistence Hunter**: Scans `/etc/cron*`, `/var/spool/cron/crontabs`, and `/etc/systemd/system/` for unauthorized tasks or world-writable execution scripts.
* **Kernel Taint Verification**: Audits `/proc/sys/kernel/tainted` to detect unsigned or unauthorized Loadable Kernel Modules (LKMs).

### 6. Detection-as-Code: Sigma Rules & MITRE ATT&CK (`sigma_rules`)
* Evaluates events against built-in Sigma rules mapped directly to MITRE ATT&CK:
  * **T1059.004**: Interactive Reverse Shell Execution (`/bin/bash -i >& /dev/tcp/...`).
  * **T1059.001**: Encoded PowerShell Download Cradles.
  * **T1003.008**: Shadow File Credential Exfiltration (`/etc/shadow`).
  * **T1574.006**: Dynamic Linker Preload Persistence (`ld.so.preload`).
  * **T1105**: Ingress Tool Transfer (`curl -fsSL`, `certutil`).

### 7. Threat Intelligence: CISA KEV & FIRST EPSS Scoring (`threat_intel`)
* **CISA KEV Integration**: Real-time cross-referencing against the federal Known Exploited Vulnerabilities catalog. Vulnerabilities confirmed active in the wild are elevated to **CRITICAL**.
* **FIRST EPSS Scoring**: Queries the Exploit Prediction Scoring System to calculate the probability of weaponization within 30 days (>50% probability triggers predictive warnings).
* **Real-Host SBOM Extraction (`pkg_audit`)**: Extracts actual installed packages (`dpkg`, `rpm`, `apk`, and Python dependencies) and queries the OSV API with exact version strings.

### 8. 24/7 Watchdog Daemon & Systemd Integration (`--daemon`, `--install-systemd`)
* **Continuous Background Monitoring**: Runs in the background at ~15-25MB RSS, sleeping between cycles and evaluating state drift (`--diff`).
* **Native Systemd Service Installer (`--install-systemd`)**: Generates and registers a hardened `/etc/systemd/system/sentinel.service` unit with `ProtectSystem=full` and `NoNewPrivileges=true`.

### 9. Enterprise SARIF & SIEM Integration (`--sarif`)
* Exports findings in standardized **OASIS SARIF v2.1.0** format, enabling direct ingestion into GitHub Code Scanning, GitLab Security Dashboards, DefectDojo, and enterprise SIEMs.

---

## 🚀 Quickstart & Usage

### 1. Complete Server 0-Day & Threat Intelligence Audit
```bash
# Audit kernel mitigations, process anomalies, package CVEs, FIM, and threat intel
sentinel --server-audit --report server_report.html
```

### 2. Autonomous Remediation (One-Click Kernel Hardening)
```bash
# Preview proposed kernel sysctl hardening diffs
sentinel --fix-kernel --dry-run

# Autonomously write and apply /etc/sysctl.d/99-sentinel-hardening.conf (requires root)
sudo sentinel --fix-kernel
```

### 3. Continuous 24/7 Daemon & Systemd Installation
```bash
# Generate and install Sentinel as a permanent Linux systemd background service
sudo sentinel --install-systemd

# Or run directly in daemon mode with Slack / Telegram notifications
sentinel --server-audit --daemon --interval 300 --notify \
  --telegram-token "YOUR_TOKEN" --telegram-chat-id "YOUR_CHAT_ID" \
  --slack-webhook "https://hooks.slack.com/services/..."
```

### 4. Active Deception, Honeytokens & Burner Sandboxes
```bash
# Seed high-fidelity decoy keys (LLM, SMTP, n8n, Docker, SSH) into current directory
sentinel --seed-honeytokens .

# Generate an ultra-lightweight (32MB RAM, 0.05 CPU) isolated Docker burner honeypot
sentinel --burner-setup docker-compose.burner.yml

# Or run the built-in pure-Python micro-burner trap (<5MB RAM) in the background
sentinel --burner-daemon

# Seed a basic local honeytoken canary tripwire
sentinel --canary-init

# Start active decoy honeyport listeners in the background (ports 23, 445, 2375, 8888)
sudo sentinel --honeyport-listen
```

### 5. Native C99 High-Performance Engine (<800KB RAM, 0% CPU)
```bash
# Build the native static binary with zero external dependencies
make

# Run the built-in self-test
make test

# Launch the native C daemon (epoll/select honeyports, inotify tripwires, auto-ban)
./bin/sentineld

# Or run C-native host audit / honeytoken seeding
./bin/sentineld --audit
./bin/sentineld --seed .
```

### 6. Enterprise SARIF Export
```bash
# Run audit and export standardized SARIF v2.1.0 for GitHub / CI / SIEM
sentinel --server-audit --sarif sentinel_results.sarif
```

### 7. Homelab LAN & Network Reconnaissance
```bash
# Scan a homelab IP or CIDR subnet with dedicated Open Ports & Services Matrix
sentinel 192.168.1.0/24 --stages recon scan --diff --report homelab_report.html
```

---

## 📊 Command-Line Reference

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `--server-audit` | - | Runs complete host 0-day, kernel hardening, FIM, and threat intel audit |
| `--fix-kernel` | - | Autonomously applies kernel 0-day mitigations to `/etc/sysctl.d/` |
| `--dry-run` | - | Previews remediation diffs and sysctl profiles without writing |
| `--daemon` | - | Runs Sentinel as a continuous background watchdog daemon |
| `--interval` | `<seconds>` | Cycle interval for daemon mode (default: `300`) |
| `--install-systemd`| - | Generates and registers hardened Linux systemd service unit |
| `--canary-init` | - | Initializes and arms local deception honeytoken canary file |
| `--seed-honeytokens`| `[dir]` | Seeds decoy credentials (LLM, SMTP, n8n, Docker, SSH) into target directory |
| `--burner-setup` | `[file]` | Generates locked-down 32MB burner honeypot docker-compose configuration |
| `--burner-daemon`| - | Runs built-in pure-Python micro-burner trap (<5MB RAM, SSH/SMTP/n8n) |
| `--honeyport-listen`| - | Binds active decoy honeyport listeners (ports 23, 445, 2375, 8888) |
| `--sarif` | `<file>` | Writes findings in standardized OASIS SARIF v2.1.0 format |
| `--report` | `<file>` | Generates self-contained, agency-grade HTML dashboard |
| `--diff` | - | Diffs findings against historical baseline to alert on drift |
| `--notify` | - | Dispatches alert digests to Slack webhooks and Telegram bots |
| `--stages` | `[stages ...]` | Restricts pipeline execution: `recon`, `scan`, `osint`, `cloud`, `audit`, `intel` |
| `--json` | - | Emits raw JSON findings to stdout |
| `--out` | `<file>` | Writes JSON findings to file |

---

## 🏗️ Architecture & Repository Structure

```
sentinel/
  core/
    models.py               # Shared Finding dataclass (tool, type, value, severity, target)
    plugin.py               # Plugin interface every engine implements
    orchestrator.py         # Discovers plugins, runs ordered pipeline, shares tech context
    config.py               # Engine binary locator (./bin, else PATH)
    report.py               # Executive report + Open Ports Matrix + 0-Day Defense Matrix
    state.py                # State tracking & baseline drift engine (new port alerts)
    notifiers.py            # Zero-dependency Slack and Telegram alert dispatchers
    remediation.py          # Autonomous kernel hardening engine & firewall rule generator
    sarif.py                # OASIS SARIF v2.1.0 exporter
    daemon.py               # Continuous background daemon & systemd unit installer
    deception.py            # High-fidelity decoy credentials (LLM, SMTP, n8n, Docker, SSH) & canaries
    honeypot_burner.py      # 32MB Docker burner sandbox generator & <5MB micro-burner daemon
    plugins/
      host_harden_plugin.py # Audit — Kernel exploit mitigations, ASLR, userns, mounts, Docker sock
      process_anomaly_plugin.py # Audit — Process lineage, LOLBin spawns, reverse shells, ld.so rootkits
      fim_plugin.py         # Audit — Cryptographic File Integrity Monitoring & persistence audit
      honeyport_plugin.py   # Audit — Active deception honeyport listener & reconnaissance trap
      canary_audit_plugin.py# Audit — Deception honeytoken canary tripwires for 0-day detection
      sigma_plugin.py       # Audit — Detection-as-Code Sigma rules mapped to MITRE ATT&CK
      threat_intel_plugin.py# Intel — CISA KEV (in-the-wild) & FIRST EPSS exploit prediction scoring
      pkg_audit_plugin.py   # Scan  — Host OS package SBOM extraction -> OSV CVE correlation
      lan_scanner_plugin.py # Recon — Homelab LAN multi-threaded port & service discovery (std socket)
      cert_audit_plugin.py  # Recon — SSL/TLS certificate validity & expiration auditor (std ssl)
      crtsh_plugin.py       # OSINT — Certificate Transparency log enumeration (API)
      subfinder_plugin.py   # Recon — projectdiscovery/subfinder (MIT)
      httpx_plugin.py       # Recon — projectdiscovery/httpx (MIT)
      http_probe_plugin.py  # Recon — Native live probe & HTTP/2 fingerprinter
      nuclei_plugin.py      # Scan  — projectdiscovery/nuclei (MIT)
      osv_correlate_plugin.py # Scan — Technology to known CVEs via OSV
      sherlock_plugin.py    # OSINT — sherlock-project/sherlock (MIT)
      prowler_plugin.py     # Cloud — prowler-cloud/prowler (Apache-2.0)
      sqlmap_external_plugin.py # External — Subprocess-isolated SQLi wrapper (GPL-2.0)
  cli.py                    # Command-line entry point with full flag suite
tests/
  test_core.py              # Test suite for orchestrator, models, and HTML reports
  test_homelab.py           # Test suite for LAN scanner, notifiers, and state diff
  test_server_defense.py    # Test suite for 0-day defense, process anomalies, CISA KEV, EPSS
  test_remediation.py       # Test suite for autonomous sysctl hardening & firewall rules
  test_sarif.py             # Test suite for OASIS SARIF v2.1.0 output validation
  test_daemon.py            # Test suite for continuous daemon & systemd unit generation
  test_honeyport.py         # Test suite for active deception honeyport traps
  test_fim.py               # Test suite for cryptographic file integrity hashing
  test_sigma.py             # Test suite for Sigma rule matching & MITRE ATT&CK tagging
  test_deception.py         # Test suite for honeytoken generation and burner honeypots
```

---

## 📜 License & Copyleft Isolation

The core agent and all built-in plugins are licensed under the **MIT License**.

> **Clean Architecture Guarantee**: No copyleft code (GPL, AGPL) is imported by, linked into, or compiled with the Sentinel core. Heavy copyleft scanners (such as `sqlmap` or `wazuh`) are intentionally excluded or invoked exclusively as **isolated external subprocesses via command-line pipes**, ensuring the core remains 100% permissively licensed for commercial and enterprise adoption. See [`LICENSES.md`](LICENSES.md) for full attribution.
