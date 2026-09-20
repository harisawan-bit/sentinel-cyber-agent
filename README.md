# Sentinel — Unified Cyber Security Agent & Homelab Guardian

Sentinel is a single **MIT-licensed** orchestration agent that unifies the best
permissively-licensed (MIT / Apache-2.0 / BSD / ISC) cyber-security engines
behind one plugin API, a shared finding model, and an executive-grade HTML dashboard.

Engineered with an ultra-low memory footprint (~15–25MB RSS), Sentinel runs effortlessly on legacy hardware (Intel Pentium, Core 2 Duo), low-power NAS units, and Raspberry Pis.

> Verified by a license analysis of **2,251 real GitHub cyber-security repos**
> (46% permissive, 21% strong-copyleft GPL/AGPL, 30% no-license). The only
> legally clean way to "merge the best" is an orchestrator: embed permissive
> engines directly, and invoke copyleft (GPL/AGPL) engines as **isolated
> external subprocesses** so their licenses never infect the MIT core.

---

## Autonomous Executive Dashboard & Open Ports Matrix

Sentinel generates a fully self-contained, agency-grade HTML report (`--report report.html`) engineered with:
* **🔌 Dedicated Open Ports & Services Matrix**: Groups all open network services across IPs and subnets with dedicated filters (Containers, Databases, High Risk), categorized risk indicators, and homelab tags (Proxmox, Portainer, TrueNAS, Home Assistant, Docker API).
* **Charcoal, Warm Brown & Silver Aesthetic**: Rich dark charcoal base surfaces (`#0e0e0e`, `#161616`), subtle warm mahogany/espresso accents (`#8b3a3a`), and brushed metallic silver borders (`#3d3d3d`, `#4a4a4a`).
* **Curved Card Panels**: 14px border-radii with subtle silver edge highlights, high-contrast tables, and monospaced finding tokens.
* **Proportional Severity Spectrum**: Visual ratio progress bar detailing global Critical, High, Medium, Low, and Info distributions.
* **Interactive Client-Side Filtering**: Real-time severity filters and live search across hosts, tools, CVEs, and values with **zero external CDN dependencies** (pure vanilla JS/CSS).

---

## Homelab Alerting: Slack & Telegram Notifications

Sentinel includes built-in notifications using Python's standard library (zero third-party dependencies):
* **Telegram Bot API**: Delivers formatted markdown/HTML security digests, alert summaries, and open port inventories.
* **Slack Webhooks**: Dispatches Block Kit notifications directly into your `#security` or `#homelab` channels.
* **Continuous State & Drift Tracking (`--diff`)**: Compares current findings against previous baselines to alert when a **new open port** or **new device** appears on your private subnet.

```bash
# Scan a homelab IP and dispatch Slack / Telegram alerts
python -m sentinel.cli 192.168.1.50 --stages recon scan --diff --notify \
  --telegram-token "YOUR_BOT_TOKEN" --telegram-chat-id "YOUR_CHAT_ID" \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --report homelab_report.html
```

---

## Install

```bash
pip install -r requirements.txt
python scripts/install_engines.py      # downloads PD windows binaries into ./bin
```

The `install_engines.py` script only vendors **MIT/Apache** engines
(projectdiscovery nuclei / subfinder / httpx) and pip-installs sherlock
(MIT). Copyleft engines (sqlmap, sliver, MobSF, wazuh, MISP, radare2) are
**intentionally excluded** — they must be invoked as external processes, not
vendored. See `sentinel/core/plugins/prowler_plugin.py` for the
external-subprocess pattern (and the commented sqlmap wrapper).

---

## Run

```bash
# Homelab LAN Port & Service Audit (RFC 1918 private subnet or single host)
python -m sentinel.cli 192.168.1.50 --stages recon scan --report homelab_report.html

# Full OSINT: username presence (sherlock, MIT)
python -m sentinel.cli google --stages osint --json --out findings.json

# Recon + scan against an AUTHORIZED target with autonomous HTML report
python -m sentinel.cli example.com --stages recon scan --report report.html --out findings.json
```

> Only scan hosts you are **authorized** to test.

---

## Architecture

```
sentinel/
  core/
    models.py               # Shared Finding dataclass (tool, type, value, severity, target)
    plugin.py               # Plugin interface every engine implements
    orchestrator.py         # Discovers plugins, runs pipeline, shares tech context
    config.py               # Engine binary locator (./bin, else PATH)
    report.py               # Charcoal/silver executive report + Open Ports Matrix
    state.py                # State tracking & baseline drift engine (new port alerts)
    notifiers.py            # Zero-dependency Slack and Telegram alert dispatchers
    plugins/
      lan_scanner_plugin.py # Homelab LAN multi-threaded port & service discovery (std socket)
      cert_audit_plugin.py  # SSL/TLS certificate validity & expiration auditor (std ssl)
      crtsh_plugin.py       # OSINT  — Certificate Transparency log enumeration (API)
      subfinder_plugin.py   # Recon  — projectdiscovery/subfinder (MIT)
      httpx_plugin.py       # Recon  — projectdiscovery/httpx (MIT)
      http_probe_plugin.py  # Recon  — Native live probe & HTTP/2 fingerprinter
      nuclei_plugin.py      # Scan   — projectdiscovery/nuclei (MIT)
      osv_correlate_plugin.py # Correlation — Technology to known CVEs via OSV
      sherlock_plugin.py    # OSINT  — sherlock-project/sherlock (MIT)
      prowler_plugin.py     # Cloud  — prowler-cloud/prowler (Apache-2.0)
      sqlmap_external_plugin.py # External — Subprocess-isolated SQLi wrapper (GPL-2.0)
  cli.py                    # Command-line entry point with --diff, --notify, --report
scripts/
  install_engines.py        # Downloads only permissive engine binaries
  generate_sample_report.py # Generates demonstration HTML report
tests/
  test_core.py              # Test suite for orchestrator, models, and HTML reports
  test_homelab.py           # Test suite for LAN scanner, notifiers, and state diff
```

---

## License

Core agent is **MIT**. Each bundled/invoked engine retains its own license —
see the respective upstream repo. No GPL/AGPL code is compiled into or imported
by the MIT core.
