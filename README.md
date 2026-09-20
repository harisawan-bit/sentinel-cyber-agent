# Sentinel — Unified Cyber Security Agent

Sentinel is a single **MIT-licensed** orchestration agent that unifies the best
permissively-licensed (MIT / Apache-2.0 / BSD / ISC) cyber-security engines
behind one plugin API, a shared finding model, and an executive-grade HTML dashboard.

> Verified by a license analysis of **2,251 real GitHub cyber-security repos**
> (46% permissive, 21% strong-copyleft GPL/AGPL, 30% no-license). The only
> legally clean way to "merge the best" is an orchestrator: embed permissive
> engines directly, and invoke copyleft (GPL/AGPL) engines as **isolated
> external subprocesses** so their licenses never infect the MIT core.

---

## Autonomous Executive HTML Dashboard

Sentinel generates a fully self-contained, agency-grade HTML report (`--report report.html`) engineered with:
* **Charcoal & Silver Aesthetic**: Rich dark charcoal base surfaces (`#0e0e0e`, `#161616`), subtle warm brown/mahogany accents (`#8b3a3a`), and brushed silver borders (`#3d3d3d`, `#4a4a4a`).
* **Curved Card Panels**: 14px border-radii with subtle silver edge highlights, high-contrast tables, and monospaced finding tokens.
* **Proportional Severity Spectrum**: Visual ratio progress bar detailing global Critical, High, Medium, Low, and Info distributions.
* **Interactive Client-side Filtering**: Real-time severity filters and live search across hosts, tools, CVEs, and values with **zero external CDN dependencies** (pure vanilla JS/CSS).

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
# OSINT: username presence (sherlock, MIT) — works offline-ready after pip install
python -m sentinel.cli google --stages osint --json --out findings.json

# Recon + scan against an AUTHORIZED target with autonomous HTML report
python -m sentinel.cli example.com --stages recon scan --report report.html --out findings.json
```

> Only scan hosts you are **authorized** to test. `example.com` (IANA) and
> `scanme.nmap.org` are sanctioned test targets.

---

## Architecture

```
sentinel/
  core/
    models.py               # Shared Finding dataclass (tool, type, value, severity, target)
    plugin.py               # Plugin interface every engine implements
    orchestrator.py         # Discovers plugins, runs pipeline, shares tech context
    config.py               # Engine binary locator (./bin, else PATH)
    report.py               # Self-contained charcoal/silver executive HTML report
    plugins/
      crtsh_plugin.py       # OSINT  — Certificate Transparency log enumeration (API)
      subfinder_plugin.py   # Recon  — projectdiscovery/subfinder (MIT)
      httpx_plugin.py       # Recon  — projectdiscovery/httpx (MIT)
      http_probe_plugin.py  # Recon  — Native live probe & HTTP/2 fingerprinter
      nuclei_plugin.py      # Scan   — projectdiscovery/nuclei (MIT)
      osv_correlate_plugin.py # Correlation — Technology to known CVEs via OSV
      sherlock_plugin.py    # OSINT  — sherlock-project/sherlock (MIT)
      prowler_plugin.py     # Cloud  — prowler-cloud/prowler (Apache-2.0)
      sqlmap_external_plugin.py # External — Subprocess-isolated SQLi wrapper (GPL-2.0)
  cli.py                    # Command-line entry point with --report and --json
scripts/
  install_engines.py        # Downloads only permissive engine binaries
  generate_sample_report.py # Generates demonstration HTML report
tests/
  test_core.py              # Test suite for orchestrator, models, and HTML reports
```

---

## Adding an engine

1. Create `sentinel/core/plugins/<name>_plugin.py`.
2. Subclass `Plugin`, set `name` / `stage` / `description`, implement `run(target, ctx)`
   yielding `Finding` objects.
3. For **GPL/AGPL** engines: shell out to the binary as an external process
   (never `import` or vendor the code). See the template in
   `sentinel/core/plugins/sqlmap_external_plugin.py`.

---

## License

Core agent is **MIT**. Each bundled/invoked engine retains its own license —
see the respective upstream repo. No GPL/AGPL code is compiled into or imported
by the MIT core.
