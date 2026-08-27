# Sentinel — Unified Cyber Security Agent

Sentinel is a single **MIT-licensed** orchestration agent that unifies the best
permissively-licensed (MIT / Apache-2.0 / BSD / ISC) cyber-security engines
behind one plugin API and one shared finding model.

> Verified by a license analysis of **2,251 real GitHub cyber-security repos**
> (46% permissive, 21% strong-copyleft GPL/AGPL, 30% no-license). The only
> legally clean way to "merge the best" is an orchestrator: embed permissive
> engines directly, and invoke copyleft (GPL/AGPL) engines as **isolated
> external subprocesses** so their licenses never infect the MIT core.

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

## Run

```bash
# OSINT: username presence (sherlock, MIT) — works offline-ready after pip install
python -m sentinel.cli google --stages osint --json --out findings.json

# Recon + scan against an AUTHORIZED target (needs PD binaries in ./bin)
python -m sentinel.cli example.com --stages recon scan --json --out findings.json
```

> Only scan hosts you are **authorized** to test. `example.com` (IANA) and
> `scanme.nmap.org` are sanctioned test targets.

## Architecture

```
sentinel/
  core/
    models.py        # shared Finding dataclass (tool, type, value, severity, target)
    plugin.py        # Plugin interface every engine implements
    orchestrator.py  # discovers plugins, runs the pipeline, aggregates findings
    config.py        # engine binary locator (./bin, else PATH)
    plugins/
      subfinder_plugin.py   # recon  — projectdiscovery/subfinder  (MIT)
      httpx_plugin.py       # recon  — projectdiscovery/httpx      (MIT)
      nuclei_plugin.py      # scan   — projectdiscovery/nuclei     (MIT)
      sherlock_plugin.py    # osint  — sherlock-project/sherlock   (MIT)
      prowler_plugin.py     # cloud  — prowler-cloud/prowler       (Apache-2.0)
  cli.py             # command-line entry point
scripts/
  install_engines.py # downloads only permissive engines
```

## Adding an engine

1. Create `sentinel/core/plugins/<name>_plugin.py`.
2. Subclass `Plugin`, set `name` / `stage` / `description`, implement `run(target, ctx)`
   yielding `Finding` objects.
3. For **GPL/AGPL** engines: shell out to the binary as an external process
   (never `import` or vendor the code). See the commented wrapper in
   `prowler_plugin.py`.

## License

Core agent is **MIT**. Each bundled/invoked engine retains its own license —
see the respective upstream repo. No GPL/AGPL code is compiled into or imported
by the MIT core.
