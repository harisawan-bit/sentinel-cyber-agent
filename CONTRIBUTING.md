# Contributing to Sentinel

Thanks for taking the time. This project is small and opinionated, so a short
set of ground rules saves everyone a review cycle.

## Ground Rules

1. **Authorised testing only.** Never add a default target that Sentinel would
   scan without permission. `example.com` (IANA) and `scanme.sh`
   (projectdiscovery) are the sanctioned test hosts.
2. **MIT core stays clean.** Do not add a dependency or vendor code under
   GPL/AGPL. If a capability genuinely requires copyleft, wire it as an
   external subprocess and document it in [`LICENSES.md`](LICENSES.md). See
   "License Isolation" below.
3. **Standard library first.** The core agent ships with no third-party
   runtime imports. `http_probe_plugin` was rewritten from `requests` to
   `urllib` for exactly this reason. `sherlock-project` is the one declared
   dependency and is optional at runtime — the plugin degrades to a note when
   it is absent.
4. **No shell.** Use list-form `subprocess` argv. `shell=True` and `system()`
   are not accepted; they have caused real command-injection surface in tools
   like this.
5. **No writes outside the state directory.** All persistent state goes through
   `sentinel/core/paths.py` and honours `SENTINEL_HOME`. Do not hardcode
   `~/.sentinel` or `os.path.expanduser` in a new module.
6. **Root is opt-in.** New code must not require root unless it is behind an
   explicit flag, and must offer a dry-run.

## Development Setup

```bash
git clone https://github.com/harisawan-bit/sentinel-cyber-agent.git
cd sentinel-cyber-agent

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # optional: sherlock only
pip install -e .                         # installs the `sentinel` entrypoint

# Optional: fetch MIT engine binaries (nuclei, subfinder, httpx).
# Downloads are SHA-256 verified against the upstream release checksums.
python3 scripts/install_engines.py
```

The first-party plugins — `host_harden`, `process_anomaly`, `fim_audit`,
`lan_scanner`, `http-probe`, `cert_audit`, `sigma_rules`, `threat_intel` —
require no external engines and no third-party packages. Everything works
without `install_engines.py`.

## Running the Tests

The suite is plain `python`, not pytest, so it runs anywhere:

```bash
for t in tests/test_*.py; do python3 "$t" || break; done
```

`pytest tests/` also works if you prefer it.

Native engine:

```bash
make          # builds bin/sentineld with -Wall -Wextra -std=c99
make test     # runs the built-in --self-test
```

CI runs the full matrix on Python 3.10–3.13 plus the C build. Keep it green;
it is a required check on `main`.

## Test Isolation

Tests must never write to the real `~/.sentinel`. State leaks from the suite
cause the next real audit to report phantom CRITICAL alerts from test
fixtures. Set the override **before importing** anything that resolves a path:

```python
import os, tempfile
os.environ["SENTINEL_HOME"] = tempfile.mkdtemp(prefix="sentinel_test_home_")
# ... then import sentinel.core.*
```

See `tests/test_honeyport.py` and `tests/test_deception.py` for the pattern,
including the regression tests that assert nothing leaked.

## Adding a Plugin

1. Create `sentinel/core/plugins/<name>_plugin.py`.
2. Subclass `Plugin` and set `name`, `description`, `stage`, and `requires`.
   `stage` must be one of `recon`, `scan`, `osint`, `cloud`, `audit`, `intel`
   (see `orchestrator.STAGE_ORDER`).
3. `run()` must **yield** `Finding` objects and must not raise on a missing
   binary or an unreachable target. The orchestrator degrades gracefully, but
   an explicit `info` note reads better than a traceback.
4. Declare external binaries in `requires`. The orchestrator now checks it and
   emits `<name> skipped: missing <bin>` rather than an opaque error. If your
   plugin shells out to a Python module rather than a binary, set
   `requires = []` and note why.
5. If you emit a `finding_type == "host"` finding, put technology tokens in
   `metadata["tech"]` as `key=value` — the orchestrator feeds those to OSV
   correlation.
6. Add tests in a new `tests/test_<area>.py` following the sandbox pattern.

No registry file needs updating; discovery is automatic via `pkgutil`.

## Commit and PR Conventions

Conventional Commits:

```
feat(honeyport): add gopher decoy listener
fix(remediation): skip non-compliant params missing from /proc
docs(readme): document SENTINEL_HOME
chore(ci): pin actions/checkout to v4
```

PRs should:
- Target `main`.
- Have a body that states the problem, the change, and how you verified it.
- Include real command output for behavioural claims, not a summary of intent.
- Update `README.md` and `CHANGELOG.md` when behaviour or flags change.

## License Isolation

The MIT core must stay importable and linkable by commercial users. Engines
under GPL/AGPL (`sqlmap`, `wazuh`, `MISP`, `sliver`, `MobSF`, `radare2`,
`ImHex`) may be referenced but never imported or vendored — subprocess only.
Add any new third-party engine to the table in [`LICENSES.md`](LICENSES.md)
with its license and integration method.

## Security Issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
