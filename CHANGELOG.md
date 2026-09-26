# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Tests no longer poison the operator's state directory.** The suite wrote
  honeytokens, FIM baselines, and *fake honeyport trips* into the real
  `~/.sentinel/`. A subsequent audit reported those fixtures as genuine
  CRITICAL breaches. All state now resolves through `sentinel/core/paths.py`
  and honours a `SENTINEL_HOME` override; the suite sandboxes itself and two
  new regression tests assert nothing leaks.
- **`--burner-daemon` no longer crashes on startup.** `time` was never
  imported in `cli.py`, so the documented feature died with
  `NameError: name 'time' is not defined` immediately after printing its
  "daemon running" banner.
- **`http-probe` works on a clean install.** It imported `requests`, which was
  declared nowhere — the plugin degraded to `plugin error: No module named
  'requests'` for anyone who had not installed it transitively. It now uses
  `urllib.request` from the standard library, which also makes the
  zero-dependency claim in the README true.
- **`install_engines.py` works on Linux and macOS.** It hardcoded
  `windows_amd64` assets and a `C:/hermes-agent-workspace/...` temp path.
  Platform and architecture are now detected, and downloads go to a real
  temporary directory.
- **Engine downloads are verified.** Archives are checked against the SHA-256
  digest published with the upstream release before extraction. If no checksum
  is published, or the digest does not match, installation is refused. No
  unverified binary is installed or executed.
- **`cert_audit` documentation** corrected — it runs in the `scan` stage, not
  `recon`.
- Removed the `py.typed` package-data declaration; the file did not exist.
- The native engine invokes `iptables` and `sysctl` via `fork`/`execvp` with
  discrete arguments instead of `system()`, so no shell parses attacker-influenced
  input. Alert lines are JSON-escaped per RFC 8259 before being written to
  `sentinel_events.jsonl`, so a quote in a `/proc` cmdline can no longer corrupt
  the log.

### Added
- `sentinel/core/paths.py` — single source of truth for the state directory,
  with `state_dir()`, `state_path()`, and `ensure_state_dir()`.
- `SENTINEL_HOME` environment override for all runtime state.
- `Plugin.requires` is now enforced. Engine-backed plugins whose binary is
  absent are skipped with `<name> skipped: missing <bin>` instead of an opaque
  plugin error.
- `scripts/bench.py` — reproducible memory measurement against the documented
  budget, with `--json` output.
- `SECURITY.md` — private disclosure process, scope, and an honest security
  model covering the root-requiring and auto-drop behaviour.
- `CONTRIBUTING.md` — development setup, test isolation rules, the plugin
  contract, and the license-isolation policy.
- Issue and pull request templates.
- Branch protection on `main` requiring the CI check to pass.
- `CHANGELOG.md` (this file).

### Changed
- Corrected the memory-footprint claims in the README to measured values.
  A full `--server-audit` cycle peaks at **~35 MB** RSS, not the previously
  claimed "<25 MB"; the idle/import floor is ~17.5 MB. The native C daemon
  measures **1.45 MB RSS** with a **21.4 KB** binary. Run `python3
  scripts/bench.py` to reproduce. The static "CI: Passing" badge — which
  rendered green even when CI was red — is replaced with a live workflow badge.
- The architecture tree in the README now includes `src/sentineld.c`, which
  was missing entirely.
- `sherlock` no longer declares a `requires` binary; it is invoked as a Python
  module, not a standalone executable.

### Security
- Added `SECURITY.md` with a private reporting path and an explicit security
  model. The native engine auto-drops trapped IPs via iptables when run as
  root, which can block a legitimate scanner or monitoring probe; this is now
  documented rather than left as a surprise.
