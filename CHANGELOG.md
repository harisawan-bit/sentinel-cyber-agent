# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-09-27

The agent is now C99. The Python implementation is removed, not deprecated.

### Added

- `scripts/install.sh` — builds, runs the daemon self-test and a real scan, and
  only then replaces the installed binary. A broken build can no longer take out
  a working install.
- `Dockerfile` — multi-stage, non-root by default, with a build-time scan so a
  broken image fails in CI rather than at someone's first `docker run`.
- `--install-systemd` and `--burner-daemon`, closing the last two gaps in
  command-line parity with the Python agent.
- `--burner-ssh` / `--burner-smtp` / `--burner-n8n` so the decoy trap cannot
  collide with a real service.
- A repository-hygiene CI job that fails on shell-string execution, hardcoded
  state paths, unregistered plugins, and stale documentation references.
- Regression tests for every defect fixed in this release.

### Fixed

Bugs that shipped and affected real scans:

- **Chunked HTTP responses were decoded from the first packet only.** A
  1.75 MB threat feed arrived as 3.6 KB of still-valid JSON, so KEV correlation
  reported every CVE as unexploited in the wild. A security tool failing
  silently in the dangerous direction.
- **Drift detection could never fire on the audit stage.** The C port had
  narrowed it to four finding types; the Python compared every finding for a
  known target. State drift now matches the original semantics.
- **Truncated JSON was accepted as valid.** `{"a":` parsed as an empty object,
  turning a partial response into a successful-looking empty result.
- **Content-Type was read one byte past its value,** so every `text/html` came
  back as `ext/html` and `chunked` encoding went undetected.
- **The decoy trap ignored SIGINT and could not be stopped.**
- **Two double frees.** Moving JSON children between trees and then freeing the
  source recursively, in the trap's log writer and the HTTP tech detector.
- **A use-after-free on every live scan,** where two findings shared one
  metadata object.
- **`SENTINEL_HOME` was read once per process,** so state could not be relocated
  after the first call.
- Four defects in the Python agent, all live: `fim` and `cert_audit` never
  produced a finding because of unhandled exceptions, `crtsh` raised on any
  `http://` target, and `host_harden` reported a hardcoded value for two sysctls.

### Changed

- The agent and daemon are C99 throughout. `-std=c99 -Wall -Wextra -Werror` with
  no exceptions, plus per-plugin isolated compilation in CI.
- CI builds on Linux x86-64, Linux arm64, and macOS arm64, and runs
  AddressSanitizer with UndefinedBehaviorSanitizer and leak detection on every
  change.
- `make static` now builds only the daemon and says so. It previously claimed to
  build everything and failed with a missing-header error, because the agent
  needs OpenSSL and musl toolchains ship no OpenSSL headers.

### Known limitations

- The agent links system OpenSSL. C99 has no TLS, and a vendored TLS stack would
  be a larger security liability than the dependency. The daemon is unaffected
  and builds fully static.
- `sigma` evaluates rule identifiers and severities but not regular expressions,
  which C99 does not provide.
- `http_probe` derives technologies from the response body; header-derived hints
  are not ported.
- The audit stage reads `/proc` and sysctls, so it is meaningful on Linux and
  thin on macOS.

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
