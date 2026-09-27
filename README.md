# Sentinel

[![CI](https://github.com/harisawan-bit/sentinel-cyber-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/harisawan-bit/sentinel-cyber-agent/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/harisawan-bit/sentinel-cyber-agent)](https://github.com/harisawan-bit/sentinel-cyber-agent/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-99-purple.svg)](https://en.cppreference.com/w/c)

**An autonomous cyber-security agent written in C99.** It maps your attack
surface, audits the host it runs on, correlates findings against live threat
intelligence, and reports in HTML, JSON, or SARIF so results drop straight into
your existing tooling.

No runtime. No package manager. No virtualenv. One binary and a system TLS
library.

```
$ sentinel example.com --stages recon
  [info    ] subdomain   mail.example.com          (crtsh)
  [medium  ] port        445/tcp                   (lan_scanner)
  [high    ] vuln        openssl 3.0.11-1 CISA KEV (threat_intel)
```

---

## Why C99

Sentinel is meant to sit resident on a small host and be trustworthy about
memory. Both properties are easier to guarantee when there is no garbage
collector and no runtime that can load code at execution time.

| | |
|---|---|
| **Agent idle RSS** | **0.04 MB** (static musl build) |
| **Daemon resident RSS** | **0.04 MB** |
| **Daemon binary** | 58 KB stripped, static musl |
| **Static agent** | 5.9 MB, zero shared libraries |
| **Peak RSS, full recon scan** | 1.9 MB |
| **Startup** | under 10 ms |
| **Third-party runtime deps** | OpenSSL (system lib) |

Measured on an x86-64 Linux container. Reproduce with `make bench`.

The 1.45 MB figure quoted for earlier versions was mostly *shared glibc text*,
not Sentinel's own memory — a program that only calls `printf()` sits at 1.4 MB
on the same host. Building against musl removes the shared pages and the real
number becomes visible.

**On dependencies:** C99 has no TLS, so HTTPS goes through OpenSSL. That means
the default `sentinel` binary needs `libssl` present, and `make static-agent`
produces a **fully static alternative with no shared libraries at all** — the
build verifies DNS and TLS still work before calling it good. Copy that one
file to a host with nothing installed and it runs.

The *daemon* is smaller still, because it needs no TLS at all: it listens rather
than connects, so it builds against musl at 58 KB.

---

## Install

```sh
git clone https://github.com/harisawan-bit/sentinel-cyber-agent
cd sentinel-cyber-agent
sudo ./scripts/install.sh
```

The installer builds, runs the daemon self-test and a real scan, and only then
replaces your binary — a broken build can never take out a working install.

**Requirements:** a C99 compiler and OpenSSL headers. Linux and macOS, x86-64
and arm64.

```sh
# Debian / Ubuntu
sudo apt-get install -y build-essential libssl-dev
# RHEL / Fedora
sudo dnf install -y gcc openssl-devel
# Alpine
sudo apk add build-base openssl-dev
# macOS
xcode-select --install
```

### Container

```sh
docker build -t sentinel .
mkdir -p ./out && chmod 777 ./out
docker run --rm -v "$PWD/out:/out" sentinel example.com --stages recon --report /out/report.html
```

It runs unprivileged, so the output directory must be writable by the
container's user. If it is not, the agent says so and exits non-zero rather
than dropping the report.

Runs unprivileged by default. An agent that reports on your infrastructure
should not be able to rewrite it.

### Build from source

```sh
make              # agent, daemon, engine installer, bench
make test         # 237 assertions + daemon self-test
make static       # static musl daemon (the resident component)
make static-agent # fully static agent, no shared libraries
```

---

## Use

```sh
# Recon an external target
sentinel example.com --stages recon --report report.html

# Audit the host you are on
sentinel localhost --stages audit

# Everything, with drift detection and a SARIF file for your CI
sentinel example.com --diff --sarif results.sarif --out results.json

# Run continuously as a service
sudo sentinel --install-systemd
```

### Stages

| Stage | What it does | Optional engines |
|---|---|---|
| `recon` | Subdomains via crt.sh and subfinder, live hosts, open ports | `subfinder` |
| `scan` | HTTP probing, TLS certificate audit, nuclei templates | `nuclei`, `httpx` |
| `osint` | Email and handle discovery, package advisories | `sherlock` |
| `intel` | Correlate findings against the CISA KEV catalog | — |
| `cloud` | Cloud storage and metadata exposure checks | `prowler` |
| `audit` | Kernel hardening, process anomalies, file integrity, canaries | root for full coverage |

Every external engine is optional. A missing engine produces an explicit `note`
finding saying what was skipped — never a silent gap, never a failed scan.

```sh
sentinel --install-engines   # fetch and verify nuclei, subfinder, httpx, sherlock
```

Downloads are SHA-256 verified against the upstream release checksum before use.

### Plugins

| Plugin | Stage | Purpose |
|---|---|---|
| `host_harden` | audit | ASLR, userns, kptr/dmesg restriction, mount flags, Docker socket |
| `process_anomaly` | audit | Process lineage, LOLBin spawns, reverse shells, `ld.so.preload` |
| `fim` | audit | SHA-256 baselines, cron/systemd persistence, kernel taint |
| `canary_audit` | audit | Honeytoken tripwires as 0-day exfiltration evidence |
| `honeyport` | audit | Active decoy port listeners |
| `sigma` | audit | Detection-as-code rules mapped to MITRE ATT&CK |
| `threat_intel` | intel | CISA KEV and FIRST EPSS correlation |
| `pkg_audit` | scan | Host package inventory to OSV CVE correlation |
| `cert_audit` | scan | TLS certificate validity and expiry |
| `osv_correlate` | scan | Detected technology to known CVEs |
| `http_probe` | recon | Live HTTP probing and technology fingerprinting |
| `lan_scanner` | recon | Host and CIDR port and service discovery |
| `crtsh` | osint | Certificate Transparency subdomain enumeration |
| `subfinder`, `httpx` | recon | projectdiscovery engines |
| `nuclei` | scan | projectdiscovery template scanner |
| `sherlock` | osint | Username and handle discovery |
| `prowler` | cloud | Cloud misconfiguration scanning |
| `sqlmap` | external | Subprocess-isolated SQLi wrapper |

### Deception

Sentinel can plant decoys and watch for them. This is the part that catches an
attacker who has *already* read the box, because canaries are worthless by
construction — if one surfaces anywhere it shouldn't, that is unambiguous.

```sh
sentinel --seed-honeytokens /srv/app    # decoy LLM/SMTP/n8n/Docker/SSH credentials
sentinel --canary-init                  # arm the tripwire
sentinel --burner-daemon                # foreground SSH/SMTP/webhook decoy trap
sentinel --burner-setup compose.yml     # hardened 32MB-capped sandbox blueprint
```

The burner trap binds three decoy services, answers with plausible banners,
logs what was sent to it, and stays in the foreground so it is observable and
killable rather than a hidden process. Ports are configurable
(`--burner-ssh`, `--burner-smtp`, `--burner-n8n`) so it will not collide with a
real service.

### Remediation

Kernel hardening is **previewed by default and never applied silently.**

```sh
sentinel --stages audit --dry-run          # show what would change
sudo sentinel --stages audit --fix-kernel  # write to /etc/sysctl.d/
```

Remediation writes a drop-in file rather than editing `/etc/sysctl.conf`, so it
is reviewable and reversible.

> **Caveat — `kernel.unprivileged_userns_clone = 0`.** This is strong defence
> against local privilege escalation, but it **breaks rootless containers**
> (Podman, rootless Docker, some Flatpak and Snap workflows). If you run
> rootless containers, do not apply that line blindly. `--dry-run` shows the full
> diff before anything is written; remove the line from
> `/etc/sysctl.d/99-sentinel-hardening.conf` and re-apply with `sysctl --system`.

---

## Reports

Sentinel writes a self-contained HTML report with no external assets, a JSON
finding stream, and SARIF 2.1.0 for code-scanning platforms. Every value that
reaches a report is escaped at the serialization boundary — an attacker
controlling a hostname or a response body cannot inject script into your report.

JSON findings carry a stable id, so the same issue produces the same id across
runs. That is what makes `--diff` and CI baselines work.

---

## State

All state resolves through `SENTINEL_HOME`, defaulting to `~/.sentinel`:

```
state.json             baseline of the last scan
burner_traps.json      decoy service interactions
fim_baseline.json      file integrity hashes
```

Set `SENTINEL_HOME` to relocate it. Nothing writes to the real home unless you
ask — the test suite asserts this on every run.

---

## Design

Security-relevant properties this codebase holds to, each enforced by a test:

- **No shell strings.** Subprocesses are spawned from `argv` arrays, never
  through `system()` or a shell. There is no path from attacker-controlled data
  to command execution.
- **No unescaped serialization.** HTML and JSON escape at the boundary, and
  plugins pass raw values rather than pre-escaped ones.
- **Explicit ownership.** Every serialized tree owns its data. Two findings
  sharing a metadata object is a use-after-free, and there is a regression test.
- **Bounded input.** Response bodies, process tables, and command output all
  have hard caps, so a hostile server cannot exhaust memory.
- **Strict warnings.** `-std=c99 -Wall -Wextra -Werror`, zero exceptions, and
  every plugin must also compile standalone so one plugin's missing include
  cannot hide behind another translation unit.
- **Sanitized in CI.** Every change runs under AddressSanitizer and
  UndefinedBehaviorSanitizer with leak detection.

Plugins declare what they need. A missing engine is a finding, not a crash.

### Layout

```
include/sentinel/   public headers
src/core/           JSON, SHA-256, TLS/HTTP, orchestrator, report, SARIF,
                    state, notifiers, remediation, daemon, burner
src/plugins/        19 audit plugins
src/sentineld.c     native resident daemon
tools/              engine installer, benchmark
tests/              237-assertion suite
```

Adding a plugin means one file in `src/plugins/` and one line in the registry in
`src/core/registry.c`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Scope

Honest about what this is not:

- **Recon and audit, not exploitation.** Sentinel finds and reports. It does not
  carry payloads or chain vulnerabilities.
- **Authorized use only.** Point it at infrastructure you own or are engaged to
  test. `--fix-kernel` and `--install-systemd` modify the host.
- **Linux-focused.** The audit stage reads `/proc` and sysctls, so it is
  meaningful on Linux and thin on macOS. The daemon and the recon and scan
  stages are portable.
- **Not a SIEM.** It detects drift between its own runs. Point it at the asset;
  it will not discover your estate for you.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see
[SECURITY.md](SECURITY.md).

Please **only scan systems you own or are explicitly authorised to test.**

## License

The core agent and all built-in plugins are MIT licensed.

> **Copyleft isolation:** no copyleft code (GPL, AGPL) is imported, linked, or
> compiled into the Sentinel core. Copyleft scanners such as `sqlmap` are
> invoked strictly as isolated external subprocesses, keeping the core
> permissively licensed for commercial and enterprise use. See
> [LICENSES.md](LICENSES.md) for full attribution of every optional engine.
