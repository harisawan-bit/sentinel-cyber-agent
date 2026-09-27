# Security Policy

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Report privately via GitHub's private reporting flow:
**Security → Report a vulnerability** on this repository, or by email to the
maintainer listed in the repository profile.

Include:
- Affected component and version (tag or commit SHA)
- Steps to reproduce, ideally with a minimal `sentinel` command
- Impact: what an attacker gains, and what access they need to start
- Any proof-of-concept output, with real secrets/IPs redacted

You can expect an acknowledgement within **72 hours** and an assessment
(severity, fix or mitigation plan) within **7 days**. Fixes ship in a tagged
release; you are credited in the release notes unless you prefer otherwise.

## Scope

**In scope**

| Component | Notes |
|---|---|
| `src/core/**` | Audit, remediation, deception, reporting, and the HTTP/TLS layer |
| `src/plugins/**` | All 19 audit plugins |
| `src/cli.c`, `src/sentineld.c` | Command line and the resident daemon |
| `tools/install_engines.c` | Engine download, checksum verification, extraction |
| `scripts/install.sh` | Build, verification, and install path |
| Findings that could mislead an operator | A suppressed or spoofed finding is a security defect, not a cosmetic bug |

**Out of scope**

- Vulnerabilities in third-party engines (`nuclei`, `subfinder`, `httpx`,
  `prowler`, `sherlock`, `sqlmap`). Report those upstream; see
  [`LICENSES.md`](LICENSES.md) for the mapping.
- Findings that require an attacker to already hold root on the target host.
- Missing hardening *recommendations* — Sentinel reports gaps in host
  configuration, and the absence of a check is an enhancement, not a
  vulnerability.
- Denial of service caused by scanning a target you are not authorised to
  scan. That is an operational error, not a bug.

## Security Model

Sentinel is an **active defensive** tool. It is designed for systems whose
operator already holds administrative rights. Understand this before running it:

- **It executes as root when you tell it to.** `sudo sentinel --fix-kernel`
  writes `/etc/sysctl.d/99-sentinel-hardening.conf` and applies 13 sysctl
  mitigations. `sudo sentinel --honeyport-listen` binds privileged ports.
  `--install-systemd` registers and starts a system service.
- **It modifies host state on purpose.** Kernel hardening, honeyport listeners,
  and honeytoken files are all real changes to the machine. Review with
  `--dry-run` first.
- **The native engine auto-drops IPs.** Running `sentineld` as root inserts an
  `iptables -I INPUT -s <ip> -j DROP` rule for every trapped source address.
  This is intended, but it means a scanner, a monitoring probe, or an
  accidental self-connection can get your own address blocked. The agent
  (`sentinel`) does not auto-drop; only `sentineld` does, and only as root.
- **Honeytokens are real credential-shaped strings.** They are high-entropy and
  non-functional, but secret scanners will flag them. Baseline your tooling
  before seeding them in a repository.
- **The agent links OpenSSL.** C99 has no TLS, so HTTPS goes through system
  OpenSSL. It is the only third-party library linked into the agent. The daemon
  (`sentineld`) has no TLS dependency and builds fully static against musl.
- **Only scan systems you own or are authorised to test.** Port scanning and
  vulnerability probing are illegal in many jurisdictions without written
  permission.

## Hardening Notes

- All subprocess invocation uses list-form `argv`; no shell is spawned.
- Engine downloads are verified against the upstream SHA-256 release checksum
  and are refused if the checksum is absent or mismatched.
- The native engine invokes `iptables` via `fork`/`execvp` with the address as
  a discrete argument, never through a shell.
- Alert output is JSON-escaped per RFC 8259 before being written to
  `sentinel_events.jsonl`.
- The HTML report escapes every interpolated value.

## State Directory

Runtime state is written under `~/.sentinel` (override with `SENTINEL_HOME`).
It contains canary manifests, FIM baselines, and trip logs. It is created with
mode `0700`. Back it up if you rely on FIM baselines, and do not commit it.
