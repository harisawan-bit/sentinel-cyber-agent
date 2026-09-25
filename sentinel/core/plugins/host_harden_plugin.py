"""Linux & Host Exploit Mitigation and Server Hardening Auditor.

Pure-Python, MIT license, zero dependencies.
Audits kernel exploit mitigations, namespace isolation, mount security,
and server hardening flags that prevent or mitigate 0-day exploits
(memory corruption, local privilege escalation, container escapes).
"""
from __future__ import annotations
import os, sys, stat
from typing import Iterator, Dict, Any, List, Tuple
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity


class HostHardenPlugin(Plugin):
    name = "host_harden"
    description = "Audit kernel exploit mitigations, memory protections, and mount security for 0-day resilience"
    stage = "audit"
    requires = []

    def _read_sysctl(self, path: str) -> str | None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
        except Exception:
            return None

    def _audit_linux_kernel(self) -> Iterator[Finding]:
        target = "localhost"

        # 1. ASLR (Address Space Layout Randomization)
        # Prevents predictable memory addresses in buffer overflow / ROP 0-day exploits.
        aslr = self._read_sysctl("/proc/sys/kernel/randomize_va_space")
        if aslr is not None:
            if aslr == "2":
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.HARDENING if hasattr(FindingType, "HARDENING") else "hardening",
                    value="kernel.randomize_va_space = 2",
                    target=target,
                    severity=Severity.INFO,
                    detail="Full ASLR enabled (Heap, Stack, VDSO, and mmap randomization active).",
                    metadata={"mitigation": "ASLR", "value": aslr, "status": "secure"}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value=f"kernel.randomize_va_space = {aslr}",
                    target=target,
                    severity=Severity.CRITICAL if aslr == "0" else Severity.HIGH,
                    detail="ASLR is disabled or incomplete! Memory corruption 0-days can execute reliable ROP/shellcode.",
                    metadata={"mitigation": "ASLR", "value": aslr, "status": "vulnerable"}
                )

        # 2. Unprivileged User Namespaces Clone
        # Disabling unprivileged user namespaces neutralizes ~60% of modern Linux privilege escalation 0-days.
        userns = self._read_sysctl("/proc/sys/kernel/unprivileged_userns_clone")
        if userns is not None:
            if userns == "0":
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value="kernel.unprivileged_userns_clone = 0",
                    target=target,
                    severity=Severity.INFO,
                    detail="Unprivileged user namespaces disabled. Blocks user namespace privilege escalation chains.",
                    metadata={"mitigation": "userns", "value": userns, "status": "secure"}
                )
            elif userns == "1":
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value="kernel.unprivileged_userns_clone = 1",
                    target=target,
                    severity=Severity.HIGH,
                    detail="Unprivileged user namespaces are enabled. Attackers can reach unhardened kernel attack surfaces.",
                    metadata={"mitigation": "userns", "value": userns, "status": "exposed"}
                )

        # 3. Kernel Pointer Restrict (kptr_restrict)
        # Prevents leaking kernel addresses to unprivileged users.
        kptr = self._read_sysctl("/proc/sys/kernel/kptr_restrict")
        if kptr is not None:
            if kptr in ("1", "2"):
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value=f"kernel.kptr_restrict = {kptr}",
                    target=target,
                    severity=Severity.INFO,
                    detail="Kernel symbol pointers hidden from unprivileged users (/proc/kallsyms).",
                    metadata={"mitigation": "kptr_restrict", "value": kptr, "status": "secure"}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value=f"kernel.kptr_restrict = {kptr}",
                    target=target,
                    severity=Severity.MEDIUM,
                    detail="Kernel addresses exposed via kallsyms. Facilitates kernel exploit offset calculations.",
                    metadata={"mitigation": "kptr_restrict", "value": kptr, "status": "vulnerable"}
                )

        # 4. dmesg restriction (dmesg_restrict)
        dmesg = self._read_sysctl("/proc/sys/kernel/dmesg_restrict")
        if dmesg is not None:
            if dmesg == "1":
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value="kernel.dmesg_restrict = 1",
                    target=target,
                    severity=Severity.INFO,
                    detail="Unprivileged dmesg logging access restricted. Protects kernel crash dumps and pointers.",
                    metadata={"mitigation": "dmesg_restrict", "value": dmesg, "status": "secure"}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value="kernel.dmesg_restrict = 0",
                    target=target,
                    severity=Severity.LOW,
                    detail="Kernel dmesg log buffer accessible to unprivileged users. May leak sensitive addresses.",
                    metadata={"mitigation": "dmesg_restrict", "value": dmesg, "status": "exposed"}
                )

        # 5. Protected symlinks, hardlinks, fifos, regular files
        for fs_param, expected in [
            ("protected_symlinks", "1"),
            ("protected_hardlinks", "1"),
            ("protected_fifos", "2"),
            ("protected_regular", "2"),
        ]:
            val = self._read_sysctl(f"/proc/sys/fs/{fs_param}")
            if val is not None:
                if val == expected or (expected == "2" and val == "1"):
                    yield Finding(
                        tool=self.name,
                        finding_type="hardening",
                        value=f"fs.{fs_param} = {val}",
                        target=target,
                        severity=Severity.INFO,
                        detail=f"Filesystem TOCTOU symlink/hardlink protection active ({fs_param}).",
                        metadata={"mitigation": fs_param, "value": val, "status": "secure"}
                    )
                else:
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.MISCONFIGURATION,
                        value=f"fs.{fs_param} = {val}",
                        target=target,
                        severity=Severity.MEDIUM,
                        detail=f"Filesystem race condition protection disabled (fs.{fs_param}). Vulnerable to /tmp symlink attacks.",
                        metadata={"mitigation": fs_param, "value": val, "status": "vulnerable"}
                    )

        # 6. Unprivileged BPF Disabled
        bpf = self._read_sysctl("/proc/sys/kernel/unprivileged_bpf_disabled")
        if bpf is not None:
            if bpf in ("1", "2"):
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value=f"kernel.unprivileged_bpf_disabled = {bpf}",
                    target=target,
                    severity=Severity.INFO,
                    detail="Unprivileged eBPF execution is disabled. Mitigates Spectre and eBPF kernel vulnerabilities.",
                    metadata={"mitigation": "bpf_restrict", "value": bpf, "status": "secure"}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value=f"kernel.unprivileged_bpf_disabled = {bpf}",
                    target=target,
                    severity=Severity.HIGH,
                    detail="Unprivileged eBPF is enabled. Allows arbitrary unprivileged users to load BPF bytecode.",
                    metadata={"mitigation": "bpf_restrict", "value": bpf, "status": "exposed"}
                )

        # 7. Yama ptrace scope (prevent process memory injection)
        yama = self._read_sysctl("/proc/sys/kernel/yama/ptrace_scope")
        if yama is not None:
            if yama in ("1", "2", "3"):
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value=f"kernel.yama.ptrace_scope = {yama}",
                    target=target,
                    severity=Severity.INFO,
                    detail="Yama ptrace protection active. Restricts process memory attachment and injection.",
                    metadata={"mitigation": "yama", "value": yama, "status": "secure"}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value="kernel.yama.ptrace_scope = 0",
                    target=target,
                    severity=Severity.MEDIUM,
                    detail="Yama ptrace protection disabled. Processes can attach to other processes owned by the same user.",
                    metadata={"mitigation": "yama", "value": yama, "status": "exposed"}
                )

    def _audit_mounts(self) -> Iterator[Finding]:
        target = "localhost"
        mounts_path = "/proc/mounts"
        if not os.path.exists(mounts_path):
            return

        critical_mounts = {"/tmp", "/var/tmp", "/dev/shm"}
        found_mounts = {}
        try:
            with open(mounts_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        m_point = parts[1]
                        m_opts = set(parts[3].split(","))
                        if m_point in critical_mounts:
                            found_mounts[m_point] = m_opts
        except Exception:
            return

        for m_point, opts in found_mounts.items():
            missing = []
            for opt in ["noexec", "nosuid", "nodev"]:
                if opt not in opts:
                    missing.append(opt)

            if missing:
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.MISCONFIGURATION,
                    value=f"mount {m_point}: missing {','.join(missing)}",
                    target=target,
                    severity=Severity.MEDIUM,
                    detail=f"Shared temporary path {m_point} allows binary execution or suid elevation.",
                    metadata={"mount": m_point, "missing_options": missing}
                )
            else:
                yield Finding(
                    tool=self.name,
                    finding_type="hardening",
                    value=f"mount {m_point}: hardened (noexec, nosuid, nodev)",
                    target=target,
                    severity=Severity.INFO,
                    detail=f"{m_point} is protected against binary drop and execution.",
                    metadata={"mount": m_point, "status": "secure"}
                )

    def _audit_container_exposure(self) -> Iterator[Finding]:
        target = "localhost"
        docker_sock = "/var/run/docker.sock"
        if os.path.exists(docker_sock):
            try:
                st = os.stat(docker_sock)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o007:  # world readable/writable
                    yield Finding(
                        tool=self.name,
                        finding_type=FindingType.MISCONFIGURATION,
                        value="Insecure /var/run/docker.sock permissions",
                        target=target,
                        severity=Severity.CRITICAL,
                        detail="Docker socket is world-accessible. Any local user can escape to root privileges instantly.",
                        metadata={"path": docker_sock, "permissions": oct(mode)}
                    )
            except Exception:
                pass

        # Check if inside container with elevated capabilities
        cap_file = "/proc/1/status"
        if os.path.exists(cap_file) and os.path.exists("/.dockerenv"):
            try:
                with open(cap_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("CapEff:"):
                            capeff = line.split(":", 1)[1].strip()
                            if capeff in ("0000003fffffffff", "000001ffffffffff"):
                                yield Finding(
                                    tool=self.name,
                                    finding_type=FindingType.MISCONFIGURATION,
                                    value="Container running in --privileged mode",
                                    target=target,
                                    severity=Severity.CRITICAL,
                                    detail="Container has all host capabilities. Breakout to host is trivial.",
                                    metadata={"capeff": capeff}
                                )
            except Exception:
                pass

    def _audit_ssh_config(self) -> Iterator[Finding]:
        target = "localhost"
        sshd_paths = ["/etc/ssh/sshd_config", "/etc/sshd_config"]
        for p in sshd_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            clean = line.strip()
                            if clean.startswith("#") or not clean:
                                continue
                            parts = clean.split()
                            if len(parts) >= 2:
                                k, v = parts[0].lower(), parts[1].lower()
                                if k == "permitrootlogin" and v in ("yes", "prohibit-password"):
                                    yield Finding(
                                        tool=self.name,
                                        finding_type=FindingType.MISCONFIGURATION,
                                        value=f"sshd: PermitRootLogin {v}",
                                        target=target,
                                        severity=Severity.HIGH if v == "yes" else Severity.LOW,
                                        detail=f"SSH daemon allows root login directly ({v}).",
                                        metadata={"setting": k, "value": v}
                                    )
                                elif k == "passwordauthentication" and v == "yes":
                                    yield Finding(
                                        tool=self.name,
                                        finding_type=FindingType.MISCONFIGURATION,
                                        value="sshd: PasswordAuthentication yes",
                                        target=target,
                                        severity=Severity.MEDIUM,
                                        detail="Password authentication enabled. Vulnerable to credential stuffing / brute-force.",
                                        metadata={"setting": k, "value": v}
                                    )
                except Exception:
                    pass

    def run(self, target: str, ctx) -> Iterator[Finding]:
        # Target check: this plugin audits the server on which it is executed
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            # If target is remote, we only run if explicitly targeted as server audit
            if not getattr(ctx, "server_audit", False):
                return

        if sys.platform.startswith("linux"):
            yield from self._audit_linux_kernel()
            yield from self._audit_mounts()
            yield from self._audit_container_exposure()
            yield from self._audit_ssh_config()
        elif sys.platform == "win32":
            # Graceful Windows server audit indicators
            yield Finding(
                tool=self.name,
                finding_type="hardening",
                value="OS Platform: Windows Server / Desktop",
                target="localhost",
                severity=Severity.INFO,
                detail="Host is running Windows. Linux kernel audit checks skipped; host execution verified.",
                metadata={"platform": "win32"}
            )
        else:
            yield Finding(
                tool=self.name,
                finding_type="hardening",
                value=f"OS Platform: {sys.platform}",
                target="localhost",
                severity=Severity.INFO,
                detail=f"Platform {sys.platform} detected. Kernel sysctl audit skipped.",
                metadata={"platform": sys.platform}
            )
