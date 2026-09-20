"""Lightweight SSL/TLS certificate expiration & validity auditor.

Zero third-party dependencies — pure Python standard library ssl & socket.
"""
from __future__ import annotations
import socket, ssl
from datetime import datetime, timezone
from typing import Iterator

from sentinel.core.models import Finding, FindingType
from sentinel.core.plugin import Plugin

TLS_PORTS = [443, 8443, 8006, 9443, 5001]


class CertAuditPlugin(Plugin):
    name = "cert_audit"
    stage = "scan"
    description = "Checks SSL/TLS certificate validity, expiry, and self-signed status"

    def run(self, target: str, ctx) -> Iterator[Finding]:
        for port in TLS_PORTS:
            try:
                ctx_ssl = ssl.create_default_context()
                ctx_ssl.check_hostname = False
                ctx_ssl.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target, port), timeout=0.5) as sock:
                    with ctx_ssl.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        if not cert:
                            continue
                        exp_str = cert.get("notAfter")
                        if not exp_str:
                            continue
                        exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (exp_dt - now).days

                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        is_self_signed = issuer.get("commonName") == subject.get("commonName")

                        if days_left <= 0:
                            sev = "critical"
                            detail = f"Certificate on port {port} EXPIRED {abs(days_left)} days ago"
                        elif days_left < 14:
                            sev = "high"
                            detail = f"Certificate on port {port} expires soon ({days_left} days remaining)"
                        elif days_left < 30:
                            sev = "medium"
                            detail = f"Certificate on port {port} expires in {days_left} days"
                        else:
                            sev = "info"
                            detail = f"Valid certificate ({days_left} days left) issued by {issuer.get('commonName', 'Unknown')}"

                        if is_self_signed and sev == "info":
                            sev = "low"
                            detail += " · Self-signed"

                        yield Finding(
                            tool=self.name,
                            finding_type=FindingType.MISCONFIGURATION if days_left < 30 else FindingType.NOTE,
                            value=f"cert:{port}/tcp",
                            target=target,
                            severity=sev,
                            detail=detail,
                            metadata={"port": port, "days_left": days_left, "self_signed": is_self_signed},
                        )
            except Exception:
                continue
