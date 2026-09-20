#!/usr/bin/env python3
"""Generate sample autonomous HTML dashboard with representative homelab findings."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.report import render

sample_findings = [
    # Homelab Server 192.168.1.50 (Proxmox / Docker host)
    Finding('lan_scanner', FindingType.PORT, '2375/tcp', '192.168.1.50', Severity.CRITICAL, detail='Docker Daemon (Raw TCP) — Unencrypted remote API access detected', metadata={'port': 2375, 'service': 'Docker Daemon', 'category': 'Containers'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '6379/tcp', '192.168.1.50', Severity.HIGH, detail='Redis DB — In-memory store listening without auth', metadata={'port': 6379, 'service': 'Redis DB', 'category': 'Database'}).to_dict(),
    Finding('cert_audit', FindingType.MISCONFIGURATION, 'cert:8006/tcp', '192.168.1.50', Severity.HIGH, detail='Certificate on port 8006 expires in 6 days (Let\'s Encrypt)', metadata={'port': 8006, 'days_left': 6}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '8006/tcp', '192.168.1.50', Severity.MEDIUM, detail='Proxmox VE Console — Hypervisor management interface active', metadata={'port': 8006, 'service': 'Proxmox VE Console', 'category': 'Hypervisor'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '9443/tcp', '192.168.1.50', Severity.MEDIUM, detail='Portainer HTTPS — Docker management UI', metadata={'port': 9443, 'service': 'Portainer HTTPS', 'category': 'Containers'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '8123/tcp', '192.168.1.50', Severity.MEDIUM, detail='Home Assistant — Local smart home orchestrator', metadata={'port': 8123, 'service': 'Home Assistant', 'category': 'Automation'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '22/tcp', '192.168.1.50', Severity.INFO, detail='SSH OpenSSH 9.6 — Public key authentication enforced', metadata={'port': 22, 'service': 'SSH', 'category': 'Remote Access'}).to_dict(),

    # Gateway Router 192.168.1.1 (OPNsense / UniFi)
    Finding('lan_scanner', FindingType.PORT, '53/tcp', '192.168.1.1', Severity.INFO, detail='DNS (Pi-hole / Unbound resolver)', metadata={'port': 53, 'service': 'DNS (Pi-hole/Unbound)', 'category': 'Network'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '443/tcp', '192.168.1.1', Severity.INFO, detail='HTTPS Router Management UI', metadata={'port': 443, 'service': 'HTTPS Web', 'category': 'Network'}).to_dict(),

    # Storage Node 192.168.1.100 (TrueNAS / Media)
    Finding('lan_scanner', FindingType.PORT, '445/tcp', '192.168.1.100', Severity.MEDIUM, detail='SMB File Sharing — Samba dialect 3.1.1', metadata={'port': 445, 'service': 'SMB File Sharing', 'category': 'Storage'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '2049/tcp', '192.168.1.100', Severity.MEDIUM, detail='NFS Storage — Network File System mount daemon', metadata={'port': 2049, 'service': 'NFS Storage', 'category': 'Storage'}).to_dict(),
    Finding('lan_scanner', FindingType.PORT, '32400/tcp', '192.168.1.100', Severity.INFO, detail='Plex Media Server — Streaming server operational', metadata={'port': 32400, 'service': 'Plex Media Server', 'category': 'Media'}).to_dict(),

    # Drift & State events
    Finding('state_diff', FindingType.NOTE, 'drift:2375/tcp', '192.168.1.50', Severity.HIGH, detail='🚨 [NEW PORT DETECTED] 2375/tcp appeared on 192.168.1.50 since last scan').to_dict(),
]

if __name__ == '__main__':
    html = render(sample_findings, title="Homelab Audit Report")
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel_report_sample.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Generated sample report at {out_path} ({len(html)} bytes)")
