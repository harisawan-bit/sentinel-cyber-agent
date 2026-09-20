"""Lightweight multi-threaded LAN port & homelab service scanner.

Designed for minimal memory and CPU usage on low-power devices, Pentium, and ARM.
Zero third-party dependencies — pure Python standard library socket.
"""
from __future__ import annotations
import socket, ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator, Dict, Any, List

from sentinel.core.models import Finding, Severity, FindingType
from sentinel.core.plugin import Plugin

HOMELAB_PORTS = {
    21: ("FTP", "high", "Storage"),
    22: ("SSH", "info", "Remote Access"),
    23: ("Telnet (Insecure)", "critical", "Legacy"),
    53: ("DNS (Pi-hole/AdGuard)", "info", "Network"),
    80: ("HTTP Web", "info", "Web"),
    81: ("Nginx Proxy Manager", "medium", "Proxy"),
    443: ("HTTPS Web", "info", "Web"),
    445: ("SMB File Sharing", "medium", "Storage"),
    1880: ("Node-RED", "medium", "Automation"),
    1883: ("MQTT Broker", "medium", "IoT"),
    2049: ("NFS Storage", "medium", "Storage"),
    2375: ("Docker Daemon (Raw TCP)", "critical", "Containers"),
    2376: ("Docker Daemon (TLS)", "medium", "Containers"),
    3000: ("AdGuard / Grafana", "info", "Web"),
    3306: ("MySQL / MariaDB", "medium", "Database"),
    3389: ("RDP Remote Desktop", "medium", "Remote Access"),
    5000: ("Synology DSM", "info", "Storage"),
    5432: ("PostgreSQL", "medium", "Database"),
    5900: ("VNC Desktop", "high", "Remote Access"),
    6379: ("Redis DB", "high", "Database"),
    8006: ("Proxmox VE Console", "medium", "Hypervisor"),
    8080: ("Traefik / Alt HTTP", "info", "Web"),
    8086: ("InfluxDB", "medium", "Database"),
    8096: ("Jellyfin Media", "info", "Media"),
    8123: ("Home Assistant", "medium", "Automation"),
    8443: ("UniFi Controller", "info", "Management"),
    8989: ("Sonarr Automation", "low", "Media"),
    9000: ("Portainer Console", "medium", "Containers"),
    9090: ("Cockpit Admin", "medium", "Management"),
    9443: ("Portainer HTTPS", "medium", "Containers"),
    27017: ("MongoDB", "high", "Database"),
    32400: ("Plex Media Server", "info", "Media"),
}


class LanScannerPlugin(Plugin):
    name = "lan_scanner"
    stage = "recon"
    description = "Ultra-lean multi-threaded homelab port and service discovery"

    def _probe_port(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.35)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def run(self, target: str, ctx) -> Iterator[Finding]:
        # Expand target if CIDR notation (e.g. 192.168.1.0/28), max 32 hosts per batch
        hosts: List[str] = []
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in list(net.hosts())[:32]]
        except ValueError:
            hosts = [target]

        for host in hosts:
            open_ports = []
            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = {pool.submit(self._probe_port, host, p): p for p in HOMELAB_PORTS}
                for f, p in futures.items():
                    if f.result():
                        open_ports.append(p)

            for port in sorted(open_ports):
                svc, sev, cat = HOMELAB_PORTS.get(port, ("Unknown", "info", "General"))
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.PORT,
                    value=f"{port}/tcp",
                    target=host,
                    severity=sev,
                    detail=f"{svc} ({cat})",
                    metadata={"port": port, "service": svc, "category": cat, "host": host},
                )
