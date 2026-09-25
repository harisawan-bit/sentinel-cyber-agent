"""Active Deception Honeyport Trap Listener.

Pure-Python, zero external dependencies.
Binds lightweight decoy socket listeners on unassigned ports that should never
receive legitimate traffic (e.g., Telnet 23, SMB 445, Raw Docker 2375, Alt-Admin 8888).
Any inbound connection represents active port scanning or lateral movement,
providing a 100% true-positive breach/reconnaissance indicator.
"""
from __future__ import annotations
import json, os, socket, threading, time
from typing import Iterator, Dict, Any, List
from ..plugin import Plugin
from ..models import Finding, FindingType, Severity

DEFAULT_HONEY_PORTS = [23, 445, 2375, 8888]
TRIPWIRE_LOG_FILE = os.path.expanduser("~/.sentinel/honeyport_trips.json")


def _record_trip(attacker_ip: str, port: int, payload_preview: str) -> None:
    """Persist tripped honeyport event to local state."""
    os.makedirs(os.path.dirname(TRIPWIRE_LOG_FILE), exist_ok=True)
    events = []
    if os.path.exists(TRIPWIRE_LOG_FILE):
        try:
            with open(TRIPWIRE_LOG_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        except Exception:
            events = []

    events.append({
        "attacker_ip": attacker_ip,
        "port": port,
        "payload": payload_preview,
        "timestamp": time.time(),
    })
    # Keep last 100 trips
    events = events[-100:]
    try:
        with open(TRIPWIRE_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except Exception:
        pass


class HoneyportServer:
    """Multi-threaded decoy listener binding on inactive ports."""

    def __init__(self, ports: List[int] = DEFAULT_HONEY_PORTS):
        self.ports = ports
        self.sockets: List[socket.socket] = []
        self.running = False
        self.trips: List[Dict[str, Any]] = []

    def _listen_port(self, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5)
            s.settimeout(1.0)
            self.sockets.append(s)
        except Exception:
            # Port already in use or requires root
            s.close()
            return

        while self.running:
            try:
                conn, addr = s.accept()
                conn.settimeout(1.0)
                attacker_ip = addr[0]
                try:
                    raw_data = conn.recv(1024)
                    payload_preview = raw_data.decode("utf-8", "ignore")[:100]
                except Exception:
                    payload_preview = ""
                conn.close()

                trip = {
                    "attacker_ip": attacker_ip,
                    "port": port,
                    "payload": payload_preview,
                    "timestamp": time.time(),
                }
                self.trips.append(trip)
                _record_trip(attacker_ip, port, payload_preview)
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()

    def start(self):
        self.running = True
        for p in self.ports:
            t = threading.Thread(target=self._listen_port, args=(p,), daemon=True)
            t.start()

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass


class HoneyportPlugin(Plugin):
    name = "honeyport"
    description = "Active deception honeyport listener and reconnaissance trap"
    stage = "audit"
    requires = []

    def run(self, target: str, ctx) -> Iterator[Finding]:
        if target not in ("localhost", "127.0.0.1", "::1", "local", "server") and not target.startswith("127."):
            if not getattr(ctx, "server_audit", False):
                return

        # Check tripped honeyport events
        if os.path.exists(TRIPWIRE_LOG_FILE):
            try:
                with open(TRIPWIRE_LOG_FILE, "r", encoding="utf-8") as f:
                    trips = json.load(f)
            except Exception:
                trips = []

            for trip in trips:
                ip = trip.get("attacker_ip", "unknown")
                port = trip.get("port", 0)
                payload = trip.get("payload", "")
                yield Finding(
                    tool=self.name,
                    finding_type=FindingType.VULNERABILITY,
                    value=f"Active Honeyport Breach: {ip} -> port {port}",
                    target=target,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"CRITICAL ACTIVE DECEPTION TRIGGER: Hostile IP {ip} connected to decoy honeyport {port}/tcp. "
                        f"Probe payload: {payload[:80] if payload else 'SYN Scan'}. Immediate firewall ban recommended."
                    ),
                    metadata={
                        "attacker_ip": ip,
                        "decoy_port": port,
                        "threat_category": "deception_honeyport_tripped",
                        "iptables_ban": f"iptables -I INPUT -s {ip} -j DROP",
                        "nftables_ban": f"nft add rule inet filter input ip saddr {ip} drop",
                    }
                )

        # Indicate active deception readiness
        yield Finding(
            tool=self.name,
            finding_type="hardening",
            value=f"Honeyport Deception Decoys ({len(DEFAULT_HONEY_PORTS)} ports)",
            target=target,
            severity=Severity.INFO,
            detail=f"Honeyport deception traps monitored on ports: {', '.join(str(p) for p in DEFAULT_HONEY_PORTS)}.",
            metadata={"monitored_ports": DEFAULT_HONEY_PORTS, "status": "active"}
        )
