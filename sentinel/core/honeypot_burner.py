"""Ultra-Lightweight Burner Honeypot Sandbox Engine.

Provides an isolated, resource-constrained "burner" sandbox that diverts attackers
away from production systems with virtually zero host resource drainage:
1. Docker Compose Burner Blueprint: Memory-capped (32MB), CPU-capped (0.05 CPU),
   read-only filesystem, dropped kernel capabilities, and isolated bridge network.
2. Built-in Pure-Python Micro-Burner Daemon (<5MB RAM, zero Docker dependency):
   Simulates minimal SSH (2222), SMTP (2525), and n8n webhook (5678) trap endpoints.
"""
from __future__ import annotations
import json, os, socket, threading, time
from typing import Dict, Any, List, Optional, Tuple

BURNER_LOG_FILE = os.path.expanduser("~/.sentinel/burner_traps.json")


def generate_burner_docker_compose(
    ssh_port: int = 2222,
    smtp_port: int = 2525,
    n8n_port: int = 5678,
    memory_limit: str = "32m",
    cpu_limit: str = "0.05"
) -> str:
    """Generate production-ready docker-compose.burner.yml configuration."""
    return f"""# ====================================================================
# Sentinel Burner Honeypot Sandbox (Zero-Drain Isolation Machine)
# Capped at {memory_limit} RAM, {cpu_limit} CPU, read-only rootfs, dropped capabilities.
# Diverts automated bots, rogue AI, and attackers away from host assets.
# ====================================================================
version: "3.8"

services:
  sentinel-burner:
    image: alpine:latest
    container_name: sentinel-burner-sandbox
    hostname: internal-staging-worker
    restart: unless-stopped
    command: >
      sh -c "echo 'Starting Sentinel Burner Trap...' &&
             nc -lk -p {ssh_port} -e sh -c 'echo \"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\"; sleep 1' &
             nc -lk -p {smtp_port} -e sh -c 'echo \"220 internal.smtp.relay ESMTP ready\"; sleep 1' &
             nc -lk -p {n8n_port} -e sh -c 'echo -e \"HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{{\\\"status\\\":\\\"queued\\\"}}\"; sleep 1' &
             wait"
    ports:
      - "127.0.0.1:{ssh_port}:{ssh_port}"
      - "127.0.0.1:{smtp_port}:{smtp_port}"
      - "127.0.0.1:{n8n_port}:{n8n_port}"
    read_only: true
    tmpfs:
      - /tmp:size=16M,noexec,nosuid,nodev
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '{cpu_limit}'
          memory: {memory_limit}
        reservations:
          cpus: '0.01'
          memory: 8m
    networks:
      - sentinel-burner-net

networks:
  sentinel-burner-net:
    driver: bridge
    internal: false
"""


def _log_burner_event(service: str, remote_ip: str, remote_port: int, raw_data: str) -> None:
    """Record interactions with burner trap endpoints."""
    os.makedirs(os.path.dirname(BURNER_LOG_FILE), exist_ok=True)
    events = []
    if os.path.exists(BURNER_LOG_FILE):
        try:
            with open(BURNER_LOG_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        except Exception:
            events = []

    events.append({
        "service": service,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "payload": raw_data[:200],
        "timestamp": time.time(),
    })
    events = events[-100:]
    try:
        with open(BURNER_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)
    except Exception:
        pass


class MicroBurnerDaemon:
    """Pure-Python micro-burner trap simulating decoy services with <5MB RAM."""

    def __init__(self, host: str = "0.0.0.0", ssh_port: int = 2222, smtp_port: int = 2525, n8n_port: int = 5678):
        self.host = host
        self.ssh_port = ssh_port
        self.smtp_port = smtp_port
        self.n8n_port = n8n_port
        self.running = False
        self.sockets: List[socket.socket] = []

    def _handle_ssh(self, client: socket.socket, addr: Tuple[str, int]):
        try:
            client.settimeout(2.0)
            client.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
            data = client.recv(1024)
            _log_burner_event("SSH_DECOY", addr[0], addr[1], data.decode("utf-8", "ignore"))
        except Exception:
            pass
        finally:
            client.close()

    def _handle_smtp(self, client: socket.socket, addr: Tuple[str, int]):
        try:
            client.settimeout(2.0)
            client.sendall(b"220 mail.internal.corp ESMTP Sentinel-Burner Ready\r\n")
            data = client.recv(1024)
            _log_burner_event("SMTP_DECOY", addr[0], addr[1], data.decode("utf-8", "ignore"))
            client.sendall(b"503 5.5.1 Error: authentication failed\r\n")
        except Exception:
            pass
        finally:
            client.close()

    def _handle_n8n(self, client: socket.socket, addr: Tuple[str, int]):
        try:
            client.settimeout(2.0)
            data = client.recv(2048)
            _log_burner_event("N8N_WEBHOOK_DECOY", addr[0], addr[1], data.decode("utf-8", "ignore"))
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 42\r\n"
                b"Connection: close\r\n\r\n"
                b'{"status":"received","workflow":"queued"}'
            )
            client.sendall(response)
        except Exception:
            pass
        finally:
            client.close()

    def _listener(self, port: int, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, port))
            s.listen(10)
            s.settimeout(1.0)
            self.sockets.append(s)
        except Exception:
            s.close()
            return

        while self.running:
            try:
                conn, addr = s.accept()
                t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
        s.close()

    def start(self):
        self.running = True
        threading.Thread(target=self._listener, args=(self.ssh_port, self._handle_ssh), daemon=True).start()
        threading.Thread(target=self._listener, args=(self.smtp_port, self._handle_smtp), daemon=True).start()
        threading.Thread(target=self._listener, args=(self.n8n_port, self._handle_n8n), daemon=True).start()

    def stop(self):
        self.running = False
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass
