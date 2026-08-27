#!/usr/bin/env python3
"""Download permissive engine binaries (projectdiscovery, MIT) into ./bin.

Only MIT/Apache engines are bundled. Copyleft engines (sqlmap, sliver, MobSF,
wazuh, MISP, radare2) are intentionally excluded — they must be invoked as
external processes, not vendored.
"""
from __future__ import annotations
import os, sys, zipfile, io, time, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
os.makedirs(BIN, exist_ok=True)

# projectdiscovery windows_amd64 release assets (served via /latest/download/)
ASSETS = {
    "nuclei": ("nuclei", "windows_amd64"),
    "subfinder": ("subfinder", "windows_amd64"),
    "httpx": ("httpx", "windows_amd64"),
}
BASE = "https://github.com/projectdiscovery/{name}/releases/latest/download/{asset}"


def fetch(url: str) -> bytes:
    print(f"  GET {url}")
    import subprocess
    # curl follows GitHub's multi-hop release-asset redirects reliably
    r = subprocess.run(["curl", "-sL", url], capture_output=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "ignore")[:200])
    if not r.stdout:
        raise RuntimeError("empty response")
    return r.stdout


def install_pd(name: str, base: str, arch: str) -> None:
    import subprocess as _sp
    # resolve the exact browser_download_url (avoid flaky /latest/download/ redirect)
    tag = _sp.run(
        ["gh", "api", f"repos/projectdiscovery/{base}/releases/latest", "--jq", ".tag_name"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    asset = f"{base}_{tag}_{arch}.zip"
    # /latest/download/ redirects to the release-assets CDN (proven to work);
    # this egress IP is intermittently throttled by GitHub -> retry patiently.
    url = f"https://github.com/projectdiscovery/{base}/releases/latest/download/{asset}"
    print(f"  GET {url}")
    tmp = "C:/hermes-agent-workspace/sentinel-cyber-agent/bin/_" + base + ".zip"
    last_err = ""
    for attempt in range(1, 11):
        try:
            r = _sp.run(["curl", "-sL", url, "-o", tmp], capture_output=True, timeout=300)
            if os.path.exists(tmp):
                with open(tmp, "rb") as fh:
                    head = fh.read(16)
                if head.startswith(b"Not Found") or os.path.getsize(tmp) < 1024:
                    last_err = f"attempt {attempt}: not-found/small"
                    time.sleep(8)
                    continue
                break
        except Exception as e:
            last_err = f"attempt {attempt}: {e}"
            time.sleep(8)
    else:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError(last_err or "download failed after retries")
    with open(tmp, "rb") as fh:
        data = fh.read()
    os.remove(tmp)
    z = zipfile.ZipFile(io.BytesIO(data))
    for info in z.infolist():
        if info.filename.lower().endswith(".exe"):
            dest = os.path.join(BIN, base + ".exe")
            with open(dest, "wb") as fh:
                fh.write(z.read(info))
            os.chmod(dest, 0o755)
            print(f"  -> {dest}")


def main() -> int:
    print("Installing permissive engines into ./bin ...")
    for name, (base, arch) in ASSETS.items():
        try:
            install_pd(name, base, arch)
        except Exception as e:
            print(f"  [!] {name} failed: {e}", file=sys.stderr)
    print("Installing sherlock (pip) ...")
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "sherlock-project"], check=False)
        print("  -> sherlock installed")
    except Exception as e:
        print(f"  [!] sherlock pip failed: {e}", file=sys.stderr)
    print("Done. Engines in:", BIN)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
