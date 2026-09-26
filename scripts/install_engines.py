#!/usr/bin/env python3
"""Download permissive engine binaries (projectdiscovery, MIT) into ./bin.

Only MIT/Apache engines are bundled. Copyleft engines (sqlmap, sliver, MobSF,
wazuh, MISP, radare2) are intentionally excluded — they must be invoked as
external processes, not vendored.

Every archive is verified against the SHA-256 checksum published with the
release before extraction. An unverified binary is never installed or run.
"""
from __future__ import annotations
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")

ENGINES = ["nuclei", "subfinder", "httpx"]
REPO = {name: f"projectdiscovery/{name}" for name in ENGINES}

# Maps (OS, machine) to the asset naming used in projectdiscovery release zips.
# Note the capitalisation: upstream ships "macOS_amd64", not "macos_amd64".
ASSET_SUFFIX = {
    ("linux", "x86_64"): "linux_amd64",
    ("linux", "aarch64"): "linux_arm64",
    ("linux", "armv7l"): "linux_arm",
    ("darwin", "x86_64"): "macOS_amd64",
    ("darwin", "arm64"): "macOS_arm64",
    ("windows", "x86_64"): "windows_amd64",
}


def current_asset_suffix() -> str | None:
    """Return the release-asset suffix for the running platform, or None."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "aarch64"
    elif machine.startswith("armv7"):
        machine = "armv7l"
    return ASSET_SUFFIX.get((system, machine))


def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, timeout=timeout)


def fetch_latest_tag(repo: str) -> str | None:
    """Resolve the newest release tag via the GitHub API (gh CLI, then curl)."""
    if shutil.which("gh"):
        r = _run(["gh", "api", f"repos/{repo}/releases/latest", "--jq", ".tag_name"], 60)
        tag = r.stdout.decode("utf-8", "ignore").strip()
        if tag:
            return tag
    if shutil.which("curl"):
        r = _run([
            "curl", "-sL", "-H", "Accept: application/vnd.github+json",
            f"https://api.github.com/repos/{repo}/releases/latest",
        ], 60)
        try:
            return json.loads(r.stdout.decode("utf-8", "ignore")).get("tag_name")
        except Exception:
            return None
    return None


def fetch_release_checksums(repo: str, tag: str):
    """Return {filename: sha256} from the release checksums file.

    Returns None when the project publishes no checksums at all — the caller
    treats that as a hard stop rather than silently trusting the download.
    """
    if not shutil.which("curl"):
        return None
    # Upstream release assets embed the version *without* the leading "v" that
    # the git tag carries: tag v3.11.1 -> nuclei_3.11.1_checksums.txt
    ver = tag[1:] if tag.startswith("v") else tag
    for candidate in (
        "checksums.txt",
        f"{repo.split('/')[-1]}_{ver}_checksums.txt",
        f"{repo.split('/')[-1]}_{tag}_checksums.txt",
    ):
        r = _run(
            ["curl", "-sL", f"https://github.com/{repo}/releases/download/{tag}/{candidate}"],
            60,
        )
        body = r.stdout.decode("utf-8", "ignore")
        # A GitHub "not found" page is HTML, not a digest list; skip it and let
        # the next candidate try. Some upstreams prefix a "# sha256 ..." header
        # but projectdiscovery emits bare "<digest>  <filename>" lines.
        if "<html" in body.lower()[:200]:
            continue
        out: dict[str, str] = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or len(parts[0]) != 64:
                continue
            try:
                int(parts[0], 16)
            except ValueError:
                continue
            out[parts[1].lstrip("*")] = parts[0].lower()
        if out:
            return out
    return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def install_engine(name: str, asset_suffix: str) -> None:
    repo = REPO[name]
    tag = fetch_latest_tag(repo)
    if not tag:
        raise RuntimeError(f"could not resolve latest release tag for {repo}")

    ver = tag[1:] if tag.startswith("v") else tag
    asset = f"{name}_{ver}_{asset_suffix}.zip"
    url = f"https://github.com/{repo}/releases/download/{tag}/{asset}"

    checksums = fetch_release_checksums(repo, tag)
    if checksums is None:
        raise RuntimeError(
            f"{repo} {tag} publishes no checksum file; refusing to install an "
            f"unverified binary. Install {name} manually and place it in {BIN}."
        )
    expected = checksums.get(asset)
    if not expected:
        raise RuntimeError(
            f"{asset} is not listed in the {tag} checksums file; refusing to install."
        )

    print(f"  [{name}] {tag} -> {asset}")
    os.makedirs(BIN, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinel_dl_") as tmp:
        archive = os.path.join(tmp, asset)
        # This egress path is intermittently throttled by GitHub; retry patiently.
        for attempt in range(1, 6):
            r = _run(["curl", "-sL", "--fail", url, "-o", archive], 300)
            if r.returncode == 0 and os.path.getsize(archive) > 1024:
                break
            print(f"    retry {attempt}/5 ({r.stderr.decode('utf-8', 'ignore')[:60]})")
            time.sleep(5)
        else:
            raise RuntimeError("download failed after 5 attempts")

        digest = sha256_file(archive)
        if digest != expected:
            raise RuntimeError(
                f"checksum mismatch for {asset}\n"
                f"  expected {expected}\n  actual   {digest}"
            )
        print(f"    sha256 verified: {digest[:16]}...")

        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                low = info.filename.lower()
                if low.endswith(".exe") or "/" not in info.filename:
                    if not (low.endswith(name) or low.endswith(name + ".exe")):
                        continue
                    dest = os.path.join(BIN, name + (".exe" if low.endswith(".exe") else ""))
                    with open(dest, "wb") as fh:
                        fh.write(z.read(info))
                    os.chmod(dest, 0o755)
                    print(f"    -> {dest}")


def main() -> int:
    suffix = current_asset_suffix()
    if suffix is None:
        print(
            f"[!] Unsupported platform: {platform.system()}/{platform.machine()}. "
            f"Install engines manually into {BIN}.",
            file=sys.stderr,
        )
        return 1

    print(f"Installing permissive engines into {BIN} (platform asset: {suffix}) ...")
    failures = 0
    for name in ENGINES:
        try:
            install_engine(name, suffix)
        except Exception as e:
            print(f"  [!] {name} failed: {e}", file=sys.stderr)
            failures += 1

    print("Installing sherlock (pip) ...")
    try:
        _run([sys.executable, "-m", "pip", "install", "-q", "sherlock-project"], 300)
        print("  -> sherlock installed")
    except Exception as e:
        print(f"  [!] sherlock pip failed: {e}", file=sys.stderr)
        failures += 1

    if failures:
        print(
            f"\nDone with {failures} failure(s). First-party plugins "
            f"(http-probe, lan_scanner, host_harden, fim_audit, process_anomaly) "
            f"require no external engines.",
            file=sys.stderr,
        )
    else:
        print("Done. Engines in:", BIN)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
