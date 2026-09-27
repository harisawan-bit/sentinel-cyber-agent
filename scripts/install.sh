#!/bin/sh
# Sentinel installer.
#
# Builds from source, verifies the result actually runs, then installs to
# /usr/local/bin. Designed to be safe to re-run: it never clobbers a working
# binary without proving the new one passes its self-test first.
set -eu

PREFIX="${PREFIX:-/usr/local}"
# This script lives in scripts/ in the source tree, and at the top level of a
# release tarball. Resolve both layouts to the directory holding the binaries.
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -f "$HERE/Makefile" ]; then
  # Source checkout: this script is in scripts/, the Makefile one level up.
  REPO="$HERE/.."
  BINDIR="$REPO/bin"
elif [ -f "$HERE/../Makefile" ]; then
  REPO="$HERE/.."
  BINDIR="$REPO/bin"
else
  # Release tarball: the binaries sit beside this script.
  REPO="$HERE"
  BINDIR="$HERE"
fi
CC="${CC:-cc}"

log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- platform
UNAME="$(uname -s)"
case "$UNAME" in
  Linux)  PLATFORM=linux ;;
  Darwin) PLATFORM=darwin ;;
  *)      die "unsupported platform: $UNAME. Sentinel targets Linux and macOS." ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)             die "unsupported architecture: $(uname -m)" ;;
esac

# ------------------------------------------------------------ requirements
command -v "$CC" >/dev/null 2>&1 || die "no C compiler found (set CC=...)"
log "compiler: $("$CC" --version 2>/dev/null | head -1)"

# OpenSSL is the one link-time dependency. C99 has no TLS, so this is required
# for the HTTPS-based plugins; there is no way around it short of bundling a
# TLS stack, which would be a larger security liability than the dependency.
if ! printf '#include <openssl/ssl.h>\nint main(void){return 0;}\n' \
     | "$CC" -x c - -o /dev/null -lssl -lcrypto 2>/dev/null; then
  case "$PLATFORM" in
    linux)
      warn "OpenSSL development headers not found."
      warn "install them, then re-run:"
      warn "  Debian/Ubuntu  sudo apt-get install -y build-essential libssl-dev"
      warn "  RHEL/Fedora    sudo dnf install -y gcc openssl-devel"
      warn "  Alpine         sudo apk add build-base openssl-dev"
      warn "  macOS          xcode-select --install"
      die "OpenSSL (libssl-dev) is required to build the agent."
      ;;
  esac
fi
log "OpenSSL: available"

# ------------------------------------------------------------------ build
# A release tarball ships prebuilt binaries alongside this script, so the
# normal case there is "install what you were given" rather than "build again".
# Building still happens when the source tree is present and a Makefile exists.
if [ -f "$REPO/Makefile" ]; then
  log "building in $REPO"
  make -C "$REPO" all >/dev/null || die "build failed in $REPO"
elif [ -x "$BINDIR/sentinel" ]; then
  log "no Makefile found; installing the prebuilt binaries in $BINDIR"
else
  die "neither a Makefile nor prebuilt binaries found in $REPO"
fi

[ -x "$BINDIR/sentinel" ]   || die "bin/sentinel was missing after the build"
[ -x "$BINDIR/sentineld" ]  || die "bin/sentineld was missing after the build"

# --------------------------------------------------------- verify before install
log "verifying the build before installing"
( cd "$(mktemp -d)" && SENTINEL_HOME="$PWD/state" "$BINDIR/sentineld" --self-test ) \
  >/dev/null || die "sentineld failed its self-test; not installing"

TMP_SCAN="$(mktemp -d)"
if ( cd "$TMP_SCAN" && SENTINEL_HOME="$PWD/state" "$BINDIR/sentinel" localhost \
       --stages audit --out out.json >/dev/null 2>&1 ); then
  log "smoke scan ok ($(grep -c '"id"' "$TMP_SCAN/out.json" 2>/dev/null || echo '?') findings)"
else
  warn "the smoke scan did not succeed; the binary still self-tested, continuing"
fi
rm -rf "$TMP_SCAN"

# ---------------------------------------------------------------- install
DEST="$PREFIX/bin"
if [ ! -d "$DEST" ]; then
  mkdir -p "$DEST" 2>/dev/null || {
    warn "cannot create $DEST. Re-run with sudo, or set PREFIX to a directory you own."
    exit 1
  }
fi
if [ -w "$DEST" ]; then
  install -m 0755 "$BINDIR/sentinel"  "$DEST/sentinel"  || die "install failed"
  install -m 0755 "$BINDIR/sentineld" "$DEST/sentineld" || die "install failed"
  log "installed $DEST/sentinel and $DEST/sentineld"
  if [ -x "$BINDIR/sentineld-static" ]; then
    install -m 0755 "$BINDIR/sentineld-static" "$DEST/sentineld-static"
    log "installed $DEST/sentineld-static (musl, no shared library dependencies)"
  fi
else
  warn "$DEST is not writable. Re-run with sudo, or set PREFIX to a directory you own:"
  warn "  sudo PREFIX=/usr/local ./scripts/install.sh"
  exit 1
fi

# ----------------------------------------------------------------- verify
if command -v sentinel >/dev/null 2>&1; then
  log "installed: $(sentinel --version 2>&1 | head -1)"
else
  warn "installed to $DEST, which is not on your PATH. Add it:"
  warn "  export PATH=\"$DEST:\$PATH\""
fi

cat <<'EOF'

Next steps:
  sentinel --help                 show every flag
  sentinel myhost --stages recon  discover subdomains and open ports
  sentinel --stages audit         audit this host's kernel and processes
  sentinel --install-systemd      run continuously as a service (needs root)

State lives in $SENTINEL_HOME, or ~/.sentinel by default.
EOF
