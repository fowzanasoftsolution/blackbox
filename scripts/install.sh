#!/bin/sh
# Blackbox installer — clean POSIX sh.
#
#   curl -fsSL https://raw.githubusercontent.com/fowzanasoftsolution/blackbox/main/scripts/install.sh | sh
#
# Detects OS/arch, downloads the latest GitHub Release binary, verifies its
# SHA-256 against the published SHA256SUMS, installs to /usr/local/bin (or
# ~/.local/bin when not root) and prints the 60-second quickstart.
#
# Environment overrides:
#   BLACKBOX_REPO          GitHub repo slug        (default fowzanasoftsolution/blackbox)
#   BLACKBOX_INSTALL_DIR   install prefix dir      (default /usr/local/bin)
#   BLACKBOX_TOKEN         GitHub token for private repos (optional)
#   BLACKBOX_DOWNLOAD_BASE serve files from this URL instead of GitHub releases
#                          (used by the project's own self-test with a mock server)

set -eu

REPO="${BLACKBOX_REPO:-fowzanasoftsolution/blackbox}"
INSTALL_DIR="${BLACKBOX_INSTALL_DIR:-/usr/local/bin}"

log()  { printf '%s\n' "==> $*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ----------------------------------------------------------------- detect ---
OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"

case "$OS" in
  Linux) ;;
  Darwin) die "no macOS build yet — build from source: git clone https://github.com/$REPO && cargo build --release" ;;
  *) die "unsupported OS: $OS (Blackbox ships Linux binaries)" ;;
esac

case "$ARCH" in
  x86_64|amd64)    ASSET="blackbox-x86_64-linux.tar.gz" ;;
  aarch64|arm64)   ASSET="blackbox-aarch64-linux.tar.gz" ;;
  *) die "unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

# ------------------------------------------------------------------ tools ---
command -v tar >/dev/null 2>&1 || die "tar is required"
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  die "curl or wget is required"
fi
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "sha256sum or shasum is required for checksum verification"
fi

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t blackbox)"
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() { # fetch <url> <outfile> — returns non-zero on failure; caller decides
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  else
    wget -qO "$2" "$1"
  fi
}

# Resolve the download URL for a release asset (latest release).
asset_url() { # asset_url <asset-name>
  if [ -n "${BLACKBOX_DOWNLOAD_BASE:-}" ]; then
    printf '%s/%s\n' "${BLACKBOX_DOWNLOAD_BASE%/}" "$1"
  elif [ -n "${BLACKBOX_TOKEN:-}" ]; then
    # Private repo: resolve through the GitHub API (needs a token).
    API="https://api.github.com/repos/$REPO/releases/latest"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL -H "Authorization: Bearer $BLACKBOX_TOKEN" "$API"
    else
      wget -qO- --header="Authorization: Bearer $BLACKBOX_TOKEN" "$API"
    fi | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*/'"$1"'\)".*/\1/p' |
      head -n 1
  else
    # Public repo: stable unauthenticated redirect to the latest asset.
    printf '%s\n' "https://github.com/$REPO/releases/latest/download/$1"
  fi
}

# ------------------------------------------------------------- download -----
log "detected $OS $ARCH → $ASSET"
log "fetching latest release from github.com/$REPO"

URL="$(asset_url "$ASSET")"
[ -n "$URL" ] || die "could not resolve download URL for $ASSET (private repo? set BLACKBOX_TOKEN)"
fetch "$URL" "$TMP/$ASSET" || die "download failed: $URL"

SUMS_URL="$(asset_url SHA256SUMS)"
if [ -n "$SUMS_URL" ]; then
  fetch "$SUMS_URL" "$TMP/SHA256SUMS" || warn "could not fetch SHA256SUMS — skipping checksum verification"
fi

# --------------------------------------------------------------- verify -----
if [ -f "$TMP/SHA256SUMS" ]; then
  log "verifying SHA-256"
  LINE="$(grep "  $ASSET\$" "$TMP/SHA256SUMS" || true)"
  [ -n "$LINE" ] || die "$ASSET missing from SHA256SUMS — refusing to install"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$LINE" | (cd "$TMP" && sha256sum -c -) || die "SHA-256 verification FAILED"
  else
    printf '%s\n' "$LINE" | (cd "$TMP" && shasum -a 256 -c -) || die "SHA-256 verification FAILED"
  fi
fi

# -------------------------------------------------------------- extract -----
(cd "$TMP" && tar -xzf "$ASSET")
[ -f "$TMP/blackbox" ] || die "archive did not contain a 'blackbox' binary"
chmod 755 "$TMP/blackbox"

"$TMP/blackbox" --version >/dev/null 2>&1 || die "downloaded binary failed to execute on this system"

# -------------------------------------------------------------- install -----
install_to() { # install_to <dest-dir>
  cp "$TMP/blackbox" "$1/blackbox.tmp.$$" || return 1
  chmod 755 "$1/blackbox.tmp.$$" || return 1
  mv "$1/blackbox.tmp.$$" "$1/blackbox" || return 1
}

if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
  install_to "$INSTALL_DIR" || die "failed to write into $INSTALL_DIR"
elif mkdir -p "$INSTALL_DIR" 2>/dev/null && [ -w "$INSTALL_DIR" ]; then
  install_to "$INSTALL_DIR" || die "failed to write into $INSTALL_DIR"
elif command -v sudo >/dev/null 2>&1 && sudo -n mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  sudo cp "$TMP/blackbox" "$INSTALL_DIR/blackbox" && sudo chmod 755 "$INSTALL_DIR/blackbox" ||
    die "sudo install into $INSTALL_DIR failed"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  install_to "$INSTALL_DIR" || die "failed to write into $INSTALL_DIR"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "$INSTALL_DIR is not on your PATH — add it: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
fi

log "installed $( "$INSTALL_DIR/blackbox" --version 2>/dev/null || echo blackbox ) → $INSTALL_DIR/blackbox"

cat <<'EOS'

  Blackbox is ready.

  60-second tour of all four engines (no setup, no config):
      blackbox demo

  Wrap your own app with the self-healing sidecar:
      blackbox run -- ./your-app

  Or proxy a running app (shield + TLS + FinOps egress):
      blackbox serve --upstream 127.0.0.1:3000 --tls-self-signed

  Admin dashboard + API:  http://127.0.0.1:9690
  Docs:                   https://github.com/fowzanasoftsolution/blackbox#readme

EOS
