#!/bin/sh
# install.sh - Install the signet-mcp binary from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/go-signet/signet-mcp/main/install.sh | sh
#
# Environment variables:
#   VERSION      Release version to install (e.g. "v0.1.0"). Defaults to the latest release.
#   INSTALL_DIR  Directory to install the binary into. Defaults to /usr/local/bin
#                (falls back to ~/.local/bin when /usr/local/bin is not writable and sudo is unavailable).

set -eu

OWNER="go-signet"
REPO="signet-mcp"
BINARY="signet-mcp"
GITHUB="https://github.com/${OWNER}/${REPO}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || error "curl is required but not installed"
command -v tar >/dev/null 2>&1 || error "tar is required but not installed"

# --- Detect OS ---
OS="$(uname -s)"
case "$OS" in
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *) error "unsupported OS: $OS (only Linux and macOS are supported; Windows users can download from ${GITHUB}/releases)" ;;
esac

# --- Detect architecture ---
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) error "unsupported architecture: $ARCH (only amd64 and arm64 are supported)" ;;
esac

# --- Resolve version ---
VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  info "Fetching latest release version..."
  # Follow the releases/latest redirect to avoid GitHub API rate limits.
  VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${GITHUB}/releases/latest" | sed 's|.*/tag/||')"
  [ -n "$VERSION" ] || error "failed to determine the latest release version"
fi
# Strip the leading "v" for archive file names (goreleaser convention).
VERSION_NUM="${VERSION#v}"

ARCHIVE="${BINARY}_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
CHECKSUMS="${BINARY}_${VERSION_NUM}_checksums.txt"
DOWNLOAD_URL="${GITHUB}/releases/download/${VERSION}/${ARCHIVE}"
CHECKSUMS_URL="${GITHUB}/releases/download/${VERSION}/${CHECKSUMS}"

info "Installing ${BINARY} ${VERSION} (${OS}/${ARCH})"

# --- Download ---
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

info "Downloading ${DOWNLOAD_URL}"
curl -fsSL -o "${TMP_DIR}/${ARCHIVE}" "$DOWNLOAD_URL" ||
  error "download failed — check that release ${VERSION} exists at ${GITHUB}/releases"

# --- Verify checksum ---
if curl -fsSL -o "${TMP_DIR}/${CHECKSUMS}" "$CHECKSUMS_URL" 2>/dev/null; then
  info "Verifying checksum..."
  EXPECTED="$(grep " ${ARCHIVE}\$" "${TMP_DIR}/${CHECKSUMS}" | awk '{print $1}')"
  if [ -n "$EXPECTED" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL="$(sha256sum "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL="$(shasum -a 256 "${TMP_DIR}/${ARCHIVE}" | awk '{print $1}')"
    else
      ACTUAL=""
    fi
    if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
      error "checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
    fi
  fi
else
  info "Checksums file not found; skipping verification"
fi

# --- Extract ---
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
[ -f "${TMP_DIR}/${BINARY}" ] || error "binary '${BINARY}' not found in the downloaded archive"
chmod +x "${TMP_DIR}/${BINARY}"

# --- Install ---
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
elif command -v sudo >/dev/null 2>&1; then
  info "Elevated permissions required to install into ${INSTALL_DIR}"
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  INSTALL_DIR="${HOME}/.local/bin"
  info "No write permission for /usr/local/bin and sudo is unavailable; installing to ${INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

info "Installed ${BINARY} ${VERSION} to ${INSTALL_DIR}/${BINARY}"

# Releases prior to v0.2.0 do not support --version; ignore failures.
"${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || true

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) : ;;
  *) printf '\033[1;33mnote:\033[0m %s is not in your PATH. Add it with:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" ;;
esac
