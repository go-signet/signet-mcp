#!/bin/sh
# install.sh - Install the signet-mcp binary from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/go-signet/signet-mcp/main/install.sh | sh
#
# Environment variables:
#   VERSION      Release version to install (e.g. "v0.1.0"). Defaults to the latest release.
#   INSTALL_DIR  Directory to install the binary into. Defaults to ~/.local/bin
#                (no sudo required). When the directory is not already in PATH,
#                the installer appends an export line to the current shell's rc file.

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

# --- Skip when the requested version is already installed ---
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
INSTALLED_BIN=""
if [ -x "${INSTALL_DIR}/${BINARY}" ]; then
  INSTALLED_BIN="${INSTALL_DIR}/${BINARY}"
elif command -v "$BINARY" >/dev/null 2>&1; then
  INSTALLED_BIN="$(command -v "$BINARY")"
fi
if [ -n "$INSTALLED_BIN" ]; then
  # Output format: "signet-mcp version X.Y.Z" (older releases may not
  # support --version; treat failures as version unknown).
  INSTALLED_VERSION="$("$INSTALLED_BIN" --version 2>/dev/null | awk '{print $NF}')" || INSTALLED_VERSION=""
  if [ "${INSTALLED_VERSION#v}" = "$VERSION_NUM" ]; then
    info "${BINARY} ${VERSION} is already installed at ${INSTALLED_BIN}; nothing to do"
    exit 0
  fi
fi

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
mkdir -p "$INSTALL_DIR" || error "cannot create ${INSTALL_DIR}"
[ -w "$INSTALL_DIR" ] || error "no write permission for ${INSTALL_DIR} (set INSTALL_DIR to a writable directory)"
mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

info "Installed ${BINARY} ${VERSION} to ${INSTALL_DIR}/${BINARY}"

# Older releases may not support --version; ignore failures.
"${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || true

# --- Ensure INSTALL_DIR is in PATH ---
# Detect the user's login shell (the script itself runs under sh via curl | sh).
warn() { printf '\033[1;33mnote:\033[0m %s\n' "$1"; }

add_path_to_rc() {
  RC_FILE="$1"
  PATH_LINE="$2"
  # Skip when the rc file already references INSTALL_DIR.
  if [ -f "$RC_FILE" ] && grep -Fq "$INSTALL_DIR" "$RC_FILE" 2>/dev/null; then
    info "${RC_FILE} already contains ${INSTALL_DIR}; skipping"
    return 0
  fi
  if ! mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null; then
    warn "cannot create $(dirname "$RC_FILE"); add ${INSTALL_DIR} to PATH manually:"
    printf '  %s\n' "$PATH_LINE"
    return 0
  fi
  if ! printf '\n# Added by %s installer\n%s\n' "$BINARY" "$PATH_LINE" >> "$RC_FILE" 2>/dev/null; then
    warn "cannot write to ${RC_FILE}; add ${INSTALL_DIR} to PATH manually:"
    printf '  %s\n' "$PATH_LINE"
    return 0
  fi
  info "Added ${INSTALL_DIR} to PATH in ${RC_FILE}"
  info "Restart your shell or run: source ${RC_FILE}"
}

# Fixed-string match so glob metacharacters in a user-supplied INSTALL_DIR
# cannot break the PATH membership check.
if printf '%s' ":${PATH}:" | grep -Fq ":${INSTALL_DIR}:"; then
  : # Already in PATH; nothing to do.
else
  USER_SHELL="$(basename "${SHELL:-sh}")"
  case "$USER_SHELL" in
    zsh)
      add_path_to_rc "${ZDOTDIR:-$HOME}/.zshrc" "export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
    bash)
      # macOS runs interactive bash as a login shell, which reads ~/.bash_profile;
      # interactive non-login shells (the Linux default) read ~/.bashrc.
      if [ "$OS" = "darwin" ]; then
        add_path_to_rc "${HOME}/.bash_profile" "export PATH=\"${INSTALL_DIR}:\$PATH\""
      else
        add_path_to_rc "${HOME}/.bashrc" "export PATH=\"${INSTALL_DIR}:\$PATH\""
      fi
      ;;
    fish)
      add_path_to_rc "${HOME}/.config/fish/config.fish" "fish_add_path -- \"${INSTALL_DIR}\""
      ;;
    *)
      warn "${INSTALL_DIR} is not in your PATH. Add it with:"
      printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
      ;;
  esac
fi
