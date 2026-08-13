#!/usr/bin/env sh
# bmcp installer - https://github.com/sirob-tech/boris-mcp-cli
# Usage: curl -fsSL https://raw.githubusercontent.com/sirob-tech/boris-mcp-cli/main/install.sh | sh

set -e

REPO="sirob-tech/boris-mcp-cli"
BINARY_NAME="bmcp"
INSTALL_DIR="${BMCP_INSTALL_DIR:-$HOME/.local/bin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
  printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
  printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
  printf "${RED}[ERROR]${NC} %s\n" "$1"
  exit 1
}

detect_os() {
  case "$(uname -s)" in
    Linux*) OS="linux" ;;
    Darwin*) OS="darwin" ;;
    *) error "Unsupported operating system: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

get_latest_version() {
  VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" \
    | grep -i '^location:' \
    | sed -E 's|.*/tag/([^[:space:]]+).*|\1|' \
    | tr -d '\r')

  if [ -z "$VERSION" ]; then
    warn "Redirect lookup failed, falling back to GitHub API..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name":' \
      | sed -E 's/.*"([^"]+)".*/\1/')
  fi

  if [ -z "$VERSION" ]; then
    error "Failed to get latest version (GitHub API may be rate-limited; set BMCP_VERSION=vX.Y.Z to pin)"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    error "Neither sha256sum nor shasum is available — cannot verify the download"
  fi
}

# Fails closed: a missing checksums.txt, a missing line for our asset, or an
# unusable hash tool all abort the install rather than falling through to an
# unverified binary. The downloaded file is named bmcp.tar.gz locally while
# checksums.txt lists the platform-specific asset name, so the asset name is
# passed in separately instead of running `shasum -c` over the file.
verify_checksum() {
  archive=$1
  sums_file=$2
  asset=$3

  if [ ! -s "$sums_file" ]; then
    error "checksums.txt is missing or empty — refusing to install an unverified binary"
  fi

  expected=$(awk -v want="$asset" '$2 == want { print $1; exit }' "$sums_file")
  if [ -z "$expected" ]; then
    error "checksums.txt has no entry for ${asset} — refusing to install an unverified binary"
  fi

  actual=$(sha256_of "$archive")
  if [ -z "$actual" ]; then
    error "Could not compute the sha256 of $archive"
  fi

  if [ "$expected" != "$actual" ]; then
    error "Checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
  fi
}

# Whitelists regular files and directories rather than blacklisting link types.
# A symlink member named bmcp would otherwise survive the path check below, and
# the later chmod and exec would follow it to a file outside the archive.
verify_archive_members() {
  archive=$1

  if tar -tzf "$archive" | grep -qE '^/|(^|/)\.\.(/|$)'; then
    error "Archive contains unsafe paths (absolute or directory traversal) — refusing to extract"
  fi

  # Deliberately awk rather than `grep -qv`: `grep -q -v` means "some line does
  # not match" on GNU grep but "no line matches" on BSD grep and ugrep, so the
  # grep form silently passed any archive containing at least one regular file
  # — which every real archive does.
  if ! tar -tvzf "$archive" | awk '
      { c = substr($1, 1, 1); if (c != "-" && c != "d") bad = 1 }
      END { exit(bad ? 1 : 0) }
    '; then
    error "Archive contains a non-regular member (symlink, hardlink, or device) — refusing to extract"
  fi
}

# BMCP_VERSION is interpolated straight into the download URL, and curl
# collapses ../ segments client-side — so an unvalidated value pivots the
# download to an arbitrary GitHub repo, taking checksums.txt with it and
# leaving the checksum gate verifying the attacker's own artifact.
validate_version() {
  case "$1" in
    "") error "Version must not be empty" ;;
    *[!A-Za-z0-9.+_-]*) error "Invalid version '$1': only letters, digits, and . + _ - are allowed" ;;
    *..*) error "Invalid version '$1': must not contain '..'" ;;
    v[0-9]*) ;;
    *) error "Invalid version '$1': expected a release tag such as v1.2.3" ;;
  esac
}

# A positive marker that this binary came from install.sh and is therefore safe
# for `bmcp update` to replace in place. bmcp otherwise has to guess from the
# path, which cannot distinguish ~/.local/bin from a Nix or mise shim.
write_receipt() {
  receipt="${INSTALL_DIR}/.bmcp.install.json"
  installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")
  cat >"$receipt" <<EOF
{
  "method": "install.sh",
  "repo": "${REPO}",
  "version": "${VERSION}",
  "asset": "${ASSET}",
  "installed_at": "${installed_at}"
}
EOF
  chmod 0644 "$receipt" 2>/dev/null || true
}

install() {
  info "Detected: $OS $ARCH"
  info "Version: $VERSION"

  ASSET="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

  # Staged inside INSTALL_DIR so the final `mv` is a same-filesystem rename.
  # From /tmp it is a copy, which can leave a half-written binary in place.
  mkdir -p "$INSTALL_DIR"
  TEMP_DIR=$(mktemp -d "${INSTALL_DIR}/.bmcp-install.XXXXXX")
  trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
  ARCHIVE="${TEMP_DIR}/${BINARY_NAME}.tar.gz"
  SUMS="${TEMP_DIR}/checksums.txt"

  info "Downloading from: $DOWNLOAD_URL"
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE"; then
    error "Failed to download binary"
  fi

  info "Verifying checksum..."
  if ! curl -fsSL "$CHECKSUMS_URL" -o "$SUMS"; then
    error "Failed to download checksums.txt — refusing to install an unverified binary"
  fi
  verify_checksum "$ARCHIVE" "$SUMS" "$ASSET"

  info "Verifying archive..."
  verify_archive_members "$ARCHIVE"

  info "Extracting..."
  tar -xzf "$ARCHIVE" -C "$TEMP_DIR"

  if [ ! -f "${TEMP_DIR}/${BINARY_NAME}" ]; then
    error "Archive did not contain a ${BINARY_NAME} binary"
  fi

  chmod +x "${TEMP_DIR}/${BINARY_NAME}"
  mv "${TEMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
  write_receipt
  rm -rf "$TEMP_DIR"
  trap - EXIT HUP INT TERM

  info "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
}

verify() {
  INSTALLED_BINARY="${INSTALL_DIR}/${BINARY_NAME}"
  if [ ! -x "$INSTALLED_BINARY" ]; then
    error "Installed binary is missing or not executable: $INSTALLED_BINARY"
  fi

  if ! INSTALLED_VERSION=$("$INSTALLED_BINARY" version 2>&1); then
    error "Installed binary failed verification: $INSTALLED_BINARY"
  fi
  INSTALLED_VERSION=$(printf '%s\n' "$INSTALLED_VERSION" | sed -n '1p')
  info "Verification: $INSTALLED_VERSION ($INSTALLED_BINARY)"

  ACTIVE_BINARY=$(command -v "$BINARY_NAME" 2>/dev/null || true)
  if [ -z "$ACTIVE_BINARY" ]; then
    warn "Binary installed but not in PATH. Add its directory to your shell profile:"
    warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  elif [ ! "$ACTIVE_BINARY" -ef "$INSTALLED_BINARY" ]; then
    warn "Another ${BINARY_NAME} takes precedence on PATH: $ACTIVE_BINARY"
    warn "The newly installed binary is: $INSTALLED_BINARY"
    warn "Remove the older installation or put ${INSTALL_DIR} before its directory on PATH."
  fi
}

main() {
  info "Installing $BINARY_NAME..."

  detect_os
  detect_arch
  if [ -n "$BMCP_VERSION" ]; then
    VERSION="$BMCP_VERSION"
    info "Using pinned version from BMCP_VERSION: $VERSION"
  else
    get_latest_version
  fi
  # Validated whichever way it was resolved: the redirect-derived value is
  # parsed out of an HTTP response header and deserves no more trust.
  validate_version "$VERSION"
  install
  verify

  echo ""
  info "Installation complete! Run '$BINARY_NAME init' to configure."
}

if [ "${BMCP_INSTALLER_TEST_MODE:-0}" != "1" ]; then
  main
fi
