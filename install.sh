#!/bin/sh
# ssl-watch installer for Linux and macOS.
# Detects OS, architecture and the latest release, then installs the binary.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | sh
#
# Environment overrides:
#   VERSION   install a specific tag (e.g. v1.2.0); default: latest release
#   BINDIR    install directory; default: /usr/local/bin
#
# sudo is used automatically only when BINDIR is not writable by the current user.
set -eu

REPO="idesyatov/ssl-watch"
BINARY="ssl-watch"
BINDIR="${BINDIR:-/usr/local/bin}"

err() { echo "error: $*" >&2; exit 1; }

# --- required tools ---
command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar  >/dev/null 2>&1 || err "tar is required"

# --- detect OS ---
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) err "unsupported OS: $os (supported: linux, darwin)" ;;
esac

# --- detect architecture ---
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) err "unsupported architecture: $arch (supported: amd64, arm64)" ;;
esac

# --- resolve version (latest by default, via the GitHub "latest" redirect) ---
version="${VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/$REPO/releases/latest" | sed 's#.*/##')
  [ -n "$version" ] || err "could not determine the latest version"
fi
ver_no_v="${version#v}"

asset="${BINARY}_${ver_no_v}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$version/$asset"

echo "Installing $BINARY $version ($os/$arch) -> $BINDIR"

# --- download and extract into a temp dir ---
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$asset" || err "download failed: $url"
tar -xzf "$tmp/$asset" -C "$tmp" "$BINARY" || err "failed to extract $BINARY from archive"

# --- decide whether sudo is needed ---
sudo_cmd=""
if [ -d "$BINDIR" ]; then
  [ -w "$BINDIR" ] || sudo_cmd="sudo"
else
  [ -w "$(dirname "$BINDIR")" ] || sudo_cmd="sudo"
fi
if [ -n "$sudo_cmd" ]; then
  command -v sudo >/dev/null 2>&1 || err "$BINDIR is not writable and sudo is not available"
  echo "Elevating with sudo to write to $BINDIR"
fi

# --- install ---
$sudo_cmd install -d -m 0755 "$BINDIR"
$sudo_cmd install -m 0755 "$tmp/$BINARY" "$BINDIR/$BINARY"

echo "Installed: $BINDIR/$BINARY"
"$BINDIR/$BINARY" -version 2>/dev/null || true
