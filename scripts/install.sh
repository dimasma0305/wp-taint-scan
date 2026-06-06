#!/usr/bin/env sh
# wp-taint-scan installer — downloads the latest prebuilt binary for your platform.
#
#   curl -fsSL https://raw.githubusercontent.com/dimasma0305/wp-taint-scan/main/scripts/install.sh | sh
#
# Override the install dir with BIN_DIR=/somewhere sh install.sh
set -eu

REPO="dimasma0305/wp-taint-scan"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os — download the Windows .zip from the releases page" >&2; exit 1 ;;
esac

asset="wp-taint-scan_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset} ..."
if ! curl -fsSL "$url" -o "$tmp/pkg.tar.gz"; then
  echo "download failed: $url" >&2
  echo "(has a release been published yet? see https://github.com/${REPO}/releases )" >&2
  exit 1
fi
tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"

install_to() { install -m 0755 "$tmp/taint-web" "$tmp/taint-scan" "$1/"; }
if [ -w "$BIN_DIR" ]; then
  install_to "$BIN_DIR"
elif command -v sudo >/dev/null 2>&1; then
  echo "Installing to $BIN_DIR (requires sudo) ..."
  sudo install -m 0755 "$tmp/taint-web" "$tmp/taint-scan" "$BIN_DIR/"
else
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
  install_to "$BIN_DIR"
fi

echo ""
echo "Installed taint-web and taint-scan to $BIN_DIR"
echo "Start the web UI:   taint-web        then open http://localhost:8080"
echo "Or scan from CLI:   taint-scan -target /path/to/plugin"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "Note: add $BIN_DIR to your PATH." ;; esac
