#!/usr/bin/env bash
# Cross-compile wp-taint-scan and package per-platform archives into dist/.
# Usage: scripts/build-release.sh [version]
set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"
rm -rf "$DIST"; mkdir -p "$DIST"

PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

for plat in $PLATFORMS; do
  os="${plat%/*}"; arch="${plat#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  echo ">> building ${os}/${arch}"
  stage="$(mktemp -d)"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" -o "$stage/taint-web${ext}" ./cmd/taint-web
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w" -o "$stage/taint-scan${ext}" ./cmd/taint-scan
  cp README.md LICENSE "$stage/" 2>/dev/null || true

  base="wp-taint-scan_${os}_${arch}"
  if [ "$os" = "windows" ]; then
    (cd "$stage" && zip -q -r "$DIST/${base}.zip" .)
  else
    tar -czf "$DIST/${base}.tar.gz" -C "$stage" .
  fi
  rm -rf "$stage"
done

( cd "$DIST" && sha256sum * > checksums.txt )
echo "=== dist/ ==="
ls -la "$DIST"
