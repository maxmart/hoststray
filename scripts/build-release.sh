#!/bin/bash
# Builds every release asset into dist/ plus the SHA256SUMS the updater needs:
#   Hosts-Tray-<v>-mac.zip, Hosts-Tray-<v>.pkg   (macOS; run on a Mac)
#   hoststray-<v>-windows-{amd64,arm64}.exe
#
#   VERSION=0.11.0 ./scripts/build-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:?set VERSION, e.g. VERSION=0.11.0}"
export VERSION
mkdir -p dist
rm -f dist/hoststray-* dist/SHA256SUMS

if [ "$(uname)" = Darwin ]; then
	./scripts/build-mac.sh
fi

echo "==> Windows"
# Icon and manifest (DPI awareness, modern controls) as a Windows resource.
go run github.com/tc-hib/go-winres@v0.3.3 simply --icon scripts/icon.png --manifest gui \
	--product-name "Hosts Tray" --file-description "Hosts Tray" --product-version "$VERSION" --file-version "$VERSION" \
	--original-filename hoststray.exe --arch amd64,arm64
for arch in amd64 arm64; do
	CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -ldflags "-H windowsgui -s -w -X main.version=$VERSION" \
		-o "dist/hoststray-$VERSION-windows-$arch.exe" .
done
rm -f rsrc_windows_*.syso

cd dist
shasum -a 256 Hosts-Tray-* hoststray-* 2>/dev/null > SHA256SUMS
cat SHA256SUMS
ls -lh
