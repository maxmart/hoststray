#!/bin/bash
# Publishes dist/ as a GitHub release (needs the gh CLI, logged in).
#   VERSION=0.11.0 ./scripts/release.sh
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:?set VERSION}"
[ -f dist/SHA256SUMS ] || { echo "run scripts/build-release.sh first"; exit 1; }
gh release create "v$VERSION" --repo maxmart/hoststray --title "Hosts Tray $VERSION" --generate-notes \
	dist/SHA256SUMS dist/Hosts-Tray-"$VERSION"* dist/hoststray-"$VERSION"-*
