#!/bin/bash
# Builds Hosts Tray.app (universal), and when signing credentials are set,
# signs, notarizes and staples it and builds a signed .pkg installer.
#
#   VERSION=0.11.0 ./scripts/build-mac.sh
#
# Credentials come from the environment or .env (see .env.example):
#   APPLE_ID, APPLE_PASSWORD, APPLE_TEAM_ID   notarization
#   APPLE_SIGN_IDENTITY        default: the keychain's "Developer ID Application" for APPLE_TEAM_ID
#   APPLE_INSTALLER_IDENTITY   optional; builds the .pkg
#   NOTARIZE=0                 sign only (quick local test builds)
#   OUT=dir                    output folder (default dist)
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] && { set -a; source .env; set +a; }
VERSION="${VERSION:-0.11.0}"
OUT="${OUT:-dist}"
APP="$OUT/Hosts Tray.app"
rm -rf "$APP" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "==> Building universal binary ($VERSION)"
for arch in arm64 amd64; do
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch MACOSX_DEPLOYMENT_TARGET=12.0 \
		go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/hoststray-$arch" .
done
lipo -create -output "$APP/Contents/MacOS/hoststray" "$OUT/hoststray-arm64" "$OUT/hoststray-amd64"
rm "$OUT/hoststray-arm64" "$OUT/hoststray-amd64"
cp scripts/icon.icns "$APP/Contents/Resources/icon.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>Hosts Tray</string>
	<key>CFBundleDisplayName</key><string>Hosts Tray</string>
	<key>CFBundleIdentifier</key><string>maxmart.hoststray</string>
	<key>CFBundleExecutable</key><string>hoststray</string>
	<key>CFBundleIconFile</key><string>icon</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$VERSION</string>
	<key>CFBundleVersion</key><string>$VERSION</string>
	<key>LSMinimumSystemVersion</key><string>12.0</string>
	<key>LSUIElement</key><true/>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
plutil -lint "$APP/Contents/Info.plist" >/dev/null

ZIP="$OUT/Hosts-Tray-$VERSION-mac.zip"
if [ -z "${APPLE_TEAM_ID:-}" ]; then
	echo "==> APPLE_TEAM_ID not set: ad-hoc signing only (fine for local use)"
	codesign --force --sign - "$APP"
	ditto -c -k --keepParent "$APP" "$ZIP"
	echo "Built $APP and $ZIP"
	exit 0
fi

SIGN_ID="${APPLE_SIGN_IDENTITY:-$(security find-identity -v -p codesigning | grep "Developer ID Application" | grep "($APPLE_TEAM_ID)" | head -1 | sed 's/.*"\(.*\)"/\1/')}"
echo "==> Signing with $SIGN_ID"
codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$APP"
codesign --verify --strict --verbose=1 "$APP"

notarize() {
	xcrun notarytool submit "$1" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" --wait --timeout 30m
}

if [ "${NOTARIZE:-1}" = 0 ]; then
	ditto -c -k --keepParent "$APP" "$ZIP"
	echo "Built signed (not notarized) $APP and $ZIP"
	exit 0
fi

echo "==> Notarizing app"
ditto -c -k --keepParent "$APP" "$OUT/notarize.zip"
notarize "$OUT/notarize.zip"
rm "$OUT/notarize.zip"
xcrun stapler staple "$APP"
ditto -c -k --keepParent "$APP" "$ZIP"

if [ -n "${APPLE_INSTALLER_IDENTITY:-}" ]; then
	echo "==> Building installer"
	PKG="$OUT/Hosts-Tray-$VERSION.pkg"
	ROOT="$OUT/pkgroot"
	mkdir -p "$ROOT" && ditto "$APP" "$ROOT/Hosts Tray.app"
	# Not relocatable: otherwise Installer "updates" another copy of the app it
	# finds on disk instead of installing to /Applications.
	pkgbuild --analyze --root "$ROOT" "$OUT/component.plist" >/dev/null
	/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$OUT/component.plist"
	pkgbuild --root "$ROOT" --component-plist "$OUT/component.plist" --install-location /Applications \
		--identifier maxmart.hoststray.pkg --version "$VERSION" "$OUT/component.pkg"
	productbuild --package "$OUT/component.pkg" --sign "$APPLE_INSTALLER_IDENTITY" "$PKG"
	rm -rf "$ROOT" "$OUT/component.plist" "$OUT/component.pkg"
	echo "==> Notarizing installer"
	notarize "$PKG"
	xcrun stapler staple "$PKG"
fi

echo "==> Done"
ls -lh "$OUT"
