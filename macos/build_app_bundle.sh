#!/usr/bin/env bash
# Builds Anton.app: a native macOS app bundle wrapping the Slint desktop GUI.
#
# The default anton executable already provides the desktop UI; include it once,
# with its sibling sandbox simulator, rather than shipping two copies of the GUI.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_NAME="Anton.app"
VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/version = "(.*)"/\1/')"

echo "[*] Building release binaries..."
cargo build --locked --release --bin anton --bin demo_ransomware

echo "[*] Assembling ${APP_NAME}..."
rm -rf "${APP_NAME}"
mkdir -p "${APP_NAME}/Contents/MacOS"
mkdir -p "${APP_NAME}/Contents/Resources"

cp target/release/anton "${APP_NAME}/Contents/MacOS/"
cp target/release/demo_ransomware "${APP_NAME}/Contents/MacOS/"

sed "s/__VERSION__/${VERSION}/g" macos/Info.plist.template > "${APP_NAME}/Contents/Info.plist"

if [ -d "macos/AppIcon.iconset" ]; then
    echo "[*] Building AppIcon.icns..."
    iconutil -c icns macos/AppIcon.iconset -o "${APP_NAME}/Contents/Resources/AppIcon.icns"
else
    echo "[*] No macos/AppIcon.iconset found -- skipping custom icon (macOS will use a generic one)."
fi

echo "[*] Ad-hoc code-signing (no Developer ID -- this satisfies Gatekeeper's basic"
echo "    integrity check, but first launch still requires a right-click > Open, or"
echo "    'xattr -d com.apple.quarantine Anton.app', since the app isn't notarized)."
codesign --force --deep --sign - "${APP_NAME}"

echo "[*] Done: ${APP_NAME} (version ${VERSION})"
