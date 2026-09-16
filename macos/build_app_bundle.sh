#!/usr/bin/env bash
# Builds Anton.app: a native macOS app bundle wrapping the Slint desktop GUI.
#
# All three binaries are co-located in Contents/MacOS/ because both
# main.rs::run_demo() (looks for a sibling demo_ransomware next to the running exe) and
# desktop.rs's on_run_demo callback (relaunches the sibling anton binary with `demo`)
# resolve their sibling binaries by relative path from std::env::current_exe().
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_NAME="Anton.app"
VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/version = "(.*)"/\1/')"

echo "[*] Building release binaries..."
cargo build --release --bin anton_desktop --bin anton --bin demo_ransomware

echo "[*] Assembling ${APP_NAME}..."
rm -rf "${APP_NAME}"
mkdir -p "${APP_NAME}/Contents/MacOS"
mkdir -p "${APP_NAME}/Contents/Resources"

cp target/release/anton_desktop "${APP_NAME}/Contents/MacOS/"
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
