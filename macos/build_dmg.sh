#!/usr/bin/env bash
# Packages Anton.app into a distributable .dmg. Builds the app bundle first if it
# doesn't already exist. Uses hdiutil (always present on macOS) rather than
# create-dmg, which isn't installed by default.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_NAME="Anton.app"
VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/version = "(.*)"/\1/')"
DMG_NAME="Anton-${VERSION}.dmg"
VOLUME_NAME="Anton Anti-Ransomware"

if [ ! -d "${APP_NAME}" ]; then
    echo "[*] ${APP_NAME} not found, building it first..."
    bash macos/build_app_bundle.sh
fi

echo "[*] Staging DMG contents..."
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGING_DIR}"' EXIT

cp -R "${APP_NAME}" "${STAGING_DIR}/"
ln -s /Applications "${STAGING_DIR}/Applications"

echo "[*] Building ${DMG_NAME}..."
rm -f "${DMG_NAME}"
hdiutil create -volname "${VOLUME_NAME}" -srcfolder "${STAGING_DIR}" -ov -format UDZO "${DMG_NAME}"

echo "[*] Done: ${DMG_NAME}"
