#!/usr/bin/env bash
# macOS equivalent of build_and_install.bat: builds the release binaries, packages
# Anton.app, and adds a Desktop alias.
#
# There is no macOS equivalent of deploy_shortcut.ps1's "run as administrator" .lnk
# byte-patch -- Windows shortcut elevation isn't a concept that exists on macOS, and
# nothing in Anton needs elevated privileges to run (the file-watching/detection
# features operate fine as the current user on both platforms). This is an
# intentional non-port, not a gap.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "=== Anton - Build and Install (macOS) ==="
echo
echo "[1/2] Building Anton.app..."
bash macos/build_app_bundle.sh

echo
echo "[2/2] Adding a Desktop alias..."
DESKTOP_ALIAS="$HOME/Desktop/Anton.app"
rm -f "$DESKTOP_ALIAS"
osascript -e "tell application \"Finder\" to make alias file to (POSIX file \"${PROJECT_ROOT}/Anton.app\") at (path to desktop)" \
    -e "set name of result to \"Anton.app\"" > /dev/null

echo
echo "=== Done ==="
echo "You should see \"Anton\" on your Desktop. Double-click it to run Anton."
echo "(First launch: right-click > Open, since the app is ad-hoc signed, not notarized.)"
