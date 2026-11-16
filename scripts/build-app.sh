#!/bin/bash
# Wraps the SecureNetMenu binary in a proper app bundle (SecureNet.app) so macOS gives it a stable
# identity: it is listed in System Settings > Menu Bar and its icon position is remembered.
# Usage: scripts/build-app.sh [output-dir]   (default .build/release)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT_DIR="${1:-.build/release}"
APP="$OUT_DIR/SecureNet.app"
swift build -c release --product SecureNetMenu >/dev/null
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp .build/release/SecureNetMenu "$APP/Contents/MacOS/SecureNetMenu"
cp support/SecureNet-Info.plist "$APP/Contents/Info.plist"
codesign --force --sign - --identifier com.securenet.menu "$APP" >/dev/null 2>&1
echo "$APP"
