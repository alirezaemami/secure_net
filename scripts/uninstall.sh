#!/bin/bash
# Stop SecureNet, remove its firewall rules, and uninstall it.
#   scripts/uninstall.sh          keep config
#   scripts/uninstall.sh --purge  also delete config and log
set -uo pipefail

SUPPORT="/Library/Application Support/SecureNet"

echo "==> Stopping"
launchctl bootout "gui/$(id -u)/com.securenet.menu" 2>/dev/null
sudo launchctl bootout system/com.securenet.daemon 2>/dev/null

echo "==> Removing firewall rules"
sudo pfctl -a com.apple/000.SecureNet -F all 2>&1 | grep -v ALTQ
if [[ -f "$SUPPORT/pf.token" ]]; then
  sudo pfctl -X "$(cat "$SUPPORT/pf.token")" 2>&1 | grep -v ALTQ
fi

echo "==> Removing files"
sudo rm -f /Library/LaunchDaemons/com.securenet.daemon.plist /Library/LaunchAgents/com.securenet.menu.plist
sudo rm -f /usr/local/bin/securenetctl /var/run/securenet.sock
sudo rm -rf /Applications/SecureNet.app
sudo rm -rf "$SUPPORT/bin" "$SUPPORT"/rules-*.conf "$SUPPORT/pf.token"

if [[ "${1:-}" == "--purge" ]]; then
  sudo rm -rf "$SUPPORT" /Library/Logs/SecureNet.log
  echo "Config and log deleted."
else
  echo "Config kept at $SUPPORT/config.json (use --purge to delete)."
fi
echo "SecureNet uninstalled. Network is unrestricted."
