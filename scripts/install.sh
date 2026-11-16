#!/bin/bash
# Build and install SecureNet. Run as your normal user; it asks for sudo when needed.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SUPPORT="/Library/Application Support/SecureNet"
BIN="$SUPPORT/bin"
DAEMON_PLIST=/Library/LaunchDaemons/com.securenet.daemon.plist
AGENT_PLIST=/Library/LaunchAgents/com.securenet.menu.plist
APP=/Applications/SecureNet.app

if [[ $EUID -eq 0 ]]; then
  echo "Run this as your normal user (not with sudo). It will ask for your password when needed."
  exit 1
fi

echo "==> Building (release)"
swift build -c release
OUT="$ROOT/.build/release"

echo "==> Installing binaries to $BIN"
sudo mkdir -p "$BIN"
sudo install -m 755 -o root -g wheel "$OUT/securenetd" "$OUT/securenetctl" "$BIN/"
sudo rm -f "$BIN/SecureNetMenu" # older versions installed the menu app here

echo "==> Installing menu bar app to $APP"
scripts/build-app.sh "$OUT" >/dev/null
sudo rm -rf "$APP"
sudo cp -R "$OUT/SecureNet.app" "$APP"
sudo chown -R root:wheel "$APP"
sudo mkdir -p /usr/local/bin
sudo ln -sf "$BIN/securenetctl" /usr/local/bin/securenetctl

if [[ ! -f "$SUPPORT/config.json" ]]; then
  echo
  echo "==> First-time setup"
  CURRENT_IP="$(curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=//p' || true)"
  echo "Your current public IP is: ${CURRENT_IP:-unknown}"
  echo
  echo "Enter your TRUSTED public IP ranges (your office IP), separated by spaces."
  echo "Examples: 203.0.113.10   or   203.0.113.0/24"
  read -r -p "Trusted ranges: " -a RANGES
  sudo "$BIN/securenetctl" init ${RANGES[@]+"${RANGES[@]}"}

  echo
  echo "Your VPN must be able to connect while the network is blocked."
  echo "Enter your VPN server as:  HOST [PORT PROTO]   HOST may be an IP or a hostname."
  echo "  L2TP/IPsec, IKEv2, PPTP: just the host (all protocols), e.g.  vpn.example.com"
  echo "  WireGuard/OpenVPN:       host port proto,          e.g.  203.0.113.10 51820 udp"
  echo "Empty line to finish."
  while true; do
    read -r -p "VPN server: " -a V || break
    [[ ${#V[@]} -eq 0 ]] && break
    sudo "$BIN/securenetctl" add-allow "${V[@]}" "VPN server" || echo "  (invalid, try again)"
  done
  echo
  echo "If your office IP is dynamic (e.g. MikroTik *.sn.mynetname.net), enter the hostname that"
  echo "always points to it. Its current IP will count as trusted. Empty line to skip."
  read -r -p "Trusted office hostname: " OFFICE_HOST || true
  if [[ -n "${OFFICE_HOST:-}" ]]; then sudo "$BIN/securenetctl" add-host "$OFFICE_HOST" || true; fi
  echo
  echo "Your VPN client also looks up its server's hostname via normal DNS, so it needs DNS while blocked."
  read -r -p "Allow DNS while on untrusted networks? [y/N] " DNS
  if [[ "$DNS" =~ ^[Yy] ]]; then sudo "$BIN/securenetctl" set allow_dns_when_untrusted true; fi
fi

echo
"$BIN/securenetctl" myip || true
echo
echo "If the result above says NOT trusted, the internet will be BLOCKED as soon as SecureNet starts"
echo "(until you connect your VPN, or click 'Allow Until Network Changes' in the menu bar)."
read -r -p "Start SecureNet now? [y/N] " GO
if [[ ! "$GO" =~ ^[Yy] ]]; then
  echo "Installed but not started. Re-run this script when ready."
  exit 0
fi

echo "==> Starting daemon"
sudo install -m 644 -o root -g wheel support/com.securenet.daemon.plist "$DAEMON_PLIST"
sudo launchctl bootout system/com.securenet.daemon 2>/dev/null || true
sudo launchctl bootstrap system "$DAEMON_PLIST"

echo "==> Starting menu bar app"
sudo install -m 644 -o root -g wheel support/com.securenet.menu.plist "$AGENT_PLIST"
launchctl bootout "gui/$(id -u)/com.securenet.menu" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$AGENT_PLIST"

sleep 4
echo
securenetctl status || true
echo
echo "Done. Log: /Library/Logs/SecureNet.log    Help: securenetctl help"
