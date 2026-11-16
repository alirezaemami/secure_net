# SecureNet

Blocks your Mac's network traffic unless your **public IP** is in a trusted range (e.g. your office IP).
On an untrusted network you're blocked until you connect your office VPN. SecureNet then sees the
office IP and unblocks automatically.

No Apple Developer account needed, and SIP stays enabled. It uses macOS's built-in `pf` firewall.

## How it works

```
                    network change / sleep / wake / every 60s
                                     │
                                     ▼
                     ┌──────── BLOCK FIRST (fail closed) ───────┐
                     │  only allowed while blocked:              │
                     │   • IP check: https://1.1.1.1 & 1.0.0.1   │
                     │   • DHCP                                  │
                     │   • your VPN server(s) (always_allowed)   │
                     │   • DNS, if allow_dns_when_untrusted      │
                     └───────────────────┬───────────────────────┘
                                         ▼
                 public IP (via HTTPS) in trusted_public_ip_ranges?
                     │ yes                                  │ no
                     ▼                                      ▼
           TRUSTED: everything allowed           UNTRUSTED: stay blocked,
           (global IPv6 still blocked to          kill open connections,
            stop leaks around the VPN)            menu bar shows a warning
```

| Part | What it does |
|---|---|
| `securenetd` | Root daemon (LaunchDaemon). Starts at boot, runs without login, survives sleep. Owns the pf anchor `com.apple/000.SecureNet`. |
| `SecureNetMenu` | Menu-bar shield icon. Pops up a warning on untrusted networks with **Keep Blocked** / **Allow Until Network Changes**. |
| `securenetctl` | CLI for status and for editing the whitelist. |

### Sleep
Before the Mac sleeps, SecureNet switches to **blocked**. The pf rules live in the kernel, so the Mac
stays blocked through dark wake / Power Nap until a fresh check passes. A Mac that wakes on a
café network at 3 a.m. can't talk to anything except the IP check and your VPN server.

### Why the public IP, and why HTTPS
The public IP is what the internet sees, so it tells you where your traffic really exits.
It's your office IP when you're in the office or on the full-tunnel office VPN, and something
else otherwise. The check uses HTTPS to an IP-literal endpoint, so a hostile network can't fake
the answer with DNS spoofing or HTTP injection. If the endpoints disagree, the network counts as
untrusted.

## Install

```bash
scripts/install.sh
```
It builds the project, asks for your trusted office IP range(s) and VPN server, shows whether your
current network would be trusted, and asks before turning protection on.

## Everyday use

```bash
securenetctl status                 # current state
securenetctl myip                   # public IP and whether it's trusted
securenetctl allow-once             # allow this network until it changes / sleep
securenetctl block                  # undo allow-once
sudo securenetctl add-range 203.0.113.0/24
sudo securenetctl add-host office.example.com          # trust a dynamic-DNS name's current IP
sudo securenetctl add-allow vpn.example.com            # VPN server, all protocols (L2TP/IPsec)
sudo securenetctl add-allow 203.0.113.10 51820 udp     # VPN server, one port (WireGuard)
sudo securenetctl config            # show config (with always_allowed indexes)
```

Config: `/Library/Application Support/SecureNet/config.json`. Log: `/Library/Logs/SecureNet.log`.

```json
{
  "trusted_public_ip_ranges": ["203.0.113.0/24"],
  "trusted_public_hosts": ["office.example.com"],
  "doh_endpoint": "https://1.1.1.1/dns-query",
  "always_allowed": [{ "host": "203.0.113.10/32", "port": 51820, "proto": "udp", "comment": "VPN" }],
  "ip_check_endpoints": ["https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"],
  "allow_dns_when_untrusted": false,
  "block_ipv6_when_trusted": true,
  "block_inbound_when_untrusted": true,
  "recheck_interval_seconds": 60,
  "allow_once_enabled": true
}
```
After editing the file by hand, run `sudo securenetctl reload`.

### Hostnames (dynamic DNS)
Hostnames in `trusted_public_hosts` and `always_allowed` are resolved over **DNS-over-HTTPS**
(`doh_endpoint`, default `https://1.1.1.1/dns-query`). They're re-resolved on every check, and the
last good answer is cached in `resolved.json` so the VPN server stays reachable right after a reboot.
Your VPN *client* still uses normal DNS to find the server, so set `allow_dns_when_untrusted: true`
when the VPN server is a hostname.

### L2TP over IPsec
Add the server with no port (`add-allow HOST`). That allows UDP 500, 4500 and 1701 plus ESP.
In macOS VPN settings, turn on **Send all traffic over VPN connection**. Otherwise your traffic
doesn't leave through the office IP and SecureNet will (correctly) keep blocking.

### Captive portals (hotel/café login pages)
These networks block everything until you log in, so SecureNet can't reach the IP check. Click
**Allow Until Network Changes**, log in, then connect your VPN. The VPN connecting counts as a
network change, which ends the allow-once; the next check sees your office IP and you're trusted.

## Emergency: I'm locked out
```bash
securenetctl allow-once                       # works unless you set allow_once_enabled=false
# or turn it off completely:
sudo launchctl bootout system/com.securenet.daemon
sudo pfctl -a com.apple/000.SecureNet -F all
```
Uninstall: `scripts/uninstall.sh` (add `--purge` to also delete config).

## Limits (read these)
- **Not per-app.** pf sees IPs and ports, not apps, so it's all-or-nothing per network. Per-app
  prompts need an Apple Network Extension, which requires a paid developer account. The core
  (whitelist, IP check, state machine) is kept separate so that layer can be added later.
- **Split-tunnel VPN.** If your VPN only routes some traffic, the IP check may exit through the VPN
  while other traffic goes out the local network. Use a full-tunnel VPN profile with SecureNet.
- **Allow-once.** Any program running as your user can call allow-once through the socket. If you
  don't need it, set `allow_once_enabled` to `false`.
- **Other pf users.** If another tool flushes pf or replaces `/etc/pf.conf`'s ruleset, SecureNet
  re-asserts its rules at the next check (within `recheck_interval_seconds`).

## Development
```bash
swift build
swift test
.build/debug/securenetctl rules   # see the exact pf rules generated
```
