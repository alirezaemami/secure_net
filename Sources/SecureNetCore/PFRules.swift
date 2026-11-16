import Foundation

/// Generates pf rules for the SecureNet anchor. Every value placed in a rule comes from a
/// parsed IPAddress/CIDR/Int/enum, never from raw user strings, so the config can't inject pf syntax.
public enum PFRules {
    /// Loaded under Apple's `anchor "com.apple/*"` hook in /etc/pf.conf.
    /// "000." sorts first among com.apple sub-anchors, so our `quick` rules are evaluated before Apple's.
    public static let anchor = "com.apple/000.SecureNet"

    static func family(_ ip: IPAddress) -> String { ip.family == .v4 ? "inet" : "inet6" }

    /// Untrusted network: block everything except the IP check, DHCP, VPN servers and other allow rules.
    public static func untrusted(_ config: Config, resolved: ResolvedHosts = [:]) -> String {
        var r = [
            "# SecureNet: UNTRUSTED network - outbound traffic blocked",
            "pass quick on lo0 all no state",
            "# DHCP, so the Mac can still get an address",
            "pass out quick inet proto udp from any port 68 to any port 67 keep state",
            "pass in quick inet proto udp from any port 67 to any port 68 no state",
            "# public-IP check endpoints",
        ]
        for ep in (try? config.endpoints()) ?? [] {
            r.append("pass out quick \(family(ep.ip)) proto tcp from any to \(ep.ip) port \(ep.port) flags any keep state")
        }
        if let doh = try? config.dohEndpointParsed() {
            r.append("# DNS-over-HTTPS endpoint (resolves hostnames)")
            r.append("pass out quick \(family(doh.ip)) proto tcp from any to \(doh.ip) port \(doh.port) flags any keep state")
        }
        if config.allowDNSWhenUntrusted {
            r.append("# DNS (allow_dns_when_untrusted)")
            r.append("pass out quick proto udp from any to any port 53 keep state")
            r.append("pass out quick proto tcp from any to any port 53 flags any keep state")
        }
        if !config.alwaysAllowed.isEmpty { r.append("# always_allowed") }
        for rule in config.alwaysAllowed { r += rules(for: rule, resolved: resolved) }
        r.append("block drop out quick all")
        if config.blockInboundWhenUntrusted { r.append("block drop in quick all") }
        return r.joined(separator: "\n") + "\n"
    }

    /// Trusted network: allow everything (optionally still block global IPv6 to stop leaks).
    public static func trusted(_ config: Config) -> String {
        var r = [
            "# SecureNet: TRUSTED network - traffic allowed",
            "pass quick on lo0 all no state",
        ]
        if config.blockIPv6WhenTrusted {
            r += [
                "# block_ipv6_when_trusted: only link-local / multicast IPv6",
                "pass out quick inet6 from any to fe80::/10 no state",
                "pass out quick inet6 from any to ff00::/8 no state",
                "block drop out quick inet6 all",
            ]
        }
        return r.joined(separator: "\n") + "\n"
    }

    /// Last-resort ruleset if the normal one fails to load.
    public static let minimalBlock = "pass quick on lo0 all no state\nblock drop out quick all\n"

    static func rules(for rule: AllowRule, resolved: ResolvedHosts) -> [String] {
        switch rule.host {
        case .cidr(let c):
            return rules(to: c, rule)
        case .name(let n):
            let ips = resolved[n] ?? []
            if ips.isEmpty { return ["# \(n): not resolved yet"] }
            return ["# \(n)"] + ips.flatMap { rules(to: CIDR($0.description)!, rule) }
        }
    }

    static func rules(to host: CIDR, _ rule: AllowRule) -> [String] {
        let fam = family(host.address)
        let to = "from any to \(host)" + (rule.port.map { " port \($0)" } ?? "")
        let tcp = "pass out quick \(fam) proto tcp \(to) flags any keep state"
        let udp = "pass out quick \(fam) proto udp \(to) keep state"
        switch rule.proto {
        case .tcp: return [tcp]
        case .udp: return [udp]
        case .any:
            // `flags any` lets TCP connections survive a state flush (e.g. TCP-based VPNs).
            // The protocol-less rule also covers UDP, ICMP, ESP and GRE (IPsec / L2TP / PPTP).
            if rule.port != nil { return [tcp, udp] }
            return [tcp, "pass out quick \(fam) \(to) keep state"]
        }
    }
}
