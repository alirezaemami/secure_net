import Foundation

public let secureNetVersion = "0.1.0"

public enum Paths {
    public static let supportDir = "/Library/Application Support/SecureNet"
    public static let config = supportDir + "/config.json"
    public static let pfToken = supportDir + "/pf.token"
    public static let resolvedCache = supportDir + "/resolved.json"
    public static let socket = "/var/run/securenet.sock"
    public static let log = "/Library/Logs/SecureNet.log"
}

/// Hostname -> resolved addresses (resolved over DNS-over-HTTPS).
public typealias ResolvedHosts = [String: [IPAddress]]

/// An IP/CIDR or a DNS hostname (e.g. a dynamic-DNS name for your VPN router).
public enum HostSpec: Hashable, Codable, CustomStringConvertible {
    case cidr(CIDR)
    case name(String)

    public init?(_ string: String) {
        if let c = CIDR(string) { self = .cidr(c); return }
        guard let n = HostSpec.normalizedHostname(string) else { return nil }
        self = .name(n)
    }

    /// Strict hostname check: letters, digits, hyphens; dotted labels of 1-63 chars.
    /// (Hostnames end up in pf rule comments, so nothing else is allowed.)
    public static func normalizedHostname(_ string: String) -> String? {
        var s = string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasSuffix(".") { s.removeLast() }
        guard !s.isEmpty, s.count <= 253 else { return nil }
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for l in labels {
            guard (1...63).contains(l.count), l.first != "-", l.last != "-",
                  l.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }) else { return nil }
        }
        if labels.last!.allSatisfy({ ("0"..."9").contains($0) }) { return nil } // looks like a broken IP
        return s
    }

    public var description: String {
        switch self { case .cidr(let c): return c.description; case .name(let n): return n }
    }

    public var hostname: String? { if case .name(let n) = self { return n }; return nil }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let s = try c.decode(String.self)
        guard let v = HostSpec(s) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Invalid IP/CIDR/hostname: \(s)")
        }
        self = v
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }
}

/// A destination that is reachable even on an untrusted network (e.g. your VPN server).
public struct AllowRule: Codable, Equatable {
    public enum Proto: String, Codable, CaseIterable { case tcp, udp, any }

    public var host: HostSpec
    public var port: Int?
    public var proto: Proto
    public var comment: String?

    public init(host: HostSpec, port: Int? = nil, proto: Proto = .any, comment: String? = nil) {
        self.host = host; self.port = port; self.proto = proto; self.comment = comment
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(HostSpec.self, forKey: .host)
        port = try c.decodeIfPresent(Int.self, forKey: .port)
        proto = try c.decodeIfPresent(Proto.self, forKey: .proto) ?? .any
        comment = try c.decodeIfPresent(String.self, forKey: .comment)
    }

    public var summary: String {
        "\(proto.rawValue) \(host)" + (port.map { ":\($0)" } ?? "") + (comment.map { "  (\($0))" } ?? "")
    }
}

public enum ConfigError: Error, CustomStringConvertible {
    case invalid([String])
    public var description: String {
        switch self { case .invalid(let m): return "invalid config:\n  - " + m.joined(separator: "\n  - ") }
    }
}

public struct Config: Codable, Equatable {
    public static let defaultEndpoints = [
        "https://1.1.1.1/cdn-cgi/trace",
        "https://1.0.0.1/cdn-cgi/trace",
    ]

    public static let defaultDoHEndpoint = "https://1.1.1.1/dns-query"

    /// Public (egress) IP ranges that count as "safe" — e.g. your office IP.
    public var trustedPublicIPRanges: [CIDR] = []
    /// Hostnames whose current IP counts as "safe" — e.g. your office router's dynamic-DNS name.
    public var trustedPublicHosts: [String] = []
    /// DNS-over-HTTPS endpoint used to resolve hostnames (IP-literal https, so it works while blocked
    /// and can't be spoofed by the local network).
    public var dohEndpoint: String = Config.defaultDoHEndpoint
    /// HTTPS endpoints used to learn the public IP. Host must be an IP literal
    /// (so no DNS is needed while blocked) and HTTPS (so a hostile network can't fake the answer).
    public var ipCheckEndpoints: [String] = Config.defaultEndpoints
    /// Destinations allowed even while blocked (VPN servers, etc).
    public var alwaysAllowed: [AllowRule] = []
    /// Allow DNS (port 53) while blocked — needed if your VPN client resolves a hostname to connect.
    public var allowDNSWhenUntrusted = false
    /// Block IPv6 (except link-local) even when trusted: prevents IPv6 leaking around an IPv4-only VPN.
    public var blockIPv6WhenTrusted = true
    /// Block new incoming connections while on an untrusted network.
    public var blockInboundWhenUntrusted = true
    public var recheckIntervalSeconds = 60
    /// Whether the "Allow until network changes" button works.
    public var allowOnceEnabled = true

    enum CodingKeys: String, CodingKey {
        case trustedPublicIPRanges = "trusted_public_ip_ranges"
        case trustedPublicHosts = "trusted_public_hosts"
        case dohEndpoint = "doh_endpoint"
        case ipCheckEndpoints = "ip_check_endpoints"
        case alwaysAllowed = "always_allowed"
        case allowDNSWhenUntrusted = "allow_dns_when_untrusted"
        case blockIPv6WhenTrusted = "block_ipv6_when_trusted"
        case blockInboundWhenUntrusted = "block_inbound_when_untrusted"
        case recheckIntervalSeconds = "recheck_interval_seconds"
        case allowOnceEnabled = "allow_once_enabled"
    }

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Config()
        trustedPublicIPRanges = try c.decodeIfPresent([CIDR].self, forKey: .trustedPublicIPRanges) ?? d.trustedPublicIPRanges
        trustedPublicHosts = try c.decodeIfPresent([String].self, forKey: .trustedPublicHosts) ?? d.trustedPublicHosts
        dohEndpoint = try c.decodeIfPresent(String.self, forKey: .dohEndpoint) ?? d.dohEndpoint
        ipCheckEndpoints = try c.decodeIfPresent([String].self, forKey: .ipCheckEndpoints) ?? d.ipCheckEndpoints
        alwaysAllowed = try c.decodeIfPresent([AllowRule].self, forKey: .alwaysAllowed) ?? d.alwaysAllowed
        allowDNSWhenUntrusted = try c.decodeIfPresent(Bool.self, forKey: .allowDNSWhenUntrusted) ?? d.allowDNSWhenUntrusted
        blockIPv6WhenTrusted = try c.decodeIfPresent(Bool.self, forKey: .blockIPv6WhenTrusted) ?? d.blockIPv6WhenTrusted
        blockInboundWhenUntrusted = try c.decodeIfPresent(Bool.self, forKey: .blockInboundWhenUntrusted) ?? d.blockInboundWhenUntrusted
        recheckIntervalSeconds = try c.decodeIfPresent(Int.self, forKey: .recheckIntervalSeconds) ?? d.recheckIntervalSeconds
        allowOnceEnabled = try c.decodeIfPresent(Bool.self, forKey: .allowOnceEnabled) ?? d.allowOnceEnabled
    }

    public struct Endpoint: Equatable {
        public let url: URL
        public let ip: IPAddress
        public let port: Int
    }

    static func parseEndpoint(_ s: String, field: String) throws -> Endpoint {
        guard let url = URL(string: s), url.scheme?.lowercased() == "https", let host = url.host else {
            throw ConfigError.invalid(["\(field): '\(s)' must be an https:// URL"])
        }
        guard let ip = IPAddress(host) else {
            throw ConfigError.invalid(["\(field): '\(s)' must use an IP address as host (no DNS while blocked)"])
        }
        let port = url.port ?? 443
        guard (1...65535).contains(port) else { throw ConfigError.invalid(["\(field): bad port in '\(s)'"]) }
        return Endpoint(url: url, ip: ip, port: port)
    }

    public func endpoints() throws -> [Endpoint] {
        var errors: [String] = []
        var out: [Endpoint] = []
        for s in ipCheckEndpoints {
            do { out.append(try Config.parseEndpoint(s, field: "ip_check_endpoints")) }
            catch ConfigError.invalid(let e) { errors += e }
        }
        if !errors.isEmpty { throw ConfigError.invalid(errors) }
        return out
    }

    public func dohEndpointParsed() throws -> Endpoint {
        try Config.parseEndpoint(dohEndpoint, field: "doh_endpoint")
    }

    /// Every hostname that needs resolving (trusted hosts + always_allowed hostnames).
    public var hostnames: [String] {
        var seen = Set<String>()
        return (trustedPublicHosts + alwaysAllowed.compactMap(\.host.hostname)).filter { seen.insert($0).inserted }
    }

    public func validate() throws {
        var errors: [String] = []
        if ipCheckEndpoints.isEmpty { errors.append("ip_check_endpoints must not be empty") }
        do { _ = try endpoints() } catch ConfigError.invalid(let e) { errors += e }
        do { _ = try dohEndpointParsed() } catch ConfigError.invalid(let e) { errors += e }
        for h in trustedPublicHosts where HostSpec.normalizedHostname(h) != h {
            errors.append("trusted_public_hosts: '\(h)' is not a valid lowercase hostname")
        }
        for (i, r) in alwaysAllowed.enumerated() {
            if let p = r.port, !(1...65535).contains(p) { errors.append("always_allowed[\(i)]: port \(p) out of range") }
        }
        if recheckIntervalSeconds < 10 { errors.append("recheck_interval_seconds must be >= 10") }
        if !errors.isEmpty { throw ConfigError.invalid(errors) }
    }

    public static func load(from path: String) throws -> Config {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(Config.self, from: data)
    }

    public func encoded() throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var d = try e.encode(self)
        d.append(0x0A)
        return d
    }

    public func save(to path: String) throws {
        try encoded().write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o644)
    }

    public var hasTrustRules: Bool { !trustedPublicIPRanges.isEmpty || !trustedPublicHosts.isEmpty }

    /// Returns why `ip` is trusted (the matching range or hostname), or nil if it is not.
    public func trustMatch(_ ip: IPAddress, resolved: ResolvedHosts = [:]) -> String? {
        if let r = trustedPublicIPRanges.first(where: { $0.contains(ip) }) { return "trusted range \(r)" }
        if let h = trustedPublicHosts.first(where: { resolved[$0]?.contains(ip) == true }) { return "trusted host \(h)" }
        return nil
    }
}
