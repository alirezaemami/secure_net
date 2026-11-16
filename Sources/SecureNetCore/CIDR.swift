import Foundation

/// An IPv4 or IPv6 address, parsed strictly with inet_pton.
public struct IPAddress: Hashable, CustomStringConvertible {
    public enum Family { case v4, v6 }

    public let bytes: [UInt8]
    public var family: Family { bytes.count == 4 ? .v4 : .v6 }

    public init?(_ string: String) {
        var s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("[") && s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return
        }
        return nil
    }

    init(bytes: [UInt8]) { self.bytes = bytes }

    public var description: String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if family == .v4 {
            var a = in_addr()
            withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: bytes) }
            inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count))
        } else {
            var a = in6_addr()
            withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: bytes) }
            inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count))
        }
        return String(cString: buf)
    }
}

/// An address range such as 203.0.113.0/24. A bare address means a single host (/32 or /128).
public struct CIDR: Hashable, CustomStringConvertible, Codable {
    /// Network address (host bits cleared).
    public let address: IPAddress
    public let prefix: Int

    public init?(_ string: String) {
        let parts = string.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2, let ip = IPAddress(String(parts[0])) else { return nil }
        let maxPrefix = ip.bytes.count * 8
        var p = maxPrefix
        if parts.count == 2 {
            guard let v = Int(parts[1]), String(v) == parts[1], (0...maxPrefix).contains(v) else { return nil }
            p = v
        }
        address = IPAddress(bytes: CIDR.mask(ip.bytes, prefix: p))
        prefix = p
    }

    static func mask(_ bytes: [UInt8], prefix: Int) -> [UInt8] {
        bytes.enumerated().map { i, byte in
            let before = i * 8
            if prefix >= before + 8 { return byte }
            if prefix <= before { return 0 }
            return byte & UInt8(truncatingIfNeeded: 0xFF << (8 - (prefix - before)))
        }
    }

    public func contains(_ ip: IPAddress) -> Bool {
        ip.bytes.count == address.bytes.count && CIDR.mask(ip.bytes, prefix: prefix) == address.bytes
    }

    public var description: String { "\(address)/\(prefix)" }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let s = try c.decode(String.self)
        guard let v = CIDR(s) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Invalid IP/CIDR: \(s)")
        }
        self = v
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(description)
    }
}
