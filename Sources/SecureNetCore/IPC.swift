import Foundation

public struct ControlRequest: Codable {
    public var cmd: String
    public init(_ cmd: String) { self.cmd = cmd }
}

public enum TrustState: String, Codable {
    case checking, trusted, untrusted
    case allowedOnce = "allowed_once"

    /// Whether traffic is currently allowed out.
    public var isOpen: Bool { self == .trusted || self == .allowedOnce }
}

public struct DaemonStatus: Codable, Equatable {
    public var state: TrustState
    public var publicIP: String?
    public var reason: String
    public var since: Date
    public var lastCheck: Date?
    public var generation: Int
    public var allowOnceEnabled: Bool
    public var trustedRanges: [String]
    public var version: String

    public init(state: TrustState, publicIP: String?, reason: String, since: Date, lastCheck: Date?,
                generation: Int, allowOnceEnabled: Bool, trustedRanges: [String], version: String) {
        self.state = state; self.publicIP = publicIP; self.reason = reason; self.since = since
        self.lastCheck = lastCheck; self.generation = generation; self.allowOnceEnabled = allowOnceEnabled
        self.trustedRanges = trustedRanges; self.version = version
    }
}

public struct ControlResponse: Codable {
    public var ok: Bool
    public var error: String?
    public var status: DaemonStatus?

    public static func success(_ s: DaemonStatus) -> ControlResponse { .init(ok: true, error: nil, status: s) }
    public static func failure(_ m: String, _ s: DaemonStatus? = nil) -> ControlResponse { .init(ok: false, error: m, status: s) }
}

public enum IPCError: Error, CustomStringConvertible {
    case system(String, Int32)
    case notRunning
    case badResponse

    public var description: String {
        switch self {
        case .system(let op, let e): return "\(op): \(String(cString: strerror(e)))"
        case .notRunning: return "securenetd is not running (cannot connect to \(Paths.socket))"
        case .badResponse: return "bad response from securenetd"
        }
    }
}

/// Small helpers around a Unix-domain stream socket speaking newline-delimited JSON.
public enum UnixSocket {
    public static func address(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw IPCError.system("socket path too long", ENAMETOOLONG) }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        return addr
    }

    public static func configure(_ fd: Int32, timeout: Int) {
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    public static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            var off = 0
            while off < raw.count {
                let n = write(fd, raw.baseAddress! + off, raw.count - off)
                if n < 0 { if errno == EINTR { continue }; throw IPCError.system("write", errno) }
                off += n
            }
        }
    }

    /// Reads until a newline or EOF. Returns the bytes without the newline.
    public static func readLine(_ fd: Int32, max: Int) throws -> Data {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while out.count < max {
            let n = read(fd, &buf, buf.count)
            if n < 0 { if errno == EINTR { continue }; throw IPCError.system("read", errno) }
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
            if let i = out.firstIndex(of: 0x0A) { return out.prefix(upTo: i) }
        }
        return out
    }
}

public enum SecureNetClient {
    public static func send(_ request: ControlRequest, socketPath: String = Paths.socket, timeout: Int = 15) throws -> ControlResponse {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw IPCError.system("socket", errno) }
        defer { close(fd) }
        UnixSocket.configure(fd, timeout: timeout)
        var addr = try UnixSocket.address(socketPath)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { throw IPCError.notRunning }
        var data = try JSONEncoder().encode(request)
        data.append(0x0A)
        try UnixSocket.writeAll(fd, data)
        let line = try UnixSocket.readLine(fd, max: 1 << 20)
        guard let resp = try? JSONDecoder().decode(ControlResponse.self, from: line) else { throw IPCError.badResponse }
        return resp
    }
}
