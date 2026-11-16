import Foundation

public enum TraceParser {
    /// Parses Cloudflare's /cdn-cgi/trace body (`ip=1.2.3.4` line) or a plain-text IP body.
    public static func ip(from body: String) -> IPAddress? {
        for line in body.split(whereSeparator: \.isNewline) where line.hasPrefix("ip=") {
            return IPAddress(String(line.dropFirst(3)))
        }
        return IPAddress(body)
    }
}

public struct CheckResult {
    public let url: URL
    public let ip: IPAddress?
    public let error: String?
}

public struct TrustDecision: Equatable {
    public let trusted: Bool
    public let ip: IPAddress?
    public let reason: String

    /// Trusted only if at least one check succeeded and EVERY successful check reports a trusted IP.
    public static func evaluate(_ results: [CheckResult], config: Config, resolved: ResolvedHosts = [:]) -> TrustDecision {
        let ips = results.compactMap(\.ip)
        guard let first = ips.first else {
            return .init(trusted: false, ip: nil, reason: "Could not determine public IP (\(results.count) check(s) failed)")
        }
        if !config.hasTrustRules {
            return .init(trusted: false, ip: first, reason: "Public IP is \(first); no trusted ranges/hosts configured")
        }
        if let bad = ips.first(where: { config.trustMatch($0, resolved: resolved) == nil }) {
            return .init(trusted: false, ip: bad, reason: "Public IP \(bad) is not trusted")
        }
        return .init(trusted: true, ip: first, reason: "Public IP \(first) matches \(config.trustMatch(first, resolved: resolved)!)")
    }
}

func makeEphemeralSession(timeout: TimeInterval) -> URLSession {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.timeoutIntervalForRequest = timeout
    cfg.timeoutIntervalForResource = timeout
    cfg.waitsForConnectivity = false
    cfg.connectionProxyDictionary = [:] // never go through a proxy: we want the real egress path
    cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    cfg.urlCache = nil
    cfg.httpShouldSetCookies = false
    return URLSession(configuration: cfg)
}

public final class PublicIPChecker {
    private let session: URLSession

    public init(timeout: TimeInterval = 6) {
        session = makeEphemeralSession(timeout: timeout)
    }

    public func check(_ urls: [URL], completion: @escaping ([CheckResult]) -> Void) {
        let group = DispatchGroup()
        let lock = NSLock()
        var results: [CheckResult] = []
        for url in urls {
            group.enter()
            var req = URLRequest(url: url)
            req.setValue("SecureNet/\(secureNetVersion)", forHTTPHeaderField: "User-Agent")
            session.dataTask(with: req) { data, resp, err in
                let r: CheckResult
                if let err {
                    r = CheckResult(url: url, ip: nil, error: err.localizedDescription)
                } else if let http = resp as? HTTPURLResponse, http.statusCode == 200,
                          let data, let body = String(data: data, encoding: .utf8),
                          let ip = TraceParser.ip(from: body) {
                    r = CheckResult(url: url, ip: ip, error: nil)
                } else {
                    let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                    r = CheckResult(url: url, ip: nil, error: "unexpected response (HTTP \(code))")
                }
                lock.lock(); results.append(r); lock.unlock()
                group.leave()
            }.resume()
        }
        group.notify(queue: .global()) { completion(results) }
    }

    /// Blocking convenience for CLI use.
    public func checkSync(_ urls: [URL]) -> [CheckResult] {
        let sem = DispatchSemaphore(value: 0)
        var out: [CheckResult] = []
        check(urls) { out = $0; sem.signal() }
        sem.wait()
        return out
    }
}
