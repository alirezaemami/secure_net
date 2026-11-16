import Foundation

/// Resolves hostnames with DNS-over-HTTPS (JSON API, e.g. https://1.1.1.1/dns-query).
/// HTTPS means a hostile local network cannot spoof the answer the way it can with plain DNS.
public final class DoHResolver {
    private let endpoint: URL
    private let session: URLSession

    public init(endpoint: URL, timeout: TimeInterval = 6) {
        self.endpoint = endpoint
        session = makeEphemeralSession(timeout: timeout)
    }

    struct Response: Decodable {
        struct Answer: Decodable { let type: Int; let data: String }
        let Status: Int
        let Answer: [Answer]?
    }

    /// Parses a DoH JSON body. Returns nil if the lookup failed (so the caller can keep its cache),
    /// or the A/AAAA addresses (possibly empty) on NOERROR/NXDOMAIN.
    public static func parse(_ data: Data, type: Int) -> [IPAddress]? {
        guard let r = try? JSONDecoder().decode(Response.self, from: data) else { return nil }
        guard r.Status == 0 || r.Status == 3 else { return nil } // 0 NOERROR, 3 NXDOMAIN
        return (r.Answer ?? []).filter { $0.type == type }.compactMap { IPAddress($0.data) }
    }

    /// Calls back with addresses for each name that resolved. Names whose lookups failed are omitted.
    public func resolve(_ names: [String], completion: @escaping (ResolvedHosts) -> Void) {
        let group = DispatchGroup()
        let lock = NSLock()
        var answers: [String: [Int: [IPAddress]]] = [:]
        for name in names {
            for type in [1, 28] { // A, AAAA
                var comps = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)!
                comps.queryItems = [URLQueryItem(name: "name", value: name),
                                    URLQueryItem(name: "type", value: type == 1 ? "A" : "AAAA")]
                var req = URLRequest(url: comps.url!)
                req.setValue("application/dns-json", forHTTPHeaderField: "Accept")
                group.enter()
                session.dataTask(with: req) { data, resp, _ in
                    if (resp as? HTTPURLResponse)?.statusCode == 200, let data,
                       let ips = DoHResolver.parse(data, type: type) {
                        lock.lock(); answers[name, default: [:]][type] = ips; lock.unlock()
                    }
                    group.leave()
                }.resume()
            }
        }
        group.notify(queue: .global()) {
            var out: ResolvedHosts = [:]
            for (name, byType) in answers { out[name] = (byType[1] ?? []) + (byType[28] ?? []) }
            completion(out)
        }
    }

    public func resolveSync(_ names: [String]) -> ResolvedHosts {
        let sem = DispatchSemaphore(value: 0)
        var out: ResolvedHosts = [:]
        resolve(names) { out = $0; sem.signal() }
        sem.wait()
        return out
    }
}
