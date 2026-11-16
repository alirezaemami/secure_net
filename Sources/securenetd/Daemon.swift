import Foundation
import Network
import SecureNetCore

/// The trust state machine. Everything runs on the main queue.
///
/// Rule: fail closed. On start, network change, sleep and wake we block FIRST,
/// then check the public IP, and only open up if it is in a trusted range.
final class Daemon {
    private var config = Config()
    private let pf = PFController()
    private let checker = PublicIPChecker()
    private var resolver: DoHResolver?
    /// Last successful DoH answers, persisted so the VPN server is reachable right after boot.
    private var resolved: ResolvedHosts = [:]

    private var state: TrustState = .checking
    private var reason = "starting"
    private var since = Date()
    private var publicIP: String?
    private var lastCheck: Date?

    /// Bumped on every network change / sleep / wake. "Allow once" is tied to one generation.
    private var generation = 0
    private var allowOnceGeneration: Int?
    /// Last state that came from a completed decision (used to decide when to flush connections).
    private var lastConfirmed: TrustState?

    private var checkSeq = 0
    private var pendingCheck: DispatchWorkItem?
    private var pathMonitor: NWPathMonitor?
    private var lastPathFingerprint: String?
    private var timer: DispatchSourceTimer?
    private var server: ControlServer?
    private var signalSources: [DispatchSourceSignal] = []

    func start() {
        log("securenetd \(secureNetVersion) starting")
        try? FileManager.default.createDirectory(atPath: Paths.supportDir, withIntermediateDirectories: true)
        loadConfig()
        loadResolvedCache()
        pf.ensureHealthy()
        enterBlocked("starting: checking network", flush: false)
        startServer()
        startPathMonitor()
        startPowerMonitor()
        startTimer()
        startSignals()
        scheduleCheck(after: 0.5)
    }

    // MARK: - State transitions

    private func setState(_ s: TrustState, _ r: String) {
        if s != state {
            log("state \(state.rawValue) -> \(s.rawValue): \(r)")
            since = Date()
        } else if r != reason {
            log("\(s.rawValue): \(r)")
        }
        state = s
        reason = r
    }

    private func enterBlocked(_ r: String, flush: Bool, state s: TrustState = .checking) {
        pf.apply(.blocked, rules: PFRules.untrusted(config, resolved: resolved))
        if flush { pf.flushStates() }
        setState(s, r)
    }

    private func enterOpen(_ s: TrustState, _ r: String) {
        if pf.apply(.trusted, rules: PFRules.trusted(config)) {
            setState(s, r)
        } else {
            enterBlocked("failed to load trusted rules; staying blocked", flush: false, state: .untrusted)
        }
    }

    // MARK: - Events

    func networkChanged(_ desc: String) {
        generation += 1
        if allowOnceGeneration != nil { log("allow-once ended: network changed") }
        allowOnceGeneration = nil
        log("network changed: \(desc)")
        enterBlocked("network changed: checking", flush: false)
        scheduleCheck(after: 1.5)
    }

    func willSleep() {
        generation += 1
        allowOnceGeneration = nil
        enterBlocked("system going to sleep: blocked until checked on wake", flush: false)
    }

    func didWake() {
        generation += 1
        allowOnceGeneration = nil
        enterBlocked("woke from sleep: checking", flush: false)
        scheduleCheck(after: 2)
    }

    // MARK: - Checking

    private func scheduleCheck(after delay: Double) {
        pendingCheck?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.runCheck() }
        pendingCheck = w
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: w)
    }

    private func runCheck() {
        pendingCheck = nil
        pf.ensureHealthy()
        checkSeq += 1
        let seq = checkSeq
        let urls = ((try? config.endpoints()) ?? []).map(\.url)
        let names = config.hostnames
        let group = DispatchGroup()
        var results: [CheckResult] = []
        var fresh: ResolvedHosts = [:]
        group.enter()
        checker.check(urls) { results = $0; group.leave() }
        if let resolver, !names.isEmpty {
            group.enter()
            resolver.resolve(names) { fresh = $0; group.leave() }
        }
        group.notify(queue: .main) {
            self.mergeResolved(fresh)
            guard seq == self.checkSeq else { return } // a newer check superseded this one
            self.finishCheck(results)
        }
    }

    private func finishCheck(_ results: [CheckResult]) {
        lastCheck = Date()
        for r in results { if let e = r.error { log("ip check \(r.url.absoluteString) failed: \(e)") } }
        let d = TrustDecision.evaluate(results, config: config, resolved: resolved)
        publicIP = d.ip?.description

        if let g = allowOnceGeneration, g == generation {
            enterOpen(.allowedOnce, "allowed by you until the network changes (\(d.reason))")
            return
        }
        if d.trusted {
            lastConfirmed = .trusted
            enterOpen(.trusted, d.reason)
        } else {
            let flush = lastConfirmed != .untrusted
            lastConfirmed = .untrusted
            enterBlocked(d.reason, flush: flush, state: .untrusted)
        }
    }

    private func periodicCheck() {
        // A check is already on the way after a network change/wake.
        if state == .checking { return }
        runCheck()
    }

    // MARK: - Control commands

    func handle(_ req: ControlRequest, uid: uid_t) -> ControlResponse {
        switch req.cmd {
        case "status":
            break
        case "allow_once":
            guard config.allowOnceEnabled else { return .failure("allow-once is disabled in config", status()) }
            allowOnceGeneration = generation
            lastConfirmed = .allowedOnce
            log("allow-once granted by uid \(uid)")
            enterOpen(.allowedOnce, "allowed by you until the network changes")
        case "block":
            if allowOnceGeneration != nil { log("allow-once revoked by uid \(uid)") }
            allowOnceGeneration = nil
            lastConfirmed = nil
            enterBlocked("blocked by you: re-checking", flush: true)
            scheduleCheck(after: 0)
        case "recheck":
            scheduleCheck(after: 0)
        case "reload":
            guard uid == 0 else { return .failure("reload requires root (use sudo)", status()) }
            loadConfig()
            if state.isOpen { enterOpen(state, reason) } else { enterBlocked(reason, flush: false, state: state) }
            startTimer()
            scheduleCheck(after: 0)
        default:
            return .failure("unknown command '\(req.cmd)'", status())
        }
        return .success(status())
    }

    private func status() -> DaemonStatus {
        DaemonStatus(state: state, publicIP: publicIP, reason: reason, since: since, lastCheck: lastCheck,
                     generation: generation, allowOnceEnabled: config.allowOnceEnabled,
                     trustedRanges: config.trustedPublicIPRanges.map(\.description) + config.trustedPublicHosts.map { h in
                         "\(h) (\(resolved[h]?.map(\.description).joined(separator: ", ") ?? "unresolved"))"
                     },
                     version: secureNetVersion)
    }

    // MARK: - Hostname resolution

    /// Applies fresh DoH answers. Failed lookups are absent from `fresh`, so the cached IPs stay in use.
    private func mergeResolved(_ fresh: ResolvedHosts) {
        let names = Set(config.hostnames)
        var next = resolved.filter { names.contains($0.key) }
        for (name, ips) in fresh where names.contains(name) {
            if next[name] != ips {
                log("resolved \(name) -> \(ips.isEmpty ? "(no address)" : ips.map(\.description).joined(separator: ", "))")
            }
            next[name] = ips
        }
        guard next != resolved else { return }
        resolved = next
        saveResolvedCache()
    }

    private func loadResolvedCache() {
        guard let data = FileManager.default.contents(atPath: Paths.resolvedCache),
              let raw = try? JSONDecoder().decode([String: [String]].self, from: data) else { return }
        let names = Set(config.hostnames)
        resolved = raw.filter { names.contains($0.key) }.mapValues { $0.compactMap(IPAddress.init) }
        if !resolved.isEmpty { log("loaded cached host addresses for \(resolved.keys.sorted())") }
    }

    private func saveResolvedCache() {
        let raw = resolved.mapValues { $0.map(\.description) }
        guard let data = try? JSONEncoder().encode(raw) else { return }
        FileManager.default.createFile(atPath: Paths.resolvedCache, contents: data, attributes: [.posixPermissions: 0o644])
    }

    // MARK: - Setup

    private func loadConfig() {
        guard FileManager.default.fileExists(atPath: Paths.config) else {
            log("WARNING: no config at \(Paths.config); every network will be treated as untrusted")
            return
        }
        do {
            let c = try Config.load(from: Paths.config)
            try c.validate()
            config = c
            resolver = (try? c.dohEndpointParsed()).map { DoHResolver(endpoint: $0.url) }
            log("config loaded: trusted ranges \(c.trustedPublicIPRanges.map(\.description)), trusted hosts \(c.trustedPublicHosts), \(c.alwaysAllowed.count) always-allowed rule(s)")
        } catch {
            log("ERROR loading config, keeping previous one: \(error)")
        }
    }

    private func startServer() {
        let s = ControlServer(path: Paths.socket) { [unowned self] req, uid in handle(req, uid: uid) }
        do { try s.start(); server = s } catch { log("ERROR starting control socket: \(error)") }
    }

    private func startPathMonitor() {
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let fp = Daemon.fingerprint(path)
            guard fp != self.lastPathFingerprint else { return }
            let isFirst = self.lastPathFingerprint == nil
            self.lastPathFingerprint = fp
            if !isFirst { self.networkChanged(fp) }
        }
        m.start(queue: .main)
        pathMonitor = m
    }

    private static func fingerprint(_ p: NWPath) -> String {
        let ifs = p.availableInterfaces.map(\.name).joined(separator: ",")
        let gws = p.gateways.map { "\($0)" }.joined(separator: ",")
        return "status=\(p.status) interfaces=[\(ifs)] gateways=[\(gws)]"
    }

    private func startPowerMonitor() {
        if !PowerMonitor.start(willSleep: { [weak self] in self?.willSleep() },
                               didWake: { [weak self] in self?.didWake() }) {
            log("WARNING: could not register for sleep/wake notifications")
        }
    }

    private func startTimer() {
        timer?.cancel()
        let interval = Double(max(10, config.recheckIntervalSeconds))
        let t = DispatchSource.makeTimerSource(queue: .main)
        t.schedule(deadline: .now() + interval, repeating: interval, leeway: .seconds(2))
        t.setEventHandler { [weak self] in self?.periodicCheck() }
        t.resume()
        timer = t
    }

    private func startSignals() {
        signal(SIGHUP, SIG_IGN)
        let s = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .main)
        s.setEventHandler { [weak self] in
            log("SIGHUP: reloading config")
            _ = self?.handle(ControlRequest("reload"), uid: 0)
        }
        s.resume()
        signalSources.append(s)
    }
}
