import Foundation
import SecureNetCore

let usage = """
securenetctl: control SecureNet

Status & actions (any user):
  status                      Show current state
  allow-once                  Allow this network until it changes (or the Mac sleeps)
  block                       Revoke allow-once and re-check now
  recheck                     Re-check the public IP now
  myip                        Show your public IP and whether it would be trusted
  config                      Print the config
  rules                       Print the pf rules generated for both modes

Config changes (need sudo):
  init [CIDR ...]             Create the config if missing, with optional trusted ranges
  add-range CIDR              Trust a public IP range, e.g. 203.0.113.10 or 203.0.113.0/24
  remove-range CIDR
  add-host HOSTNAME           Trust whatever IP a hostname points to (e.g. office dynamic DNS)
  remove-host HOSTNAME
  add-allow HOST [PORT] [tcp|udp|any] [comment...]
                              Always allow a destination (e.g. your VPN server) while blocked.
                              HOST may be an IP, CIDR or hostname. Omit PORT to allow all
                              protocols (needed for L2TP/IPsec: UDP 500/4500/1701 + ESP).
  remove-allow INDEX          (see indexes with `securenetctl config`)
  set KEY VALUE               allow_dns_when_untrusted | block_ipv6_when_trusted |
                              block_inbound_when_untrusted | allow_once_enabled (true/false)
                              recheck_interval_seconds (number)
  reload                      Tell the daemon to re-read the config
"""

func fail(_ m: String) -> Never {
    FileHandle.standardError.write(Data("error: \(m)\n".utf8))
    exit(1)
}

func send(_ cmd: String) -> DaemonStatus {
    do {
        let r = try SecureNetClient.send(ControlRequest(cmd))
        guard r.ok, let s = r.status else { fail(r.error ?? "unknown error") }
        return s
    } catch {
        fail("\(error)")
    }
}

func ago(_ d: Date) -> String {
    let s = Int(-d.timeIntervalSinceNow)
    if s < 60 { return "\(s)s ago" }
    if s < 3600 { return "\(s / 60)m ago" }
    return "\(s / 3600)h \(s % 3600 / 60)m ago"
}

func printStatus(_ s: DaemonStatus) {
    let label: String
    switch s.state {
    case .trusted: label = "TRUSTED: traffic allowed"
    case .allowedOnce: label = "ALLOWED ONCE: traffic allowed until network changes"
    case .untrusted: label = "UNTRUSTED: outbound traffic BLOCKED"
    case .checking: label = "CHECKING: blocked while checking"
    }
    print("State:     \(label)  (since \(ago(s.since)))")
    print("Public IP: \(s.publicIP ?? "unknown")")
    print("Reason:    \(s.reason)")
    print("Last check: \(s.lastCheck.map(ago) ?? "never")")
    print("Trusted:   \(s.trustedRanges.isEmpty ? "(none configured)" : s.trustedRanges.joined(separator: ", "))")
}

func requireRoot() {
    if geteuid() != 0 { fail("this changes the config; run it with sudo") }
}

func loadConfig() -> Config {
    guard FileManager.default.fileExists(atPath: Paths.config) else { return Config() }
    do { return try Config.load(from: Paths.config) } catch { fail("cannot read \(Paths.config): \(error)") }
}

func saveAndReload(_ c: Config) {
    do {
        try c.validate()
        try FileManager.default.createDirectory(atPath: Paths.supportDir, withIntermediateDirectories: true)
        try c.save(to: Paths.config)
    } catch {
        fail("\(error)")
    }
    print("Saved \(Paths.config)")
    if let r = try? SecureNetClient.send(ControlRequest("reload")), r.ok {
        print("Daemon reloaded.")
    } else {
        print("(daemon not running; changes apply when it starts)")
    }
}

func resolveHosts(_ c: Config) -> ResolvedHosts {
    guard !c.hostnames.isEmpty, let doh = try? c.dohEndpointParsed() else { return [:] }
    return DoHResolver(endpoint: doh.url).resolveSync(c.hostnames)
}

func parseBool(_ s: String) -> Bool {
    switch s.lowercased() {
    case "true", "yes", "on", "1": return true
    case "false", "no", "off", "0": return false
    default: fail("expected true/false, got '\(s)'")
    }
}

var args = Array(CommandLine.arguments.dropFirst())
guard !args.isEmpty else { print(usage); exit(0) }
let cmd = args.removeFirst()

switch cmd {
case "status":
    printStatus(send("status"))

case "allow-once":
    printStatus(send("allow_once"))

case "block":
    printStatus(send("block"))

case "recheck":
    let before = send("recheck").lastCheck
    for _ in 0..<40 {
        usleep(250_000)
        let s = send("status")
        if s.lastCheck != before && s.state != .checking { printStatus(s); exit(0) }
    }
    printStatus(send("status"))

case "myip":
    let c = loadConfig()
    let eps: [Config.Endpoint]
    do { eps = try c.endpoints() } catch { fail("\(error)") }
    let results = PublicIPChecker().checkSync(eps.map(\.url))
    for r in results {
        print("\(r.url.absoluteString): \(r.ip?.description ?? "FAILED (\(r.error ?? "?"))")")
    }
    let resolved = resolveHosts(c)
    for h in c.hostnames {
        print("\(h) -> \(resolved[h].map { $0.isEmpty ? "(no address)" : $0.map(\.description).joined(separator: ", ") } ?? "LOOKUP FAILED")")
    }
    let d = TrustDecision.evaluate(results, config: c, resolved: resolved)
    print(d.trusted ? "=> TRUSTED. \(d.reason)" : "=> NOT trusted. \(d.reason)")

case "config":
    let c = loadConfig()
    print(String(decoding: try! c.encoded(), as: UTF8.self), terminator: "")
    if !c.alwaysAllowed.isEmpty {
        print("\nalways_allowed indexes:")
        for (i, r) in c.alwaysAllowed.enumerated() { print("  [\(i)] \(r.summary)") }
    }

case "rules":
    let c = loadConfig()
    print("# ---- anchor \(PFRules.anchor), UNTRUSTED mode ----")
    print(PFRules.untrusted(c, resolved: resolveHosts(c)))
    print("# ---- anchor \(PFRules.anchor), TRUSTED mode ----")
    print(PFRules.trusted(c))

case "init":
    requireRoot()
    if FileManager.default.fileExists(atPath: Paths.config) && args.isEmpty {
        print("Config already exists at \(Paths.config)"); exit(0)
    }
    var c = loadConfig()
    for a in args {
        guard let r = CIDR(a) else { fail("invalid IP/CIDR '\(a)'") }
        if !c.trustedPublicIPRanges.contains(r) { c.trustedPublicIPRanges.append(r) }
    }
    saveAndReload(c)

case "add-range":
    requireRoot()
    guard args.count == 1, let r = CIDR(args[0]) else { fail("usage: add-range CIDR  (e.g. 203.0.113.10 or 203.0.113.0/24)") }
    var c = loadConfig()
    if c.trustedPublicIPRanges.contains(r) { print("\(r) is already trusted"); exit(0) }
    c.trustedPublicIPRanges.append(r)
    saveAndReload(c)

case "remove-range":
    requireRoot()
    guard args.count == 1, let r = CIDR(args[0]) else { fail("usage: remove-range CIDR") }
    var c = loadConfig()
    guard c.trustedPublicIPRanges.contains(r) else { fail("\(r) is not in the trusted list") }
    c.trustedPublicIPRanges.removeAll { $0 == r }
    saveAndReload(c)

case "add-host":
    requireRoot()
    guard args.count == 1, let h = HostSpec.normalizedHostname(args[0]) else { fail("usage: add-host HOSTNAME") }
    var c = loadConfig()
    if c.trustedPublicHosts.contains(h) { print("\(h) is already trusted"); exit(0) }
    c.trustedPublicHosts.append(h)
    saveAndReload(c)

case "remove-host":
    requireRoot()
    guard args.count == 1, let h = HostSpec.normalizedHostname(args[0]) else { fail("usage: remove-host HOSTNAME") }
    var c = loadConfig()
    guard c.trustedPublicHosts.contains(h) else { fail("\(h) is not in the trusted hosts") }
    c.trustedPublicHosts.removeAll { $0 == h }
    saveAndReload(c)

case "add-allow":
    requireRoot()
    guard let hostArg = args.first, let host = HostSpec(hostArg) else {
        fail("usage: add-allow HOST [PORT] [tcp|udp|any] [comment...]  (HOST: IP, CIDR or hostname)")
    }
    var rest = Array(args.dropFirst())
    var port: Int?
    var proto = AllowRule.Proto.any
    if let p = rest.first, let n = Int(p) { port = n; rest.removeFirst() }
    if let p = rest.first, let v = AllowRule.Proto(rawValue: p.lowercased()) { proto = v; rest.removeFirst() }
    let comment = rest.isEmpty ? nil : rest.joined(separator: " ")
    var c = loadConfig()
    c.alwaysAllowed.append(AllowRule(host: host, port: port, proto: proto, comment: comment))
    saveAndReload(c)

case "remove-allow":
    requireRoot()
    var c = loadConfig()
    guard args.count == 1, let i = Int(args[0]), c.alwaysAllowed.indices.contains(i) else {
        fail("usage: remove-allow INDEX  (see `securenetctl config`)")
    }
    print("Removing: \(c.alwaysAllowed[i].summary)")
    c.alwaysAllowed.remove(at: i)
    saveAndReload(c)

case "set":
    requireRoot()
    guard args.count == 2 else { fail("usage: set KEY VALUE") }
    var c = loadConfig()
    switch args[0] {
    case "allow_dns_when_untrusted": c.allowDNSWhenUntrusted = parseBool(args[1])
    case "block_ipv6_when_trusted": c.blockIPv6WhenTrusted = parseBool(args[1])
    case "block_inbound_when_untrusted": c.blockInboundWhenUntrusted = parseBool(args[1])
    case "allow_once_enabled": c.allowOnceEnabled = parseBool(args[1])
    case "recheck_interval_seconds":
        guard let n = Int(args[1]) else { fail("expected a number") }
        c.recheckIntervalSeconds = n
    default: fail("unknown key '\(args[0])'")
    }
    saveAndReload(c)

case "reload":
    requireRoot()
    printStatus(send("reload"))

case "help", "-h", "--help":
    print(usage)

default:
    print(usage)
    exit(2)
}
