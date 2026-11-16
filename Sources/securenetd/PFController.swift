import Foundation
import SecureNetCore

/// Drives /sbin/pfctl. All calls happen on the main queue.
final class PFController {
    enum Mode: String { case blocked, trusted }

    private(set) var mode: Mode?
    private var loadedRules: String?

    @discardableResult
    func run(_ args: [String]) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (-1, "\(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let out = String(decoding: data, as: UTF8.self)
            .split(separator: "\n")
            .filter { !$0.contains("ALTQ") } // pfctl always prints ALTQ noise on macOS
            .joined(separator: "\n")
        return (p.terminationStatus, out)
    }

    /// Makes sure pf is enabled, Apple's anchor point exists, and our anchor still holds our rules.
    /// Some tools flush pf or replace the main ruleset; this re-asserts our protection.
    func ensureHealthy() {
        let rules = run(["-s", "rules"]).output
        let hasAnchorPoint = rules.split(separator: "\n").contains { $0.hasPrefix("anchor \"com.apple/*\"") }
        if !hasAnchorPoint {
            log("WARNING: pf main ruleset lost the com.apple anchor point; reloading /etc/pf.conf")
            let r = run(["-f", "/etc/pf.conf"])
            if r.status != 0 { log("ERROR reloading /etc/pf.conf: \(r.output)") }
        }

        if !run(["-s", "info"]).output.contains("Status: Enabled") {
            let r = run(["-E"])
            log("pf was disabled; enabled it")
            if let range = r.output.range(of: #"Token\s*:\s*(\d+)"#, options: .regularExpression) {
                let token = r.output[range].split(separator: ":").last!.trimmingCharacters(in: .whitespaces)
                try? (token + "\n").write(toFile: Paths.pfToken, atomically: true, encoding: .utf8)
            }
        }

        if let mode, let loadedRules {
            let current = run(["-a", PFRules.anchor, "-s", "rules"]).output.trimmingCharacters(in: .whitespacesAndNewlines)
            if current.isEmpty {
                log("WARNING: SecureNet pf anchor was flushed by something else; reloading")
                self.mode = nil
                self.loadedRules = nil
                apply(mode, rules: loadedRules)
            }
        }
    }

    @discardableResult
    func apply(_ m: Mode, rules: String) -> Bool {
        if mode == m && loadedRules == rules { return true }
        if load(rules, name: m.rawValue) {
            mode = m
            loadedRules = rules
            log("pf: \(m.rawValue) rules active")
            return true
        }
        if m == .blocked {
            log("ERROR: falling back to minimal block ruleset")
            if load(PFRules.minimalBlock, name: "minimal") { mode = .blocked; loadedRules = PFRules.minimalBlock }
        }
        return false
    }

    private func load(_ rules: String, name: String) -> Bool {
        let path = "\(Paths.supportDir)/rules-\(name).conf"
        do {
            try rules.write(toFile: path, atomically: true, encoding: .utf8)
            chmod(path, 0o600)
        } catch {
            log("ERROR writing \(path): \(error)")
            return false
        }
        let r = run(["-a", PFRules.anchor, "-f", path])
        if r.status != 0 {
            log("ERROR loading \(name) rules (exit \(r.status)): \(r.output)")
            return false
        }
        return true
    }

    /// Drops all tracked connections, so connections opened while trusted can't continue on an untrusted network.
    func flushStates() {
        run(["-F", "states"])
        log("pf: flushed connection states")
    }
}
