import XCTest
@testable import SecureNetCore

final class CIDRTests: XCTestCase {
    func testParseAndContainsV4() {
        let r = CIDR("203.0.113.0/24")!
        XCTAssertTrue(r.contains(IPAddress("203.0.113.1")!))
        XCTAssertTrue(r.contains(IPAddress("203.0.113.255")!))
        XCTAssertFalse(r.contains(IPAddress("203.0.114.1")!))
        XCTAssertEqual(r.description, "203.0.113.0/24")
    }

    func testBareAddressIsSingleHost() {
        let r = CIDR("198.51.100.7")!
        XCTAssertEqual(r.prefix, 32)
        XCTAssertTrue(r.contains(IPAddress("198.51.100.7")!))
        XCTAssertFalse(r.contains(IPAddress("198.51.100.8")!))
    }

    func testHostBitsAreNormalized() {
        XCTAssertEqual(CIDR("10.1.2.3/8")!.description, "10.0.0.0/8")
        XCTAssertEqual(CIDR("192.168.1.130/25")!.description, "192.168.1.128/25")
    }

    func testOddPrefixes() {
        let r = CIDR("10.0.0.0/13")!
        XCTAssertTrue(r.contains(IPAddress("10.7.255.255")!))
        XCTAssertFalse(r.contains(IPAddress("10.8.0.0")!))
        XCTAssertTrue(CIDR("0.0.0.0/0")!.contains(IPAddress("8.8.8.8")!))
    }

    func testV6() {
        let r = CIDR("2001:db8::/32")!
        XCTAssertTrue(r.contains(IPAddress("2001:db8:1::5")!))
        XCTAssertFalse(r.contains(IPAddress("2001:db9::1")!))
        XCTAssertFalse(r.contains(IPAddress("32.1.13.184")!), "v4 never matches a v6 range")
        XCTAssertEqual(CIDR("2001:db8::1")!.prefix, 128)
    }

    func testInvalid() {
        for s in ["", "1.2.3", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/ 8", "1.2.3.4/08", "256.1.1.1",
                  "abc", "1.2.3.4/24/1", "::1/129", "1.2.3.4; pass all", "1.2.3.4 port 22"] {
            XCTAssertNil(CIDR(s), "should reject '\(s)'")
        }
    }
}

final class ConfigTests: XCTestCase {
    func testDefaultsWhenKeysMissing() throws {
        let c = try JSONDecoder().decode(Config.self, from: Data(#"{"trusted_public_ip_ranges":["203.0.113.10"]}"#.utf8))
        XCTAssertEqual(c.trustedPublicIPRanges, [CIDR("203.0.113.10/32")!])
        XCTAssertEqual(c.ipCheckEndpoints, Config.defaultEndpoints)
        XCTAssertTrue(c.blockIPv6WhenTrusted)
        XCTAssertFalse(c.allowDNSWhenUntrusted)
        XCTAssertNoThrow(try c.validate())
    }

    func testRoundTrip() throws {
        var c = Config()
        c.trustedPublicIPRanges = [CIDR("203.0.113.0/24")!]
        c.alwaysAllowed = [AllowRule(host: .cidr(CIDR("203.0.113.10")!), port: 51820, proto: .udp, comment: "VPN")]
        let back = try JSONDecoder().decode(Config.self, from: c.encoded())
        XCTAssertEqual(back, c)
    }

    func testRejectsBadRange() {
        XCTAssertThrowsError(try JSONDecoder().decode(Config.self, from: Data(#"{"trusted_public_ip_ranges":["nope"]}"#.utf8)))
    }

    func testEndpointsMustBeHTTPSWithIPHost() {
        var c = Config()
        c.ipCheckEndpoints = ["http://1.1.1.1/cdn-cgi/trace"]
        XCTAssertThrowsError(try c.validate())
        c.ipCheckEndpoints = ["https://api.ipify.org"]
        XCTAssertThrowsError(try c.validate())
        c.ipCheckEndpoints = ["https://[2606:4700:4700::1111]/cdn-cgi/trace", "https://1.1.1.1:8443/x"]
        let eps = try! c.endpoints()
        XCTAssertEqual(eps[0].ip, IPAddress("2606:4700:4700::1111"))
        XCTAssertEqual(eps[1].port, 8443)
    }

    func testValidateRanges() {
        var c = Config()
        c.alwaysAllowed = [AllowRule(host: .cidr(CIDR("1.2.3.4")!), port: 70000)]
        XCTAssertThrowsError(try c.validate())
        c.alwaysAllowed = []
        c.recheckIntervalSeconds = 1
        XCTAssertThrowsError(try c.validate())
    }
}

final class TrustTests: XCTestCase {
    let url = URL(string: "https://1.1.1.1/cdn-cgi/trace")!
    var config: Config {
        var c = Config()
        c.trustedPublicIPRanges = [CIDR("203.0.113.0/24")!]
        return c
    }

    func ok(_ ip: String) -> CheckResult { CheckResult(url: url, ip: IPAddress(ip), error: nil) }
    var failed: CheckResult { CheckResult(url: url, ip: nil, error: "timeout") }

    func testTrusted() {
        let d = TrustDecision.evaluate([ok("203.0.113.9"), ok("203.0.113.9")], config: config)
        XCTAssertTrue(d.trusted)
        XCTAssertEqual(d.ip, IPAddress("203.0.113.9"))
    }

    func testUntrusted() {
        XCTAssertFalse(TrustDecision.evaluate([ok("198.51.100.1")], config: config).trusted)
    }

    func testOneFailureStillTrustedIfOtherSucceeds() {
        XCTAssertTrue(TrustDecision.evaluate([failed, ok("203.0.113.9")], config: config).trusted)
    }

    func testAllFailedIsUntrusted() {
        let d = TrustDecision.evaluate([failed, failed], config: config)
        XCTAssertFalse(d.trusted)
        XCTAssertNil(d.ip)
    }

    func testDisagreementIsUntrusted() {
        // e.g. split routing: one endpoint goes via VPN, the other leaks out the local network
        XCTAssertFalse(TrustDecision.evaluate([ok("203.0.113.9"), ok("198.51.100.1")], config: config).trusted)
    }

    func testNoRangesIsUntrusted() {
        XCTAssertFalse(TrustDecision.evaluate([ok("203.0.113.9")], config: Config()).trusted)
    }

    func testTraceParser() {
        let body = "fl=123\nh=1.1.1.1\nip=203.0.113.9\nts=1\nvisit_scheme=https\n"
        XCTAssertEqual(TraceParser.ip(from: body), IPAddress("203.0.113.9"))
        XCTAssertEqual(TraceParser.ip(from: "2001:db8::1\n"), IPAddress("2001:db8::1"))
        XCTAssertNil(TraceParser.ip(from: "<html>captive portal</html>"))
    }
}

final class PFRulesTests: XCTestCase {
    func testUntrustedRules() {
        var c = Config()
        c.alwaysAllowed = [
            AllowRule(host: .cidr(CIDR("203.0.113.10")!), port: 51820, proto: .udp),
            AllowRule(host: .cidr(CIDR("198.51.100.0/24")!), port: 443, proto: .tcp),
            AllowRule(host: .cidr(CIDR("2001:db8::1")!)),
        ]
        let r = PFRules.untrusted(c)
        XCTAssertTrue(r.contains("pass out quick inet proto tcp from any to 1.1.1.1 port 443 flags any keep state"))
        XCTAssertTrue(r.contains("pass out quick inet proto udp from any to 203.0.113.10/32 port 51820 keep state"))
        XCTAssertTrue(r.contains("pass out quick inet proto tcp from any to 198.51.100.0/24 port 443 flags any keep state"))
        XCTAssertTrue(r.contains("pass out quick inet6 from any to 2001:db8::1/128 keep state"))
        XCTAssertFalse(r.contains("port 53"))
        XCTAssertTrue(r.contains("block drop in quick all"))
        // block rule must come after all pass rules
        let lines = r.split(separator: "\n")
        XCTAssertEqual(lines.filter { !$0.hasPrefix("#") }.last, "block drop in quick all")
        XCTAssertLessThan(lines.firstIndex(of: "pass out quick inet proto udp from any to 203.0.113.10/32 port 51820 keep state")!,
                          lines.firstIndex(of: "block drop out quick all")!)
    }

    func testDNSOption() {
        var c = Config()
        c.allowDNSWhenUntrusted = true
        XCTAssertTrue(PFRules.untrusted(c).contains("pass out quick proto udp from any to any port 53 keep state"))
    }

    func testTrustedRules() {
        var c = Config()
        XCTAssertTrue(PFRules.trusted(c).contains("block drop out quick inet6 all"))
        c.blockIPv6WhenTrusted = false
        XCTAssertFalse(PFRules.trusted(c).contains("block"))
    }
}

final class HostnameTests: XCTestCase {
    func testHostSpec() {
        XCTAssertEqual(HostSpec("33b60248f971.sn.mynetname.net"), .name("33b60248f971.sn.mynetname.net"))
        XCTAssertEqual(HostSpec("VPN.Example.COM."), .name("vpn.example.com"))
        XCTAssertEqual(HostSpec("10.0.0.1"), .cidr(CIDR("10.0.0.1")!))
        for bad in ["localhost", "-a.com", "a-.com", "a..com", "a.com; pass all", "a.com\npass", "1.2.3.999", "a_b.com", ""] {
            XCTAssertNil(HostSpec(bad), "should reject '\(bad)'")
        }
    }

    func testAllowRuleDecodesHostname() throws {
        let c = try JSONDecoder().decode(Config.self, from: Data(#"""
        {"always_allowed":[{"host":"vpn.example.com"}],"trusted_public_hosts":["office.example.com"]}
        """#.utf8))
        XCTAssertEqual(c.alwaysAllowed[0].host, .name("vpn.example.com"))
        XCTAssertEqual(c.alwaysAllowed[0].proto, .any)
        XCTAssertEqual(c.hostnames, ["office.example.com", "vpn.example.com"])
        XCTAssertNoThrow(try c.validate())
    }

    func testRulesForResolvedHostnameL2TP() {
        var c = Config()
        c.alwaysAllowed = [AllowRule(host: .name("vpn.example.com"), comment: "L2TP/IPsec")]
        let unresolved = PFRules.untrusted(c)
        XCTAssertTrue(unresolved.contains("# vpn.example.com: not resolved yet"))
        let r = PFRules.untrusted(c, resolved: ["vpn.example.com": [IPAddress("203.0.113.10")!]])
        // protocol-less rule covers UDP 500/4500/1701 and ESP
        XCTAssertTrue(r.contains("pass out quick inet from any to 203.0.113.10/32 keep state"))
        XCTAssertTrue(r.contains("pass out quick inet proto tcp from any to 1.1.1.1 port 443 flags any keep state"))
    }

    func testTrustByHostname() {
        var c = Config()
        c.trustedPublicHosts = ["office.example.com"]
        let ok = CheckResult(url: URL(string: "https://1.1.1.1/")!, ip: IPAddress("203.0.113.10"), error: nil)
        XCTAssertFalse(TrustDecision.evaluate([ok], config: c).trusted, "unresolved host trusts nothing")
        let d = TrustDecision.evaluate([ok], config: c, resolved: ["office.example.com": [IPAddress("203.0.113.10")!]])
        XCTAssertTrue(d.trusted)
        XCTAssertTrue(d.reason.contains("office.example.com"))
        XCTAssertFalse(TrustDecision.evaluate([ok], config: c, resolved: ["office.example.com": [IPAddress("203.0.113.11")!]]).trusted)
    }

    func testDoHParse() {
        let body = #"{"Status":0,"Answer":[{"name":"a.example.com","type":5,"data":"b.example.com."},{"name":"b.example.com","type":1,"data":"203.0.113.10"}]}"#
        XCTAssertEqual(DoHResolver.parse(Data(body.utf8), type: 1), [IPAddress("203.0.113.10")!])
        XCTAssertEqual(DoHResolver.parse(Data(#"{"Status":3}"#.utf8), type: 1), [])
        XCTAssertNil(DoHResolver.parse(Data(#"{"Status":2}"#.utf8), type: 1), "SERVFAIL keeps the cache")
        XCTAssertNil(DoHResolver.parse(Data("<html>".utf8), type: 1))
    }

    func testLiveDoH() throws {
        // Uses a public name only; skipped if offline.
        let r = DoHResolver(endpoint: URL(string: Config.defaultDoHEndpoint)!).resolveSync(["one.one.one.one"])
        guard let ips = r["one.one.one.one"] else { throw XCTSkip("DoH not reachable") }
        XCTAssertTrue(ips.contains(IPAddress("1.1.1.1")!))
    }
}
