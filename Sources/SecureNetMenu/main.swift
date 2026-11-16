import AppKit
import SecureNetCore

/// Menu-bar UI. Polls the daemon and warns when the Mac is on an untrusted network.
/// Protection is enforced by securenetd; quitting this app does NOT disable it.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private let menu = NSMenu()
    private let stateItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let ipItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let reasonItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private var allowItem: NSMenuItem!
    private var blockItem: NSMenuItem!
    private var recheckItem: NSMenuItem!

    private var status: DaemonStatus?
    private var lastAlertedSince: Date?
    private var alertOpen = false
    private var timer: Timer?

    func applicationDidFinishLaunching(_ n: Notification) {
        // New status items are placed at the far left of the icon area, which on notched MacBooks
        // with a crowded menu bar means "hidden behind the notch". Default to a spot near the clock
        // (distance from the right screen edge); a position you choose with ⌘-drag is saved and wins.
        UserDefaults.standard.register(defaults: ["NSStatusItem Preferred Position SecureNet": 160])
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = "SecureNet"
        allowItem = NSMenuItem(title: "Allow This Network Until It Changes…", action: #selector(allowOnce), keyEquivalent: "")
        blockItem = NSMenuItem(title: "Block Again", action: #selector(block), keyEquivalent: "")
        recheckItem = NSMenuItem(title: "Re-check Now", action: #selector(recheck), keyEquivalent: "r")
        for i in [stateItem, ipItem, reasonItem] { i.isEnabled = false; menu.addItem(i) }
        menu.addItem(.separator())
        for i in [allowItem!, blockItem!, recheckItem!] { i.target = self; menu.addItem(i) }
        menu.addItem(.separator())
        let logItem = NSMenuItem(title: "Open Log", action: #selector(openLog), keyEquivalent: "")
        logItem.target = self
        menu.addItem(logItem)
        let quit = NSMenuItem(title: "Quit Menu (protection keeps running)", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        menu.autoenablesItems = false
        item.menu = menu

        render(nil, error: "connecting…")
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.poll() }
    }

    private func poll() {
        DispatchQueue.global().async {
            let result = Result { try SecureNetClient.send(ControlRequest("status"), timeout: 5) }
            DispatchQueue.main.async {
                switch result {
                case .success(let r) where r.status != nil: self.render(r.status, error: nil)
                case .success(let r): self.render(nil, error: r.error ?? "bad response")
                case .failure(let e): self.render(nil, error: "\(e)")
                }
            }
        }
    }

    private func send(_ cmd: String) {
        DispatchQueue.global().async {
            let result = Result { try SecureNetClient.send(ControlRequest(cmd)) }
            DispatchQueue.main.async {
                if case .success(let r) = result, !r.ok { self.showError(r.error ?? "failed") }
                if case .failure(let e) = result { self.showError("\(e)") }
                self.poll()
            }
        }
    }

    private func render(_ s: DaemonStatus?, error: String?) {
        status = s
        let button = item.button!
        guard let s else {
            setIcon("shield.slash", tint: .systemOrange, button: button)
            stateItem.title = "SecureNet daemon not reachable"
            ipItem.title = error ?? ""
            reasonItem.title = "Protection status unknown"
            allowItem.isEnabled = false; blockItem.isEnabled = false; recheckItem.isEnabled = false
            return
        }
        switch s.state {
        case .trusted:
            setIcon("lock.shield.fill", tint: nil, button: button)
            stateItem.title = "✅ Trusted network: traffic allowed"
        case .allowedOnce:
            setIcon("exclamationmark.shield.fill", tint: .systemYellow, button: button)
            stateItem.title = "⚠️ Untrusted network ALLOWED by you"
        case .untrusted:
            setIcon("xmark.shield.fill", tint: .systemRed, button: button)
            stateItem.title = "⛔️ Untrusted network: traffic BLOCKED"
        case .checking:
            setIcon("shield.lefthalf.filled", tint: .systemGray, button: button)
            stateItem.title = "⏳ Checking network (blocked meanwhile)"
        }
        ipItem.title = "Public IP: \(s.publicIP ?? "unknown")"
        reasonItem.title = s.reason
        allowItem.isEnabled = s.allowOnceEnabled && (s.state == .untrusted || s.state == .checking)
        blockItem.isEnabled = s.state == .allowedOnce
        recheckItem.isEnabled = true

        // Warn once each time we newly enter the untrusted state.
        if s.state == .untrusted && lastAlertedSince != s.since && !alertOpen {
            lastAlertedSince = s.since
            showUntrustedAlert(s)
        }
    }

    private func setIcon(_ symbol: String, tint: NSColor?, button: NSStatusBarButton) {
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "SecureNet")
        img?.isTemplate = tint == nil
        button.image = img
        button.contentTintColor = tint
    }

    private func showUntrustedAlert(_ s: DaemonStatus) {
        alertOpen = true
        defer { alertOpen = false }
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Untrusted network: internet blocked"
        alert.informativeText = """
        \(s.reason).

        All connections from this Mac are blocked, except your VPN server and other always-allowed destinations.

        Connect your office VPN and SecureNet will unblock automatically once your public IP is trusted.

        Allow only if you really need to (for example, to log in to a hotel/café Wi-Fi page). The permission ends when the network changes or the Mac sleeps.
        """
        alert.addButton(withTitle: "Keep Blocked")
        if s.allowOnceEnabled { alert.addButton(withTitle: "Allow Until Network Changes") }
        NSApp.activate(ignoringOtherApps: true)
        alert.window.level = .floating
        if alert.runModal() == .alertSecondButtonReturn { send("allow_once") }
    }

    private func showError(_ m: String) {
        let a = NSAlert()
        a.messageText = "SecureNet"
        a.informativeText = m
        NSApp.activate(ignoringOtherApps: true)
        a.runModal()
    }

    @objc private func allowOnce() {
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = "Allow all traffic on this untrusted network?"
        a.informativeText = "Public IP: \(status?.publicIP ?? "unknown"). The permission ends when the network changes or the Mac sleeps."
        a.addButton(withTitle: "Cancel")
        a.addButton(withTitle: "Allow")
        NSApp.activate(ignoringOtherApps: true)
        if a.runModal() == .alertSecondButtonReturn { send("allow_once") }
    }

    @objc private func block() { send("block") }
    @objc private func recheck() { send("recheck") }
    @objc private func openLog() { NSWorkspace.shared.open(URL(fileURLWithPath: Paths.log)) }
    @objc private func quit() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
