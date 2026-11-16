import Foundation
import IOKit
import IOKit.pwr_mgt

// iokit_common_msg(x) = 0xE0000000 | x  (macros are not imported into Swift)
private let kMsgCanSystemSleep: UInt32 = 0xE000_0270
private let kMsgSystemWillSleep: UInt32 = 0xE000_0280
private let kMsgSystemHasPoweredOn: UInt32 = 0xE000_0300

/// Sleep/wake notifications. Callbacks run on the main queue.
enum PowerMonitor {
    private static var rootPort: io_connect_t = 0
    private static var notifier: io_object_t = 0
    private static var willSleep: (() -> Void)?
    private static var didWake: (() -> Void)?

    static func start(willSleep: @escaping () -> Void, didWake: @escaping () -> Void) -> Bool {
        self.willSleep = willSleep
        self.didWake = didWake
        var port: IONotificationPortRef?
        rootPort = IORegisterForSystemPower(nil, &port, { _, _, type, arg in
            PowerMonitor.handle(type: type, arg: arg)
        }, &notifier)
        guard rootPort != 0, let port else { return false }
        IONotificationPortSetDispatchQueue(port, DispatchQueue.main)
        return true
    }

    private static func handle(type: UInt32, arg: UnsafeMutableRawPointer?) {
        switch type {
        case kMsgCanSystemSleep:
            IOAllowPowerChange(rootPort, Int(bitPattern: arg))
        case kMsgSystemWillSleep:
            willSleep?() // block BEFORE acknowledging, so we sleep in the blocked state
            IOAllowPowerChange(rootPort, Int(bitPattern: arg))
        case kMsgSystemHasPoweredOn:
            didWake?()
        default:
            break
        }
    }
}
