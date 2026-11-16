import Foundation
import SecureNetCore

setvbuf(stdout, nil, _IOLBF, 0)
setvbuf(stderr, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

private let timestampFormatter = ISO8601DateFormatter()

func log(_ message: String) {
    print("\(timestampFormatter.string(from: Date())) \(message)")
}

guard geteuid() == 0 else {
    FileHandle.standardError.write(Data("securenetd must run as root (it is started by launchd).\n".utf8))
    exit(1)
}

let daemon = Daemon()
daemon.start()
dispatchMain()
