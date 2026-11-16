import Foundation
import SecureNetCore

/// Unix-socket server for the menu app and CLI. Each connection: one JSON request line, one JSON response line.
final class ControlServer {
    private let path: String
    private let handler: (ControlRequest, uid_t) -> ControlResponse
    private var listenFD: Int32 = -1

    init(path: String, handler: @escaping (ControlRequest, uid_t) -> ControlResponse) {
        self.path = path
        self.handler = handler
    }

    func start() throws {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw IPCError.system("socket", errno) }
        var addr = try UnixSocket.address(path)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { close(fd); throw IPCError.system("bind \(path)", errno) }
        chmod(path, 0o666) // any local user may connect; permissions are checked per request
        guard listen(fd, 16) == 0 else { close(fd); throw IPCError.system("listen", errno) }
        listenFD = fd
        Thread { [self] in acceptLoop() }.start()
    }

    private func acceptLoop() {
        while true {
            let c = accept(listenFD, nil, nil)
            if c < 0 {
                if errno != EINTR { usleep(100_000) }
                continue
            }
            DispatchQueue.global().async { self.serve(c) }
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        UnixSocket.configure(fd, timeout: 5)
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return }

        let response: ControlResponse
        if uid != 0 && uid < 501 {
            // Only root and real (login) users; not system service accounts.
            response = .failure("permission denied")
        } else if let line = try? UnixSocket.readLine(fd, max: 8192),
                  let req = try? JSONDecoder().decode(ControlRequest.self, from: line) {
            response = DispatchQueue.main.sync { handler(req, uid) }
        } else {
            response = .failure("bad request")
        }
        guard var data = try? JSONEncoder().encode(response) else { return }
        data.append(0x0A)
        try? UnixSocket.writeAll(fd, data)
    }
}
