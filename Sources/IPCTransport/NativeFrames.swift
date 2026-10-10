import Darwin
import Foundation

enum TransportFailure: Error {
    case identity, insecurePath, disconnected, invalidFrame, unavailable
}

enum NativeFrames {
    static let maximum = 1_048_576
    static var directory: String { "/tmp/xyz.kuvshynov.Keywarden-\(geteuid())" }
    static var socketPath: String { directory + "/ipc.sock" }

    private static func address(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw TransportFailure.insecurePath }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address) { raw in
            for (index, byte) in bytes.enumerated() { raw[2 + index] = UInt8(bitPattern: byte) }
        }
        return address
    }

    private static func socketFD() throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw TransportFailure.unavailable }
        var enabled: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            close(fd)
            throw TransportFailure.unavailable
        }
        return fd
    }

    private static func withAddress<T>(_ path: String, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) throws -> T {
        var value = try address(path)
        return withUnsafePointer(to: &value) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }

    private static func verifyDirectory() throws {
        var info = stat()
        guard lstat(directory, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            throw TransportFailure.insecurePath
        }
    }

    static func connect() throws -> Int32 {
        try verifyDirectory()
        var info = stat()
        guard lstat(socketPath, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o600 else {
            throw TransportFailure.insecurePath
        }
        let fd = try socketFD()
        do {
            guard try withAddress(socketPath, { Darwin.connect(fd, $0, $1) }) == 0 else {
                throw TransportFailure.unavailable
            }
            return fd
        } catch { close(fd); throw error }
    }

    private static func readFully(_ fd: Int32, _ data: UnsafeMutableRawPointer, _ count: Int, eof: Bool) throws -> Bool {
        var offset = 0
        while offset < count {
            let n = Darwin.read(fd, data.advanced(by: offset), count - offset)
            if n == 0 {
                if offset == 0 && eof { return false }
                throw TransportFailure.invalidFrame
            }
            if n < 0 {
                if errno == EINTR { continue }
                throw TransportFailure.disconnected
            }
            offset += n
        }
        return true
    }

    private static func writeFully(_ fd: Int32, _ data: UnsafeRawPointer, _ count: Int) throws {
        var offset = 0
        while offset < count {
            let n = Darwin.write(fd, data.advanced(by: offset), count - offset)
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw TransportFailure.disconnected }
            offset += n
        }
    }

    /// Copies a complete frame, and never buffers more than one bounded frame per direction.
    static func copyFrame(from source: Int32, to destination: Int32) throws -> Bool {
        var header = [UInt8](repeating: 0, count: 4)
        let present = try header.withUnsafeMutableBytes { try readFully(source, $0.baseAddress!, 4, eof: true) }
        if !present { return false }
        let size = header.enumerated().reduce(UInt32(0)) { $0 | (UInt32($1.element) << ($1.offset * 8)) }
        guard size > 0, size <= maximum else { throw TransportFailure.invalidFrame }
        var payload = [UInt8](repeating: 0, count: Int(size))
        try payload.withUnsafeMutableBytes { _ = try readFully(source, $0.baseAddress!, Int(size), eof: false) }
        try header.withUnsafeBytes { try writeFully(destination, $0.baseAddress!, 4) }
        try payload.withUnsafeBytes { try writeFully(destination, $0.baseAddress!, Int(size)) }
        return true
    }
}

/// The lock stays owned until this object is released. Only its owner may unlink a stale socket.
final class NativeSocketListener: @unchecked Sendable {
    let descriptor: Int32
    private let lock: Int32
    private let lifecycle = NSLock()
    private var stopped = false

    init() throws {
        let path = NativeFrames.directory
        if mkdir(path, 0o700) != 0 && errno != EEXIST { throw TransportFailure.insecurePath }
        var dirInfo = stat()
        guard lstat(path, &dirInfo) == 0,
              dirInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              dirInfo.st_uid == geteuid(), dirInfo.st_mode & 0o777 == 0o700 else {
            throw TransportFailure.insecurePath
        }
        let dirFD = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard dirFD >= 0 else { throw TransportFailure.insecurePath }
        defer { close(dirFD) }
        let lockFD = openat(dirFD, "ipc.lock", O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard lockFD >= 0 else { throw TransportFailure.insecurePath }
        var info = stat()
        guard fstat(lockFD, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_mode & 0o777 == 0o600,
              flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
            close(lockFD)
            throw TransportFailure.unavailable
        }
        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { close(lockFD); throw TransportFailure.unavailable }
        var enabled: Int32 = 1
        _ = setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size))
        do {
            if lstat(NativeFrames.socketPath, &info) == 0 {
                guard info.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK), info.st_uid == geteuid() else {
                    throw TransportFailure.insecurePath
                }
                // The lock is ours; nevertheless, never unlink a live listener.
                if let existing = try? NativeFrames.connect() {
                    close(existing)
                    throw TransportFailure.unavailable
                }
                guard unlink(NativeFrames.socketPath) == 0 else { throw TransportFailure.insecurePath }
            } else if errno != ENOENT { throw TransportFailure.insecurePath }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let bytes = Array(NativeFrames.socketPath.utf8CString)
            guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw TransportFailure.insecurePath }
            withUnsafeMutableBytes(of: &address) { raw in
                for (index, byte) in bytes.enumerated() { raw[2 + index] = UInt8(bitPattern: byte) }
            }
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bound == 0, chmod(NativeFrames.socketPath, 0o600) == 0,
                  listen(socketFD, 16) == 0 else { throw TransportFailure.unavailable }
            descriptor = socketFD
            lock = lockFD
        } catch {
            close(socketFD)
            close(lockFD)
            throw error
        }
    }
    func stop() {
        lifecycle.lock()
        defer { lifecycle.unlock() }
        if stopped { return }
        stopped = true
        _ = shutdown(descriptor, SHUT_RDWR)
        close(descriptor)
        _ = unlink(NativeFrames.socketPath)
        close(lock)
    }

    deinit { stop() }
    func acceptConnection() throws -> Int32 {
        let fd = Darwin.accept(descriptor, nil, nil)
        guard fd >= 0 else { throw TransportFailure.disconnected }
        return fd
    }
}
