import AppKit
import Darwin
import Foundation
import os

private let log = Logger(subsystem: "xyz.kuvshynov.Keywarden", category: "helper")

private final class ParentGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var failed = false

    var isValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !failed
    }

    func invalidate() {
        lock.lock()
        failed = true
        lock.unlock()
    }
}

private func executableURL() throws -> URL {
    var capacity: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &capacity)
    guard capacity > 0, capacity <= 4096 else { throw TransportFailure.identity }
    var path = [CChar](repeating: 0, count: Int(capacity))
    guard _NSGetExecutablePath(&path, &capacity) == 0 else { throw TransportFailure.identity }
    guard let end = path.firstIndex(of: 0),
          let resolved = String(bytes: path[..<end].map(UInt8.init(bitPattern:)), encoding: .utf8) else {
        throw TransportFailure.identity
    }
    return URL(fileURLWithPath: resolved).resolvingSymlinksInPath()
}


private func run() throws {
    let arguments = CommandLine.arguments
    let home = FileManager.default.homeDirectoryForCurrentUser
    let candidates = BrowserRegistry.candidates(arguments: arguments, home: home, pins: BrowserPins.load(home: home))
    guard !candidates.isEmpty else {
        log.error("Refused launch: arguments match no connected browser")
        throw TransportFailure.identity
    }

    let executable = try executableURL()
    guard executable.lastPathComponent == "keywarden-native-host",
          executable.deletingLastPathComponent().lastPathComponent == "Helpers",
          executable.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent == "Contents" else {
        throw TransportFailure.identity
    }
    let application = executable.deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()
    guard application.pathExtension == "app" else { throw TransportFailure.identity }
    let team = try PeerIdentity.currentTeam()
    try PeerIdentity.verifySignedApp(at: application, team: team)
    let parent = getppid()
    let requirement: String
    do {
        requirement = try PeerIdentity.verifyParent(parent, requirements: candidates.flatMap(\.requirements))
    } catch {
        log.error("Refused launch by \(PeerIdentity.describe(parent), privacy: .public); expected \(candidates.map(\.browser.name).joined(separator: " or "), privacy: .public)")
        throw error
    }
    log.info("Launched by \(candidates.map(\.browser.name).joined(separator: "/"), privacy: .public)")

    let deadline = ProcessInfo.processInfo.systemUptime + 5
    var fd: Int32 = -1
    var launchRequested = false
    while ProcessInfo.processInfo.systemUptime < deadline {
        if let connected = try? NativeFrames.connect() {
            fd = connected
            break
        }
        // An already running app may still be starting its listener. Never reopen its vault.
        if !launchRequested && NSRunningApplication.runningApplications(withBundleIdentifier: PeerIdentity.appID).isEmpty {
            let configuration = NSWorkspace.OpenConfiguration()
            configuration.activates = false
            configuration.addsToRecentItems = false
            configuration.arguments = ["--background"]
            NSWorkspace.shared.openApplication(at: application, configuration: configuration) { _, _ in }
            launchRequested = true
        }
        usleep(100_000)
    }
    guard fd >= 0 else { throw TransportFailure.unavailable }
    defer { close(fd) }
    try PeerIdentity.verifyPeer(fd, identifier: PeerIdentity.appID, team: team)
    guard getppid() == parent else { throw TransportFailure.identity }
    _ = try PeerIdentity.verifyParent(parent, requirements: [requirement])
    let guardState = ParentGuard()
    let monitor = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .userInitiated))
    monitor.schedule(deadline: .now() + 1, repeating: 1)
    monitor.setEventHandler {
        guard getppid() == parent,
              (try? PeerIdentity.verifyParent(parent, requirements: [requirement])) != nil else {
            guardState.invalidate()
            _ = shutdown(fd, SHUT_RDWR)
            return
        }
    }
    monitor.resume()
    defer { monitor.cancel() }


    // stdout is exclusively native-messaging protocol bytes; no browser payload is decoded here.
    let browserInput = STDIN_FILENO
    let browserOutput = STDOUT_FILENO
    let socket = fd
    DispatchQueue.global(qos: .userInitiated).async {
        while (try? NativeFrames.copyFrame(from: browserInput, to: socket)) == true {}
        _ = shutdown(socket, SHUT_WR)
    }
    while try NativeFrames.copyFrame(from: socket, to: browserOutput) {}
    _ = shutdown(socket, SHUT_RD)
    guard guardState.isValid else { throw TransportFailure.identity }
}

do {
    try run()
    exit(EXIT_SUCCESS)
} catch {
    // Do not put private request data or identities on the native-messaging stdout.
    fputs("Keywarden native host connection refused\n", stderr)
    exit(EXIT_FAILURE)
}
