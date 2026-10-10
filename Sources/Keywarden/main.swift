import Foundation

private enum LaunchError: Error { case invalidArguments }

enum LaunchCommand: Equatable {
    case app, install(replace: Bool), uninstall, quit

    static func parse(_ arguments: ArraySlice<String>) -> Self? {
        var index = arguments.startIndex
        var command = Self.app
        var hasCommand = false
        while index < arguments.endIndex {
            let argument = arguments[index]
            // Foundation consumes single-dash key/value pairs as launch-time UserDefaults.
            // They remain in CommandLine.arguments, including macOS's language overrides.
            if argument.hasPrefix("-"), !argument.hasPrefix("--"), argument.count > 1 {
                let valueIndex = arguments.index(after: index)
                guard valueIndex < arguments.endIndex,
                      !arguments[valueIndex].hasPrefix("--") else { return nil }
                index = arguments.index(after: valueIndex)
                continue
            }
            if argument == "--replace" {
                guard hasCommand, command == .install(replace: false) else { return nil }
                command = .install(replace: true)
            } else {
                guard !hasCommand else { return nil }
                switch argument {
                case "--background": command = .app
                case "install": command = .install(replace: false)
                case "uninstall": command = .uninstall
                case "--quit": command = .quit
                default: return nil
                }
                hasCommand = true
            }
            index = arguments.index(after: index)
        }
        return command
    }
}

@MainActor
private func launch() throws {
    let arguments = CommandLine.arguments.dropFirst()
    if ProcessInfo.processInfo.environment["XCTestSessionIdentifier"] != nil {
        KeywardenApp.main()
        return
    }
    guard let command = LaunchCommand.parse(arguments) else {
        FileHandle.standardError.write(Data("Usage: keywarden install [--replace] | uninstall | --quit\n".utf8))
        throw LaunchError.invalidArguments
    }
    switch command {
    case .app: KeywardenApp.main()
    case .install(let replace): try Installer.install(replace: replace)
    case .uninstall: try Installer.uninstall()
    case .quit:
        // Asks a running copy to lock and quit, for install scripts. Any same-user process could
        // already terminate the app, so this grants nothing new.
        DistributedNotificationCenter.default().postNotificationName(
            AppDelegate.quitNotification, object: nil, userInfo: nil, deliverImmediately: true)
        // Delivery goes through distnoted asynchronously; don't exit before it leaves.
        RunLoop.current.run(until: Date().addingTimeInterval(0.5))
    }
}

#if DEBUG
nonisolated(unsafe) private var crashFrames: UnsafeMutablePointer<UnsafeMutableRawPointer?>!
nonisolated(unsafe) private var crashFrameCapacity: Int32 = 0
// UI tests capture the app's stderr (Swift traps, Rust `[keywarden]` logs) in a file they attach.
if let log = ProcessInfo.processInfo.environment["BW_UI_TEST_LOG"], log.hasPrefix("/") {
    freopen(log, "a", stderr)
    setvbuf(stderr, nil, _IONBF, 0)
    // Crash reports are rate-limited during test runs; write the faulting stack ourselves, on an
    // alternate stack so a stack overflow can still be reported.
    let size = 1 << 20
    var alternate = stack_t(ss_sp: UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 16),
                            ss_size: size, ss_flags: 0)
    sigaltstack(&alternate, nil)
    // Preallocated so the handler can walk a stack that overflowed; the outermost frames show
    // what started a recursion.
    let capacity = 200_000
    crashFrames = UnsafeMutablePointer<UnsafeMutableRawPointer?>.allocate(capacity: capacity)
    crashFrameCapacity = Int32(capacity)
    for number in [SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE] {
        var action = sigaction()
        action.__sigaction_u.__sa_handler = { number in
            let count = backtrace(crashFrames, crashFrameCapacity)
            let header = "\n*** signal \(number), \(count) frames; innermost 60:\n"
            _ = header.withCString { write(STDERR_FILENO, $0, strlen($0)) }
            backtrace_symbols_fd(crashFrames, min(count, 60), STDERR_FILENO)
            _ = "*** outermost 80:\n".withCString { write(STDERR_FILENO, $0, strlen($0)) }
            if count > 80 { backtrace_symbols_fd(crashFrames! + Int(count - 80), 80, STDERR_FILENO) }
            Darwin.signal(number, SIG_DFL)
            raise(number)
        }
        action.sa_flags = SA_ONSTACK
        sigaction(number, &action, nil)
    }
}
#endif

do {
    try launch()
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
