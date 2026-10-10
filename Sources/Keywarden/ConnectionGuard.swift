import CoreServices
import Foundation

/// Watches the browsers' native-messaging folders and takes back a connection another app has
/// replaced, such as Bitwarden Desktop registering its own host each time it launches.
///
/// If some app keeps rewriting a browser's host, Keywarden stops reclaiming that browser after
/// `limit` takebacks within `window`, instead of trading writes with it forever.
final class ConnectionGuard: @unchecked Sendable {
    static let manifestName = "\(BrowserRegistry.hostName).json"
    private let folders: [URL]
    private let latency: TimeInterval
    private let limit: Int
    private let window: TimeInterval
    private let reclaim: @Sendable (Set<String>) -> [String]
    private let now: @Sendable () -> Date
    private let queue = DispatchQueue(label: "xyz.kuvshynov.Keywarden.ConnectionGuard")
    private var stream: FSEventStreamRef?
    /// When each browser was taken back, within the last `window`. Touched only on `queue`.
    private var history: [String: [Date]] = [:]
    /// Called on the guard's queue with the browsers just taken back.
    var onReclaim: (@Sendable ([String]) -> Void)?

    init(folders: [URL] = Installer.manifestFolders, latency: TimeInterval = 1, limit: Int = 3,
         window: TimeInterval = 600, now: @escaping @Sendable () -> Date = Date.init,
         reclaim: @escaping @Sendable (Set<String>) -> [String] = Installer.reclaim(skipping:)) {
        self.folders = folders
        self.latency = latency
        self.limit = limit
        self.window = window
        self.now = now
        self.reclaim = reclaim
    }

    deinit { stop() }

    /// Checks once now (another app may have registered while Keywarden wasn't running), then on
    /// every change in the folders. Folders that don't exist yet are watched too.
    func start() {
        queue.async { self.check() }
        guard stream == nil else { return }
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        // Other apps' hosts share these folders; only a change to the Bitwarden host is checked.
        let callback: FSEventStreamCallback = { _, info, count, paths, _, _ in
            guard let info else { return }
            let names = Unmanaged<CFArray>.fromOpaque(paths).takeUnretainedValue() as? [String] ?? []
            guard names.prefix(count).contains(where: {
                URL(fileURLWithPath: $0).lastPathComponent.caseInsensitiveCompare(ConnectionGuard.manifestName) == .orderedSame
            }) else { return }
            Unmanaged<ConnectionGuard>.fromOpaque(info).takeUnretainedValue().check()
        }
        guard let stream = FSEventStreamCreate(
            nil, callback, &context, folders.map(\.path) as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow), latency,
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer
                                     | kFSEventStreamCreateFlagUseCFTypes)
        ) else { return }
        FSEventStreamSetDispatchQueue(stream, queue)
        FSEventStreamStart(stream)
        self.stream = stream
    }

    func stop() {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    /// Runs on `queue`.
    private func check() {
        let cutoff = now().addingTimeInterval(-window)
        history = history.compactMapValues { dates in
            let recent = dates.filter { $0 > cutoff }
            return recent.isEmpty ? nil : recent
        }
        let exhausted = Set(history.filter { $0.value.count >= limit }.keys)
        let reclaimed = reclaim(exhausted)
        guard !reclaimed.isEmpty else { return }
        for id in reclaimed {
            history[id, default: []].append(now())
            if history[id]?.count == limit {
                installLog.error("Another app keeps replacing \(id, privacy: .public)’s host; not reconnecting it for now")
            }
        }
        onReclaim?(reclaimed)
    }

    /// Checks now, after any check already queued, and returns once done.
    func checkNow() { queue.sync(execute: check) }
}
