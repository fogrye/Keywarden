import AppKit
import Observation

/// Finds the installed browsers and their connections off the main thread. The last result is
/// kept, so the Browsers tab shows it at once while a fresh scan runs in the background.
@MainActor @Observable
final class BrowserScanner {
    static let shared = BrowserScanner()

    private(set) var scan: Installer.Scan?
    private(set) var isScanning = false
    @ObservationIgnored private var scanAgain = false
    @ObservationIgnored private var icons: [String: NSImage] = [:]
    @ObservationIgnored private let perform: @Sendable () -> Installer.Scan

    init(perform: @escaping @Sendable () -> Installer.Scan = Installer.scan) {
        self.perform = perform
    }

    /// Starts a scan. One asked for while another runs follows it, so a change made meanwhile shows.
    func refresh() {
        guard !isScanning else { scanAgain = true; return }
        isScanning = true
        let perform = perform
        Task {
            let result = await Task.detached(priority: .userInitiated) { perform() }.value
            if result != scan { scan = result }
            isScanning = false
            if scanAgain {
                scanAgain = false
                refresh()
            }
        }
    }

    /// Starts a scan unless one is already running, for when the tab appears or the app comes back.
    func refreshIfIdle() {
        if !isScanning { refresh() }
    }

    /// Runs a connection change off the main thread, then rescans. Returns the error to show, if any.
    func change(_ operation: @escaping @Sendable () throws -> Void) async -> String? {
        let failure = await Task.detached(priority: .userInitiated) { () -> String? in
            do { try operation(); return nil } catch { return error.localizedDescription }
        }.value
        refresh()
        return failure
    }

    func icon(for app: URL) -> NSImage {
        if let icon = icons[app.path] { return icon }
        let icon = NSWorkspace.shared.icon(forFile: app.path)
        icons[app.path] = icon
        return icon
    }
}
