import AppKit

@MainActor
enum SecureClipboard {
    /// Supplies the "Clear clipboard" and "Minimize when copying" preferences.
    static weak var settings: AppSettings?
    private static var ownedChangeCount: Int?
    private static var clearTask: Task<Void, Never>?
    /// Clipboard managers that follow nspasteboard.org skip these items.
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    static func copy(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(value, forType: .string) else { return }
        pasteboard.setData(Data(), forType: concealed)
        pasteboard.setData(Data(), forType: transient)
        ownedChangeCount = pasteboard.changeCount
        clearTask?.cancel()
        let delay = settings?.clearClipboardSeconds ?? 60
        if delay > 0 {
            clearTask = Task {
                try? await Task.sleep(for: .seconds(delay))
                if !Task.isCancelled { clearIfOwned() }
            }
        }
        if settings?.minimizeOnCopy == true {
            // Hand focus back to the app the value is being pasted into.
            NSApp.hide(nil)
        }
    }

    static func clearIfOwned() {
        let pasteboard = NSPasteboard.general
        guard let ownedChangeCount, pasteboard.changeCount == ownedChangeCount else { return }
        pasteboard.clearContents()
        self.ownedChangeCount = nil
    }
}
