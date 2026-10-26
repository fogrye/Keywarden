import AppKit
import Darwin
import SwiftUI

struct KeywardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("Keywarden", id: WindowID.vault) {
            RootView(model: delegate.model, autoTouchID: delegate.settings.autoTouchID)
                .onAppear { delegate.vaultWindowOpened() }
                .onDisappear { delegate.vaultWindowClosed() }
        }
        .defaultSize(width: 1080, height: 660)
        .commands { VaultCommands(model: delegate.model, delegate: delegate) }
        // In menu-bar mode the delegate decides whether a launch shows the window; otherwise
        // Keywarden behaves like a regular app and opens it.
        .defaultLaunchBehavior(delegate.settings.keepRunningInBackground ? .suppressed : .presented)
        .restorationBehavior(.disabled)
        .windowToolbarStyle(.unified)

        Window("Password Generator", id: WindowID.generator) {
            GeneratorView()
        }
        .windowResizability(.contentSize)
        // Floats above other apps' windows, so a generated value can be copied into any form.
        .windowLevel(.floating)
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)

        Settings {
            SettingsView(settings: delegate.settings, model: delegate.model)
        }

        MenuBarExtra(isInserted: Bindable(delegate.settings).showsMenuBarIcon) {
            StatusMenu(model: delegate.model)
        } label: {
            StatusIcon(model: delegate.model, delegate: delegate)
        }
    }
}

enum WindowID {
    static let vault = "vault"
    static let generator = "generator"
}

/// The menu bar icon. It is always alive, so it also hands the scene's window opener to AppKit code.
private struct StatusIcon: View {
    let model: VaultModel
    let delegate: AppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(model.phase == .unlocked ? "MenuBarUnlocked" : "MenuBarLocked")
            .accessibilityLabel("Keywarden")
            .onAppear { delegate.capture(openWindow) }
    }
}

private struct StatusMenu: View {
    let model: VaultModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Text(statusText)
        Divider()
        Button("Open Vault") {
            WindowFront.present(WindowID.vault) { openWindow(id: WindowID.vault) }
        }
        .keyboardShortcut("o")
        Button("Password Generator") {
            WindowFront.present(WindowID.generator) { openWindow(id: WindowID.generator) }
        }
        .keyboardShortcut("g")
        if model.phase == .unlocked {
            Button("Lock Vault") { Task { await model.lock() } }
                .keyboardShortcut("l")
        }
        Divider()
        Button("Settings…") {
            WindowFront.present(WindowFront.settings) { openSettings() }
        }
        .keyboardShortcut(",")
        Divider()
        Button("Quit Keywarden") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var statusText: String {
        switch model.phase {
        case .loading: String(localized: "Starting…")
        case .loggedOut: String(localized: "Signed out")
        case .locked: String(localized: "Locked · \(model.email)")
        case .unlocked: String(localized: "Unlocked · \(model.email)")
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let settings = AppSettings()
    let model = VaultModel()
    private(set) var openVault: (() -> Void)?
    private var autoLock: AutoLockController?
    private var activityMonitor: Any?
    private var listener: NativeSocketListener?
    private var connectionGuard: ConnectionGuard?
    private var terminating = false
    private static let showVaultNotification = Notification.Name("xyz.kuvshynov.Keywarden.showVault")
    nonisolated static let quitNotification = Notification.Name("xyz.kuvshynov.Keywarden.quit")

    #if DEBUG
    /// The running app's delegate, for tests that drive its main menu and reopen handling.
    static private(set) weak var current: AppDelegate?
    #endif

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if DEBUG
        Self.current = self
        #endif
        guard bindListener() else { return }
        Installer.migrate()
        keepBrowserConnections()
        // Earlier builds loaded website icons through the shared cache, which kept the vault's
        // website names on disk. Icons are now held in memory only (`WebsiteIcons`).
        URLCache.shared.removeAllCachedResponses()
        URLCache.shared = URLCache(memoryCapacity: 0, diskCapacity: 0)
        SecureClipboard.settings = settings
        model.settings = settings
        applyActivationPolicy()
        observeWindows()
        settings.onAppearanceChange = { [weak self] in self?.applyActivationPolicy() }
        let autoLock = AutoLockController(settings: settings) { [weak self] in
            guard let self else { return }
            Task {
                switch self.settings.timeoutAction {
                case .lock: await self.model.lock()
                case .logOut: if self.model.phase != .loggedOut { await self.model.logout() }
                }
            }
        }
        self.autoLock = autoLock
        model.onPhaseChange = { [weak self] phase in self?.autoLock?.setUnlocked(phase == .unlocked) }
        autoLock.setUnlocked(model.phase == .unlocked)
        // Firefox requests are answered only once the account identity and preferences are loaded,
        // so a cold launch by the native host never reports "not enabled" by mistake.
        if model.isReady { acceptConnections() } else { model.onReady = { [weak self] in self?.acceptConnections() } }
        installActivityMonitor()
        DistributedNotificationCenter.default().addObserver(
            forName: Self.showVaultNotification, object: nil, queue: .main
        ) { [weak self] _ in MainActor.assumeIsolated { self?.openVault?() } }
        DistributedNotificationCenter.default().addObserver(
            forName: Self.quitNotification, object: nil, queue: .main
        ) { _ in
            // Not inside this main-queue block: termination waits for a main-actor task to lock
            // the vault, which could never run while this block still occupies the main queue.
            RunLoop.main.perform { MainActor.assumeIsolated { NSApp.terminate(nil) } }
        }
        // Launches by Firefox's native host or as a login item stay in the menu bar.
        if settings.keepRunningInBackground,
           !CommandLine.arguments.contains("--background") && !Self.launchedAsLoginItem() {
            DispatchQueue.main.async { [weak self] in self?.openVault?() }
        }
    }

    /// Keeps a scene's window opener for AppKit code. The menu bar icon and the main menu both
    /// provide one, so the vault can be opened whichever icon is shown.
    /// Every way in (a reopen from Spotlight, Raycast or the Dock, a second launch, a launch) lands
    /// ready to type a search, even when the vault was already in front.
    func capture(_ openWindow: OpenWindowAction) {
        guard openVault == nil else { return }
        openVault = { [model] in
            WindowFront.present(WindowID.vault) { openWindow(id: WindowID.vault) }
            if model.phase == .unlocked, model.editor == nil { model.focusRequest = .search }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard let openVault else { return true } // Let SwiftUI reopen the window itself.
        openVault()
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !settings.keepRunningInBackground
    }

    /// With the Dock icon on, Keywarden is a regular Dock app. With the menu bar icon alone it is an
    /// accessory app (no Dock icon, no menu bar) until one of its windows opens; then it becomes a
    /// regular app so File, Edit, View and Help work as usual.
    private func applyActivationPolicy() {
        let windowOpen = NSApp.windows.contains {
            $0.isVisible && $0.styleMask.contains(.titled) && !($0 is NSPanel) && $0 !== closingWindow
        }
        let policy: NSApplication.ActivationPolicy = settings.iconPlacement.showsDockIcon || windowOpen ? .regular : .accessory
        guard NSApp.activationPolicy() != policy else { return }
        NSApp.setActivationPolicy(policy)
        if policy == .regular { NSApp.activate() }
    }

    /// Takes back browser connections another app replaces. Only the copy in Applications does, so
    /// tests and development builds never touch the real browsers' registrations.
    private func keepBrowserConnections() {
        let environment = ProcessInfo.processInfo.environment
        guard Installer.isInstalled, ["XCTestSessionIdentifier", "BW_TEST_NAMESPACE", "BW_UI_TEST_NAMESPACE"]
            .allSatisfy({ environment[$0] == nil }) else { return }
        let connectionGuard = ConnectionGuard()
        connectionGuard.onReclaim = { _ in Task { @MainActor in BrowserScanner.shared.refresh() } }
        connectionGuard.start()
        self.connectionGuard = connectionGuard
    }

    private weak var closingWindow: NSWindow?

    private func observeWindows() {
        let center = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification] {
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.applyActivationPolicy() }
            }
        }
        center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { [weak self] note in
            let window = note.object as? NSWindow
            MainActor.assumeIsolated {
                self?.closingWindow = window
                self?.applyActivationPolicy()
                self?.closingWindow = nil
            }
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        terminating = true
        autoLock?.setUnlocked(false)
        Task {
            await model.lock()
            listener?.stop()
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    func vaultWindowOpened() {
        autoLock?.recordActivity()
        model.refreshIfStale()
    }

    func vaultWindowClosed() {
        guard settings.lockOnWindowClose, !terminating else { return }
        Task { await model.lock() }
    }

    // MARK: Firefox listener

    /// Binds the per-user socket. A second instance hands off to the running one and quits.
    private func bindListener() -> Bool {
        do {
            listener = try NativeSocketListener()
            return true
        } catch TransportFailure.unavailable {
            // Hand focus to the running copy so the window it shows can come to the front.
            if let running = NSRunningApplication.runningApplications(withBundleIdentifier: PeerIdentity.appID)
                .first(where: { $0 != .current }) {
                NSApp.yieldActivation(to: running)
            }
            DistributedNotificationCenter.default().postNotificationName(
                Self.showVaultNotification, object: nil, userInfo: nil, deliverImmediately: true)
            NSApp.terminate(nil)
            return false
        } catch {
            // Invalid local socket/signing state must not start an alternate account authority.
            NSApp.terminate(nil)
            return false
        }
    }

    private func acceptConnections() {
        guard let listener, let team = try? PeerIdentity.currentTeam() else { return }
        let capacity = DispatchSemaphore(value: 16)
        DispatchQueue.global(qos: .userInitiated).async {
            var connectionID: UInt64 = 1
            while let fd = try? listener.acceptConnection() {
                do {
                    let helper = try PeerIdentity.verifyPeer(fd, identifier: PeerIdentity.helperID, team: team)
                    guard capacity.wait(timeout: .now()) == .success else {
                        Darwin.close(fd)
                        continue
                    }
                    let id = connectionID
                    connectionID &+= 1
                    BiometricCoordinator.shared.register(connection: id, requester: Self.launchingApp(of: helper))
                    DispatchQueue.global(qos: .userInitiated).async {
                        _ = bwIpcRunFD(fd, id) // Rust takes ownership of the authenticated descriptor.
                        capacity.signal()
                    }
                } catch {
                    Darwin.close(fd)
                }
            }
        }
    }

    /// The name of the app that launched the helper (the browser), for the Touch ID prompt.
    /// The helper has already verified its parent's signature; this is only for display.
    private nonisolated static func launchingApp(of helper: pid_t) -> String {
        var pid = helper
        for _ in 0..<4 {
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.size
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
            guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { break }
            pid = info.kp_eproc.e_ppid
            guard pid > 1 else { break }
            if let name = NSRunningApplication(processIdentifier: pid)?.localizedName, !name.isEmpty {
                return name
            }
        }
        return String(localized: "an unidentified app")
    }

    // MARK: Activity

    private func installActivityMonitor() {
        activityMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown, .scrollWheel]
        ) { [weak self] event in
            let inWindow = event.window != nil
            MainActor.assumeIsolated {
                if inWindow { self?.autoLock?.recordActivity() }
            }
            return event
        }
    }

    private static func launchedAsLoginItem() -> Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventID == kAEOpenApplication
            && event.paramDescriptor(forKeyword: keyAEPropData)?.enumCodeValue == keyAELaunchedAsLogInItem
    }
}

@_silgen_name("bw_ipc_run_fd")
private func bwIpcRunFD(_ fd: Int32, _ connectionID: UInt64) -> Int32

/// Menu bar commands while a Keywarden window is focused.
private struct VaultCommands: Commands {
    let model: VaultModel
    let delegate: AppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        // The main menu is built at launch, so the Dock icon can open the vault without the
        // menu bar icon.
        let _ = delegate.capture(openWindow)
        CommandGroup(replacing: .newItem) {
            Button("New Login") { open(.login) }
                .keyboardShortcut("n")
            Button("New Secure Note") { open(.note) }
            Button("New Card") { open(.card) }
            Button("New Identity") { open(.identity) }
            Button("New Bank Account") { open(.bankAccount) }
            Button("New Driver’s License") { open(.driversLicense) }
            Button("New Passport") { open(.passport) }
            Divider()
            Button("New Folder…") {
                openWindow(id: WindowID.vault)
                model.newFolderRequested = true
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
            .disabled(model.phase != .unlocked)
            Button("Rename Folder…") { model.renamingFolder = shownFolder }
                .disabled(shownFolder == nil)
            Button("Delete Folder…") { model.deletingFolder = shownFolder }
                .disabled(shownFolder == nil)
        }
        CommandGroup(replacing: .importExport) {
            Button("Import Data…") {
                openWindow(id: WindowID.vault)
                model.importRequested = true
            }
            .keyboardShortcut("i", modifiers: [.command, .shift])
            .disabled(model.phase != .unlocked)
            Button("Export Vault…") {
                openWindow(id: WindowID.vault)
                model.exportRequested = true
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])
            .disabled(model.phase != .unlocked)
        }
        CommandGroup(after: .textEditing) {
            Button("Search") {
                openWindow(id: WindowID.vault)
                model.focusRequest = .search
            }
            .keyboardShortcut("f")
            .disabled(model.phase != .unlocked)
        }
        SidebarCommands()
        CommandGroup(after: .sidebar) {
            Divider()
            destination("All Items", .all, "1")
            destination("Favorites", .favorites, "2")
            destination("Archive", .archive, "3")
            destination("Trash", .trash, "4")
        }
        CommandMenu("Item") { ItemMenu(model: model) }
        CommandMenu("Vault") {
            Button("Sync") { Task { await model.sync() } }
                .keyboardShortcut("r")
                .disabled(model.phase != .unlocked || model.isSyncing)
            Button("Lock Vault") { Task { await model.lock() } }
                .keyboardShortcut("l")
                .disabled(model.phase != .unlocked)
            Divider()
            Button("Password Generator") { openWindow(id: WindowID.generator) }
                .keyboardShortcut("g")
        }
    }

    private func open(_ type: VaultItemType) {
        openWindow(id: WindowID.vault)
        model.beginNewItem(type)
    }

    /// The folder the sidebar shows, for Rename Folder… and Delete Folder….
    private var shownFolder: VaultFolder? {
        guard model.phase == .unlocked, case .folder(let id) = model.destination else { return nil }
        return model.folders.first { $0.id == id }
    }

    /// Shows a list and moves focus to it, ready for ↓/↑. (A new list drops the old one's focus.)
    private func destination(_ title: LocalizedStringKey, _ place: SidebarItem, _ key: KeyEquivalent) -> some View {
        Button(title) {
            openWindow(id: WindowID.vault)
            model.show(place)
            if model.editor == nil { model.focusRequest = .list }
        }
            .keyboardShortcut(key)
            .disabled(model.phase != .unlocked)
    }
}

/// Actions on the selected item, so none needs the mouse: the list's context menu, the detail's
/// toolbar and copy buttons. Copy shortcuts are Bitwarden Desktop's (⌘U, ⌘P, ⌘T). None uses a key
/// that edits text, because the search field usually has focus and menu shortcuts reach the menu first.
private struct ItemMenu: View {
    let model: VaultModel

    var body: some View {
        let detail = model.shownDetail
        let fields = detail?.copyableFields ?? []
        let item = model.phase == .unlocked && model.editor == nil ? model.selectedSummary : nil
        copy("Copy Username", CopyableField.username, "u", fields)
        copy("Copy Password", CopyableField.password, "p", fields)
        copy("Copy Verification Code", CopyableField.totp, "t", fields)
        Menu("Copy") {
            ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                let button = Button(field.label) { Task { await model.copy(field.id) } }
                if index < 9 {
                    button.keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: [.command, .option])
                } else {
                    button
                }
            }
        }
        .disabled(fields.isEmpty)
        Button("Open Website") {
            Task {
                guard let url = model.shownDetail?.launchURL, await model.passReprompt() else { return }
                NSWorkspace.shared.open(url)
            }
        }
        .keyboardShortcut("o", modifiers: [.command, .shift])
        .disabled(detail?.launchURL == nil)
        Divider()
        Button("Edit") { Task { if await model.passReprompt() { model.beginEditing() } } }
            .keyboardShortcut("e")
            .disabled(!(detail.map { $0.editable && $0.deletedDate == nil } ?? false))
        Button("Clone") { Task { if await model.passReprompt() { model.beginCloning() } } }
            .keyboardShortcut("d")
            .disabled(!(detail.map { $0.deletedDate == nil && $0.item.kind != .sshKey } ?? false))
        Divider()
        if let item, item.deleted {
            Button("Restore") { Task { await model.restoreFromTrash(item.id) } }
            Button("Delete Permanently…") { model.confirmingDelete = item.id }
        } else {
            Button(item?.favorite == true ? "Remove from Favorites" : "Add to Favorites") {
                guard let item else { return }
                Task { await model.setFavorite(item.id, !item.favorite) }
            }
            .disabled(item == nil)
            Menu("Move to Folder") {
                if let item {
                    Button("No Folder") { Task { await model.move(item.id, toFolder: nil) } }
                        .disabled(item.folderId == nil)
                    ForEach(model.folders) { folder in
                        Button(folder.name) { Task { await model.move(item.id, toFolder: folder.id) } }
                            .disabled(item.folderId == folder.id)
                    }
                }
            }
            .disabled(item == nil)
            Button(item?.archived == true ? "Unarchive" : "Archive") {
                guard let item else { return }
                Task { await model.setArchived(item.id, !item.archived) }
            }
            .disabled(item == nil)
            Button("Move to Trash") {
                guard let item else { return }
                Task { await model.moveToTrash(item.id) }
            }
            .disabled(item == nil || detail?.editable == false)
        }
    }

    private func copy(_ title: LocalizedStringKey, _ id: String, _ key: KeyEquivalent,
                      _ fields: [CopyableField]) -> some View {
        Button(title) { Task { await model.copy(id) } }
            .keyboardShortcut(key)
            .disabled(!fields.contains { $0.id == id })
    }
}

/// Opens a window from the menu bar and makes it the focused window in front of other apps.
@MainActor
enum WindowFront {
    static let settings = "com_apple_SwiftUI_Settings_window"

    static func present(_ id: String, open: @escaping @MainActor () -> Void) {
        var handedToDock = false
        // An accessory app's windows open behind the frontmost app, so become a regular app
        // before the window exists rather than after it gets focus.
        if NSApp.activationPolicy() != .regular {
            NSApp.setActivationPolicy(.regular)
            // A launcher activates Keywarden while it is still an accessory app, before asking it to
            // reopen. AppKit then counts it as active and ignores another activation, but macOS keeps
            // the previous app in front: ⌘Tab lists Keywarden last, and minimizing the window hands
            // focus back to that app. Passing activation to the Dock lets the activation below count.
            if NSApp.isActive,
               let dock = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.dock").first {
                NSApp.yieldActivation(to: dock)
                dock.activate()
                handedToDock = true
            }
        }
        // Since macOS 14 `NSApp.activate()` is only a request, which macOS refuses when a launcher
        // starts Keywarden. `open` orders the window front and makes it key.
        NSApp.activate(ignoringOtherApps: true)
        guard handedToDock else { return show(id, open) }
        // Activation goes to the Dock and comes back. A window already on screen meanwhile is drawn
        // inactive and active again, and its sidebar flickers, so show it once Keywarden is back.
        let pending = PendingPresentation()
        pending.observer = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: NSApp, queue: .main
        ) { _ in MainActor.assumeIsolated { pending.finish { show(id, open) } } }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { pending.finish { show(id, open) } }
    }

    private static func show(_ id: String, _ open: () -> Void) {
        open()
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix(id) == true }),
           window.isMiniaturized {
            window.deminiaturize(nil)
        }
    }

    /// Shows the window once, on whichever comes first: reactivation or the fallback timeout.
    @MainActor private final class PendingPresentation {
        var observer: NSObjectProtocol?
        private var done = false

        func finish(_ show: () -> Void) {
            guard !done else { return }
            done = true
            if let observer { NotificationCenter.default.removeObserver(observer) }
            show()
        }
    }
}
