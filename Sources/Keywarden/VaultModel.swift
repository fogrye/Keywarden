import AppKit
import Foundation
import Observation

enum SidebarItem: Hashable {
    case all, favorites, type(VaultItemType), folder(String), noFolder, archive, trash, generator
}

/// An in-progress create or edit. The detail pane shows the editor while one exists.
struct ItemEditor: Equatable {
    var draft: ItemData
    let original: ItemData
    /// The login's existing passkeys, shown with a remove control. Never part of the draft.
    var passkeys: [ItemDetail.Passkey] = []
    /// The saved item's attachments. Adding or removing one takes effect on the server at once,
    /// independent of the draft.
    var attachments: [ItemDetail.Attachment] = []
    /// True for a copy of another item; it saves as a new item.
    var isClone = false
    var isNew: Bool { original.id == nil }
    var isDirty: Bool { draft != original }
    var isValid: Bool { !draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
}

// The list holds only nonsecret metadata and the text advanced search reads (notes, usernames, websites,
// custom fields; never passwords, hidden fields, card numbers or codes, and nothing but the basics for
// items that ask for the master password again). Item details are decrypted on selection.
@MainActor @Observable
final class VaultModel {
    enum Phase: Equatable { case loading, loggedOut, locked, unlocked }

    var phase: Phase = .loading {
        didSet {
            guard phase != oldValue else { return }
            lockedAfterUse = phase == .locked && oldValue == .unlocked && Self.vaultInFront
            // Generator history is secret: shown only while unlocked, and wiped on logout.
            GeneratorHistory.shared.sessionChanged(unlocked: phase == .unlocked, loggedOut: phase == .loggedOut)
            onPhaseChange?(phase)
        }
    }
    /// The vault was open and then locked, rather than starting locked. A lock screen that takes
    /// the vault's place in front of the user doesn't ask for Touch ID by itself.
    private(set) var lockedAfterUse = false
    /// The app is active with a window up, so a lock now happens in front of the user. A lock while
    /// the window is closed or Keywarden is in the background shows the lock screen as new later.
    private static var vaultInFront: Bool {
        NSApp.isActive && NSApp.windows.contains {
            $0.isVisible && !$0.isMiniaturized && $0.styleMask.contains(.titled) && !($0 is NSPanel)
        }
    }
    var onPhaseChange: (@MainActor (Phase) -> Void)?
    /// Runs once the stored account identity and biometric preferences are known.
    var onReady: (@MainActor () -> Void)?
    private(set) var isReady = false

    var email = ""
    var server = ""
    private(set) var accountId: String?
    private var accountHash: String?
    var password = ""

    var search = ""
    var destination: SidebarItem = .all
    private(set) var selection: String?
    var errorMessage: String?
    /// Set when navigation would drop unsaved edits; the view asks before running it.
    var pendingNavigation: (() -> Void)?

    private(set) var isBusy = false
    private(set) var isSyncing = false
    private(set) var syncError: String?
    private(set) var lastSync: Date?
    private(set) var items: [VaultItemSummary] = []
    private(set) var folders: [VaultFolder] = []
    private(set) var failures: [VaultItemFailure] = []
    private(set) var detail: ItemDetail?
    private(set) var detailError: String?
    /// The selected item whose "master password re-prompt" was passed. It lasts until another
    /// item is selected or the vault locks, so the detail and the Item menu ask only once.
    private(set) var repromptPassedID: String?

    /// Asks the vault window to show the New Folder sheet (from the File menu).
    var newFolderRequested = false
    /// Asks the vault window to show the Export Vault sheet (from the File menu).
    var exportRequested = false
    /// Asks the vault window to show the Import Data sheet (from the File menu).
    var importRequested = false
    /// Where the vault window should move keyboard focus: asked by the menus (⌘F), a reopen, and
    /// the search field, list and detail handing focus to each other. The pane it names takes it.
    enum Pane: Equatable { case search, list, detail }
    var focusRequest: Pane?
    /// The item waiting for "Delete permanently?" (from the list, the detail or the Item menu).
    var confirmingDelete: String?
    /// The folder whose Rename sheet or Delete confirmation is showing (sidebar or File menu).
    var renamingFolder: VaultFolder?
    var deletingFolder: VaultFolder?

    var editor: ItemEditor?
    private(set) var isSaving = false
    var editorError: String?

    /// What an attachment transfer is doing right now; the views disable their controls meanwhile.
    enum AttachmentActivity: Equatable { case uploading, downloading(String), removing(String) }
    private(set) var attachmentActivity: AttachmentActivity?

    private var generation: UInt64 = 0
    private var detailTask: Task<Void, Never>?

    var biometricEnabled = false
    var browserBiometricsEnabled = false
    private(set) var pinEnabled = false

    init() { Task { await restore() } }

    // MARK: Derived lists

    /// The search text actually applied. A single character matches nearly everything, so
    /// filtering starts at two.
    var effectiveSearch: String {
        let trimmed = search.trimmingCharacters(in: .whitespaces)
        return trimmed.count >= 2 ? trimmed : ""
    }

    var visibleItems: [VaultItemSummary] {
        let query = effectiveSearch
        // A query starting with ">" is an advanced (field-scoped) search, as in Bitwarden Desktop.
        // It is parsed once here; one that can't be read is matched as plain text without the ">".
        var advanced: AdvancedSearch?
        var plainQuery = query
        if let body = AdvancedSearch.body(of: query) {
            advanced = AdvancedSearch(parsing: body)
            plainQuery = body
        }
        let folderNames = advanced == nil ? [:] : Dictionary(folders.map { ($0.id, $0.name) }) { first, _ in first }
        return items.filter { item in
            guard Self.item(item, belongsTo: destination) else { return false }
            if query.isEmpty || plainQuery.isEmpty { return true }
            if let advanced { return advanced.matches(item, folderName: item.folderId.flatMap { folderNames[$0] }) }
            return Self.matchesPlain(item, plainQuery)
        }
    }

    /// Plain search: the query is a substring of the name, subtitle, username, website or text field.
    static func matchesPlain(_ item: VaultItemSummary, _ query: String) -> Bool {
        item.name.localizedCaseInsensitiveContains(query)
            || item.subtitle.localizedCaseInsensitiveContains(query)
            || item.searchValues.contains { $0.localizedCaseInsensitiveContains(query) }
    }

    func count(_ place: SidebarItem) -> Int {
        items.lazy.filter { Self.item($0, belongsTo: place) }.count
    }

    /// The item types the sidebar lists: those with items outside Archive and Trash, plus the type
    /// being shown, so its row doesn't vanish from under the selection when its last item goes.
    var sidebarTypes: [VaultItemType] { Self.sidebarTypes(items, showing: destination) }

    static func sidebarTypes(_ items: [VaultItemSummary], showing destination: SidebarItem) -> [VaultItemType] {
        VaultItemType.allCases.filter { type in
            destination == .type(type) || items.contains { item($0, belongsTo: .type(type)) }
        }
    }

    /// Where an item appears. As in the official clients, archived and trashed items leave the
    /// regular views and appear only under Archive and Trash.
    private static func item(_ item: VaultItemSummary, belongsTo place: SidebarItem) -> Bool {
        let active = !item.deleted && !item.archived
        return switch place {
        case .all: active
        case .favorites: active && item.favorite
        case .type(let type): active && item.type == type.rawValue
        case .folder(let id): active && item.folderId == id
        case .noFolder: active && item.folderId == nil
        case .archive: item.archived && !item.deleted
        case .trash: item.deleted
        case .generator: false
        }
    }

    /// Supplies preferences the vault views follow, such as website icons.
    weak var settings: AppSettings?
    var showWebsiteIcons: Bool { settings?.showWebsiteIcons ?? true }

    /// The account server's icon service, as used by the official clients. Only the host is sent.
    func iconURL(_ host: String?) -> URL? {
        guard showWebsiteIcons, let host, !server.isEmpty else { return nil }
        let base: String
        switch server {
        case "https://api.bitwarden.com": base = "https://icons.bitwarden.net"
        case "https://api.bitwarden.eu": base = "https://icons.bitwarden.eu"
        default:
            guard server.hasSuffix("/api") else { return nil }
            base = String(server.dropLast(4)) + "/icons"
        }
        guard let encoded = host.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) else { return nil }
        return URL(string: "\(base)/\(encoded)/icon.png")
    }

    var selectedSummary: VaultItemSummary? { items.first { $0.id == selection } }

    func folderName(_ id: String?) -> String? {
        guard let id else { return nil }
        return folders.first { $0.id == id }?.name
    }

    var defaultFolderForNewItems: String? {
        if case .folder(let id) = destination { return id }
        return nil
    }

    // MARK: Navigation

    /// Runs `action` now, or after the user confirms discarding unsaved edits.
    func navigate(_ action: @escaping () -> Void) {
        if let editor, editor.isDirty {
            pendingNavigation = { [weak self] in
                self?.editor = nil
                action()
            }
        } else {
            editor = nil
            action()
        }
    }

    func select(_ id: String?) {
        guard id != selection || editor != nil else { return }
        navigate { [weak self] in self?.setSelection(id) }
    }

    func show(_ place: SidebarItem) {
        guard place != destination else { return }
        navigate { [weak self] in
            guard let self else { return }
            destination = place
            if let selection, !visibleItems.contains(where: { $0.id == selection }) { setSelection(nil) }
        }
    }

    private func setSelection(_ id: String?) {
        if id != selection { repromptPassedID = nil }
        selection = id
        loadSelectedItem()
    }

    // MARK: Account

    private func restore() async {
        do {
            let status = try await SDKClient.shared.status()
            generation = status.generation
            email = status.email ?? ""
            server = status.server ?? ""
            accountId = status.accountId
            accountHash = status.accountHash
            BiometricCoordinator.shared.configure(id: accountId, hash: accountHash,
                                                  server: server, email: email)
            refreshBiometricPreferences()
            pinEnabled = status.pinEnabled ?? false
            // A process launch never restores an unlocked key.
            phase = status.phase == .loggedOut ? .loggedOut : .locked
        } catch {
            phase = .loggedOut
            errorMessage = error.localizedDescription
        }
        isReady = true
        onReady?()
    }

    func login() async {
        guard !isBusy, phase == .loggedOut else { return }
        isBusy = true
        defer { isBusy = false; password = "" }
        errorMessage = nil
        do {
            let address = server.trimmingCharacters(in: .whitespacesAndNewlines)
            accept(try await SDKClient.shared.login(email: email, password: password,
                                                     server: address.isEmpty ? "https://bitwarden.com" : address))
        } catch { if phase == .loggedOut { fail(error) } }
    }

    func unlock() async {
        guard !isBusy, phase == .locked else { return }
        isBusy = true
        defer { isBusy = false; password = "" }
        errorMessage = nil
        do {
            accept(try await SDKClient.shared.unlock(password: password))
            refreshInBackground()
        } catch { if phase == .locked { fail(error) } }
    }

    func unlock(pin: String) async {
        guard !isBusy, phase == .locked, !pin.isEmpty else { return }
        isBusy = true
        defer { isBusy = false }
        errorMessage = nil
        do {
            accept(try await SDKClient.shared.unlock(pin: pin))
            refreshInBackground()
        } catch {
            guard phase == .locked else { return }
            if (error as? VaultError)?.code == "pinUnavailable" { pinEnabled = false }
            fail(error)
        }
    }

    func enablePin(_ pin: String) async -> Bool {
        guard phase == .unlocked else { return false }
        do {
            try await SDKClient.shared.enrollPin(pin)
            pinEnabled = true
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func disablePin() async {
        guard phase == .unlocked else { return }
        do {
            try await SDKClient.shared.disablePin()
            pinEnabled = false
        } catch { errorMessage = error.localizedDescription }
    }

    /// Refreshes from the server. Background refreshes report problems inline, not as alerts.
    func sync(background: Bool = false) async {
        guard !isSyncing, phase == .unlocked else { return }
        isSyncing = true
        defer { isSyncing = false }
        do {
            accept(try await SDKClient.shared.sync())
            syncError = nil
        } catch {
            guard phase == .unlocked else { return }
            syncError = error.localizedDescription
            if !background { fail(error) }
        }
    }

    func refreshInBackground() {
        Task { await sync(background: true) }
    }

    /// Called when the vault window appears; avoids hammering the server on every open.
    func refreshIfStale() {
        guard phase == .unlocked, !isSyncing else { return }
        if let lastSync, Date().timeIntervalSince(lastSync) < 300 { return }
        refreshInBackground()
    }

    func lock() async {
        guard phase != .locked || isBusy else { return }
        generation = SDKClient.shared.invalidateSession()
        BiometricCoordinator.shared.cancel()
        let previous = phase
        redact()
        phase = previous == .loggedOut ? .loggedOut : .locked
        do { try await SDKClient.shared.lock(); generation = SDKClient.shared.generation() }
        catch { errorMessage = error.localizedDescription }
    }

    func logout() async {
        generation = SDKClient.shared.invalidateSession()
        BiometricCoordinator.shared.cancel()
        BiometricCoordinator.shared.setBrowserEnabled(false)
        redact()
        phase = .loggedOut
        password = ""
        do {
            try await SDKClient.shared.logout()
            generation = SDKClient.shared.generation()
            email = ""
            server = ""
            accountId = nil
            accountHash = nil
            pinEnabled = false
            BiometricCoordinator.shared.configure(id: nil, hash: nil, server: "", email: "")
            refreshBiometricPreferences()
        } catch { errorMessage = error.localizedDescription }
    }

    // MARK: Editing

    func beginNewItem(_ type: VaultItemType) {
        navigate { [weak self] in
            guard let self else { return }
            if destination == .trash || destination == .archive { destination = .all }
            let item = ItemData.new(type, folderId: defaultFolderForNewItems)
            editorError = nil
            editor = ItemEditor(draft: item, original: item)
        }
    }

    func beginEditing() {
        guard let detail, detail.editable, detail.deletedDate == nil else { return }
        editorError = nil
        editor = ItemEditor(draft: detail.item, original: detail.item, passkeys: detail.passkeys,
                            attachments: detail.attachments)
    }

    /// Opens the editor on a copy of the shown item. Saving creates a new item; the source is untouched.
    func beginCloning() {
        guard let detail, detail.deletedDate == nil, detail.item.kind != .sshKey else { return }
        let clone = detail.item.cloned()
        navigate { [weak self] in
            guard let self else { return }
            editorError = nil
            // The original is blank, so the copy counts as unsaved and can be saved as is.
            editor = ItemEditor(draft: clone, original: ItemData(type: clone.type), isClone: true)
        }
    }

    func cancelEditing() {
        editor = nil
        editorError = nil
    }

    /// Saves the draft. On failure the draft stays open with the error shown beside it.
    func saveEditor() async {
        guard let editor, editor.isValid, editor.isDirty, !isSaving, attachmentActivity == nil,
              phase == .unlocked else { return }
        isSaving = true
        editorError = nil
        defer { isSaving = false }
        do {
            let result = try await SDKClient.shared.save(editor.draft)
            guard phase == .unlocked else { return }
            // Decrypt the saved item before leaving the editor, so the pane and its toolbar swap
            // in one step instead of flashing an empty loading state.
            var refreshed: ItemDetail?
            if let id = result.id { refreshed = try? await SDKClient.shared.item(id: id) }
            guard phase == .unlocked else { return }
            if let id = result.id, editor.isNew, !visibleAfterSave(result, id: id) { destination = .all }
            apply(result)
            if let refreshed, refreshed.id == selection {
                detailTask?.cancel()
                detail = refreshed
            }
            self.editor = nil
        } catch {
            guard phase == .unlocked else { return }
            editorError = error.localizedDescription
            if (error as? VaultError)?.code == "conflict" { refreshInBackground() }
        }
    }

    private func visibleAfterSave(_ result: MutationResult, id: String) -> Bool {
        guard let item = result.snapshot.items.first(where: { $0.id == id }) else { return false }
        return Self.item(item, belongsTo: destination)
    }

    func setArchived(_ id: String, _ archived: Bool) async {
        await mutate { try await SDKClient.shared.archive(id: id, archived: archived) }
    }

    func setFavorite(_ id: String, _ favorite: Bool) async {
        guard let item = items.first(where: { $0.id == id }) else { return }
        await mutate { try await SDKClient.shared.organize(id: id, favorite: favorite, folderId: item.folderId) }
    }

    func move(_ id: String, toFolder folderId: String?) async {
        guard let item = items.first(where: { $0.id == id }) else { return }
        await mutate { try await SDKClient.shared.organize(id: id, favorite: item.favorite, folderId: folderId) }
    }

    func moveToTrash(_ id: String) async {
        await mutate { try await SDKClient.shared.delete(id: id, permanent: false) }
    }

    func restoreFromTrash(_ id: String) async {
        await mutate { try await SDKClient.shared.restore(id: id) }
    }

    func deletePermanently(_ id: String) async {
        await mutate { try await SDKClient.shared.delete(id: id, permanent: true) }
    }

    @discardableResult
    func saveFolder(id: String?, name: String) async -> Bool {
        await mutate { try await SDKClient.shared.saveFolder(id: id, name: name) }
    }

    func deleteFolder(_ id: String) async {
        if destination == .folder(id) { destination = .all }
        await mutate { try await SDKClient.shared.deleteFolder(id: id) }
    }

    @discardableResult
    private func mutate(_ operation: () async throws -> MutationResult) async -> Bool {
        guard !isBusy, attachmentActivity == nil, phase == .unlocked else { return false }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await operation()
            guard phase == .unlocked else { return false }
            apply(result)
            return true
        } catch {
            if phase == .unlocked { fail(error) }
            return false
        }
    }

    // MARK: Import

    /// Uploads what `prepareImport` read, after the user confirmed the counts, and refreshes the
    /// list from the server. Throws a `VaultError` the sheet shows.
    @discardableResult
    func commitImport() async throws -> ImportSummary {
        try requireUnlocked()
        guard !isBusy, attachmentActivity == nil, !isSaving else {
            throw VaultError(code: "busy", message: String(localized: "Finish what you’re doing first, then try again."))
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let result = try await SDKClient.shared.commitImport()
            guard phase == .unlocked else { throw VaultError(code: "locked", message: String(localized: "Unlock the vault first.")) }
            if let snapshot = result.snapshot { accept(snapshot) } else { refreshInBackground() }
            return ImportSummary(items: result.items, folders: result.folders)
        } catch {
            if phase == .unlocked, SDKClient.shared.generation() != generation { self.fail(error) }
            throw error
        }
    }

    // MARK: Attachments

    /// Saves an attachment's decrypted contents to `url`, a file the user picked.
    @discardableResult
    func downloadAttachment(itemID: String, _ attachment: ItemDetail.Attachment, to url: URL) async -> Bool {
        await attachmentOperation(.downloading(attachment.id)) {
            try await SDKClient.shared.downloadAttachment(id: itemID, attachmentId: attachment.id, to: url)
            return nil
        }
    }

    /// Encrypts the file at `url` and uploads it to a saved item.
    @discardableResult
    func addAttachment(itemID: String, from url: URL) async -> Bool {
        if let problem = AttachmentLimits.problem(with: url) { errorMessage = problem; return false }
        return await attachmentOperation(.uploading) {
            try await SDKClient.shared.uploadAttachment(id: itemID, from: url)
        }
    }

    @discardableResult
    func removeAttachment(itemID: String, _ attachment: ItemDetail.Attachment) async -> Bool {
        await attachmentOperation(.removing(attachment.id)) {
            try await SDKClient.shared.deleteAttachment(id: itemID, attachmentId: attachment.id)
        }
    }

    /// Runs one transfer. A change to the item refreshes the list and re-reads the item, so a later
    /// edit starts from what the server has. The editor's unsaved draft is left alone.
    private func attachmentOperation(_ activity: AttachmentActivity,
                                     _ operation: () async throws -> MutationResult?) async -> Bool {
        guard attachmentActivity == nil, !isBusy, !isSaving, phase == .unlocked else { return false }
        attachmentActivity = activity
        defer { attachmentActivity = nil }
        do {
            let result = try await operation()
            guard phase == .unlocked else { return false }
            if let result, let id = result.id {
                apply(result)
                if let refreshed = try? await SDKClient.shared.item(id: id), phase == .unlocked {
                    if detail?.id == id { detailTask?.cancel(); detail = refreshed }
                    if editor?.original.id == id { editor?.attachments = refreshed.attachments }
                }
            }
            return true
        } catch {
            if phase == .unlocked { fail(error) }
            return false
        }
    }

    private func apply(_ result: MutationResult) {
        accept(result.snapshot)
        if let id = result.id, items.contains(where: { $0.id == id }) {
            if visibleItems.contains(where: { $0.id == id }) { setSelection(id) }
            else if selection == id { setSelection(nil) }
        }
    }

    // MARK: Biometrics

    func enableBiometrics() async {
        guard phase == .unlocked, let accountHash, let accountId else { return }
        errorMessage = nil
        let expected = generation
        let reason = String(localized: "turn on Touch ID for \(email) (\(server))",
                            comment: "Touch ID prompt: “Keywarden is trying to …”")
        let approved = await Task.detached {
            BiometricCoordinator.shared.approvedInApp(reason: reason)
        }.value
        guard approved, generation == expected, phase == .unlocked else { return }
        do {
            try await SDKClient.shared.enrollBiometrics(generation: expected)
            guard generation == expected else { return }
            biometricEnabled = PlatformCredentials.enrolled(accountHash)
            BiometricCoordinator.shared.configure(id: accountId, hash: accountHash, server: server, email: email)
        } catch { errorMessage = error.localizedDescription }
    }

    func disableBiometrics() async {
        guard phase == .unlocked, let accountHash else { return }
        do {
            try PlatformCredentials.delete(PlatformCredentials.biometric, accountHash)
            biometricEnabled = false
            setBrowserBiometricsEnabled(false)
        } catch { errorMessage = String(localized: "Could not remove Touch ID enrollment.") }
    }

    /// Turns on browser unlock, enrolling Touch ID first when this account has none yet.
    func enableBrowserBiometrics() async {
        if !biometricEnabled { await enableBiometrics() }
        setBrowserBiometricsEnabled(true)
    }

    func setBrowserBiometricsEnabled(_ enabled: Bool) {
        browserBiometricsEnabled = enabled && biometricEnabled
        if let accountHash { BrowserUnlockPreference.set(browserBiometricsEnabled, accountHash) }
        BiometricCoordinator.shared.setBrowserEnabled(browserBiometricsEnabled)
    }

    func unlockBiometrics() async {
        guard !Task.isCancelled, phase == .locked, !isBusy, let accountHash, let accountId else { return }
        isBusy = true
        defer {
            if Task.isCancelled, phase == .locked,
               self.accountId == accountId, self.accountHash == accountHash {
                generation = SDKClient.shared.generation()
            }
            isBusy = false
        }
        let expected = generation
        let client = SDKClient.shared
        let enrollmentRead = Task.detached {
            BiometricCoordinator.shared.readAuthorizedEnrollment(
                id: accountId, connection: BiometricCoordinator.appConnection, browser: false)
        }
        let snapshot: VaultSnapshot? = await withTaskCancellationHandler {
            guard var data = await enrollmentRead.value else {
                guard !Task.isCancelled, generation == expected, phase == .locked,
                      self.accountId == accountId, self.accountHash == accountHash else { return nil }
                if let failure = BiometricCoordinator.shared.lastFailure { errorMessage = failure }
                return nil
            }
            defer { data.resetBytes(in: data.startIndex..<data.endIndex) }
            guard !Task.isCancelled, generation == expected, phase == .locked,
                  self.accountId == accountId, self.accountHash == accountHash else { return nil }
            guard let record = try? JSONDecoder().decode(StoredEnrollment.self, from: data),
                  record.accountId.caseInsensitiveCompare(accountId) == .orderedSame,
                  record.server == server else {
                errorMessage = String(localized: "Touch ID enrollment does not match this account.")
                return nil
            }
            let snapshot: VaultSnapshot?
            do {
                snapshot = try await SDKClient.shared.unlockBiometrics(
                    authorization: Data(record.keyB64.utf8), generation: expected)
            } catch {
                guard !Task.isCancelled, generation == expected, phase == .locked,
                      self.accountId == accountId, self.accountHash == accountHash else { return nil }
                errorMessage = error.localizedDescription
                snapshot = nil
            }
            guard !Task.isCancelled, generation == expected, phase == .locked,
                  self.accountId == accountId, self.accountHash == accountHash else { return nil }
            biometricEnabled = PlatformCredentials.enrolled(accountHash)
            return snapshot
        } onCancel: {
            enrollmentRead.cancel()
            BiometricCoordinator.shared.cancel(BiometricCoordinator.appConnection)
            client.invalidateSession()
        }
        guard let snapshot, !Task.isCancelled, generation == expected, phase == .locked,
              self.accountId == accountId, self.accountHash == accountHash else { return }
        accept(snapshot)
        refreshInBackground()
    }

    private func refreshBiometricPreferences() {
        biometricEnabled = accountHash.map(PlatformCredentials.enrolled) ?? false
        browserBiometricsEnabled = biometricEnabled && accountHash.map(BrowserUnlockPreference.isEnabled) == true
        BiometricCoordinator.shared.setBrowserEnabled(browserBiometricsEnabled)
    }

    // MARK: Keyboard

    /// Selects the item `offset` rows away in the list (↓/↑ while typing a search), starting at
    /// the top or bottom when the selection isn't in the list.
    func selectAdjacent(_ offset: Int) {
        let items = visibleItems
        guard !items.isEmpty else { return }
        let index = items.firstIndex { $0.id == selection }.map { $0 + offset } ?? (offset > 0 ? 0 : items.count - 1)
        select(items[min(max(index, 0), items.count - 1)].id)
    }

    /// The shown item's detail, once it has loaded for the selection and no editor is open.
    var shownDetail: ItemDetail? {
        guard phase == .unlocked, editor == nil, let detail, detail.id == selection else { return nil }
        return detail
    }

    /// The shown item still asks for the master password again before it is shown or copied.
    var shownItemLocked: Bool {
        guard let detail else { return false }
        return detail.item.reprompt && repromptPassedID != detail.id
    }

    /// Whether the shown item may be shown and copied. An item with "master password re-prompt"
    /// asks for Touch ID or the Mac password first, once per selection.
    func passReprompt() async -> Bool {
        guard let detail = shownDetail else { return false }
        guard detail.item.reprompt, repromptPassedID != detail.id else { return true }
        let id = detail.id
        guard await Reprompt.authenticate(detail.item.name), shownDetail?.id == id else { return false }
        repromptPassedID = id
        return true
    }

    /// Copies one of the shown item's `copyableFields` through the secure clipboard, after the
    /// re-prompt. A one-time code is generated now.
    func copy(_ fieldID: String) async {
        guard let detail = shownDetail, let field = detail.copyableFields.first(where: { $0.id == fieldID }),
              await passReprompt() else { return }
        if field.kind == .totp {
            guard let code = try? await totpCode(detail.id), shownDetail?.id == detail.id else { return }
            SecureClipboard.copy(code.code)
        } else {
            SecureClipboard.copy(field.value)
        }
    }

    // MARK: Detail loading

    func reloadDetail() { loadSelectedItem() }

    func totpCode(_ id: String) async throws -> TotpCode {
        guard phase == .unlocked else { throw CancellationError() }
        return try await SDKClient.shared.totp(id: id)
    }

    func generatePassword() async -> String? {
        let options = GeneratorOptions.stored
        guard let value = try? await SDKClient.shared.generate(options: options.request) else { return nil }
        GeneratorHistory.shared.record(value, kind: options.mode == .password ? .password : .passphrase)
        return value
    }

    /// Generates a username with the stored options for the editor's button. Throws the service's error.
    func generateUsername(website: String?) async throws -> String {
        let options = UsernameOptions.stored
        let token = options.kind == .forwarded ? ForwarderSecrets.token(for: options.service) : nil
        let value = try await SDKClient.shared.generateUsername(options: options.request(token: token, website: website))
        GeneratorHistory.shared.record(value, kind: .username)
        return value
    }

    private func loadSelectedItem() {
        detailTask?.cancel()
        // Keep showing the current item while a refresh of the same item decrypts.
        if detail?.id != selection { detail = nil }
        detailError = nil
        guard phase == .unlocked, let id = selection else { detail = nil; return }
        let expectedGeneration = generation
        detailTask = Task {
            do {
                let loaded = try await SDKClient.shared.item(id: id)
                guard !Task.isCancelled, phase == .unlocked,
                      expectedGeneration == generation, selection == id else { return }
                detail = loaded
            } catch {
                guard !Task.isCancelled, phase == .unlocked, selection == id else { return }
                detailError = error.localizedDescription
            }
        }
    }

    private func fail(_ error: Error) {
        let current = SDKClient.shared.generation()
        if current != generation {
            // The session was invalidated underneath the request (for example by auto-lock).
            // Firefox unlock stays as configured; only an explicit sign-out turns it off.
            generation = current
            BiometricCoordinator.shared.cancel()
            redact()
            phase = phase == .loggedOut ? .loggedOut : .locked
        }
        errorMessage = error.localizedDescription
    }

    private func redact() {
        detailTask?.cancel()
        detailTask = nil
        detail = nil
        detailError = nil
        editor = nil
        editorError = nil
        pendingNavigation = nil
        exportRequested = false
        importRequested = false
        focusRequest = nil
        confirmingDelete = nil
        renamingFolder = nil
        deletingFolder = nil
        repromptPassedID = nil
        items = []
        folders = []
        failures = []
        selection = nil
        destination = .all
        search = ""
        password = ""
        errorMessage = nil
        syncError = nil
        WebsiteIcons.shared.clear()
        SecureClipboard.clearIfOwned()
    }

    #if DEBUG
    /// Loads a snapshot without the backend, for performance tests.
    func loadForTesting(_ snapshot: VaultSnapshot) {
        items = snapshot.items
        folders = snapshot.folders
        phase = .unlocked
    }
    #endif

    private func accept(_ snapshot: VaultSnapshot) {
        guard snapshot.generation == SDKClient.shared.generation() else { return }
        generation = snapshot.generation
        email = snapshot.email
        accountId = snapshot.accountId
        accountHash = snapshot.accountHash
        server = snapshot.server
        BiometricCoordinator.shared.configure(id: accountId, hash: accountHash,
                                              server: server, email: email)
        refreshBiometricPreferences()
        items = snapshot.items
        folders = snapshot.folders
        failures = snapshot.failures
        lastSync = snapshot.lastSync.map { Date(timeIntervalSince1970: TimeInterval($0)) }
        if case .folder(let id) = destination, !folders.contains(where: { $0.id == id }) {
            destination = .all
        }
        phase = .unlocked
        if let selection, !items.contains(where: { $0.id == selection }) {
            setSelection(nil)
        } else if selection != nil {
            loadSelectedItem()
        }
    }
}
