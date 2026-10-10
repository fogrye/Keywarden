import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// The vault flow the UI test used to click through, run in-process: the real `VaultModel` and the
/// real `RootView` in an unseen window, against the disposable server, read and driven through the
/// accessibility tree (what XCUITest reads). Needs the seeded account (`BW_TEST_*`).
@MainActor
final class VaultFlowTests: XCTestCase {
    struct Account {
        let server: String
        let email: String
        let password: String
    }

    static func account() throws -> Account {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        return Account(server: server, email: email, password: password)
    }

    /// A model signed in to the seeded account through its own sign-in path. The session is kept for
    /// the rest of the class, and each test gets it locked and unlocked again (fresh state, from
    /// the local cache), because a server rate-limits repeated sign-ins.
    static func signedIn(_ account: Account) async throws -> VaultModel {
        if let model = SeededSession.model, model.phase != .loggedOut {
            if model.phase == .unlocked { await model.lock() }
            model.password = account.password
            await model.unlock()
            XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
            return model
        }
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        if model.phase == .locked { await model.logout() }
        model.email = account.email
        model.server = account.server
        model.password = account.password
        await model.login()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        SeededSession.model = model
        return model
    }

    override class func tearDown() {
        SeededSession.end()
    }

    private func summary(_ model: VaultModel, _ name: String) throws -> VaultItemSummary {
        try XCTUnwrap(model.items.first { $0.name == name }, "\(name) missing from the list")
    }

    /// Selects an item and waits until its detail is loaded.
    private func open(_ model: VaultModel, _ name: String) async throws {
        let item = try summary(model, name)
        model.select(item.id)
        let deadline = Date().addingTimeInterval(15)
        while model.detail?.id != item.id, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertEqual(model.detail?.id, item.id, "\(name) detail did not load")
    }

    // MARK: Sign in, list and details

    /// Old steps: sign in, every seeded type is listed, each detail renders, the list shows the
    /// username but the detail keeps secrets masked until revealed, re-prompt items are gated.
    func testEverySeededTypeIsListedAndItsDetailRenders() async throws {
        let account = try Self.account()
        let model = try await Self.signedIn(account)
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }

        var tree = try await hosted.tree(containing: "Seed Login")
        for name in ["Seed Login", "Mail", "Router admin", "Travel Visa", "Alex Example", "Wi-Fi"] {
            XCTAssertTrue(tree.contains(name), "\(name) missing from the list")
        }
        // The list may show the username, as Bitwarden does; it never holds a secret.
        XCTAssertEqual(try summary(model, "Seed Login").subtitle, "seed.user@example.com")
        XCTAssertTrue(tree.contains("seed.user@example.com"))
        for item in model.items {
            XCTAssertFalse(item.subtitle.contains("Seed-Password-1"))
            XCTAssertFalse(item.searchValues.contains("Seed-Password-1"), "\(item.name) leaks a password to the list")
        }

        // Login detail: TOTP row, username visible, password masked until revealed, custom fields.
        try await open(model, "Seed Login")
        tree = try await hosted.tree(containing: "One-time code")
        XCTAssertTrue(tree.contains("One-time code"), "TOTP row missing")
        XCTAssertTrue(tree.contains("seed.user@example.com"))
        XCTAssertFalse(tree.contains("Seed-Password-1"), "Password must start masked")
        XCTAssertTrue(tree.contains("Reveal Password"))
        XCTAssertTrue(tree.contains("Recovery code"), "Custom fields missing")
        let pressed = try await hosted.press(label: "Reveal Password")
        XCTAssertTrue(pressed, "Reveal Password could not be pressed")
        tree = try await hosted.tree(containing: "Seed-Password-1", timeout: 5)
        XCTAssertTrue(tree.contains("Seed-Password-1"))
        XCTAssertTrue(tree.contains("Hide Password"))

        // Card and identity details.
        try await open(model, "Travel Visa")
        tree = try await hosted.tree(containing: "Cardholder name")
        XCTAssertTrue(tree.contains("Cardholder name"))
        XCTAssertTrue(tree.contains("Alex Example"))
        try await open(model, "Alex Example")
        tree = try await hosted.tree(containing: "Cupertino")
        XCTAssertTrue(tree.contains("Cupertino"))

        // A re-prompt item is gated, and the list's username never reaches the detail.
        try await open(model, "Router admin")
        tree = try await hosted.tree(containing: "Show Item")
        XCTAssertNotNil(tree.node(role: "AXButton", label: "Show Item"), "Re-prompt item must be gated")
        XCTAssertFalse(tree.contains("Username"))
        XCTAssertFalse(tree.contains("Website"))
    }

    // MARK: Create, edit, trash

    /// Old steps: create a login through the editor, edit and rename it, move it to the trash and
    /// find it there.
    func testCreateEditRenameAndTrashALogin() async throws {
        let account = try Self.account()
        let model = try await Self.signedIn(account)
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        let suffix = UUID().uuidString.prefix(6)
        let created = "UI Created \(suffix)"
        let renamed = "UI Renamed \(suffix)"

        // The + menu's item types all start an editor of that type.
        XCTAssertEqual(VaultItemType.creatable.count, 7)
        for type in VaultItemType.creatable {
            model.beginNewItem(type)
            XCTAssertEqual(model.editor?.draft.kind, type)
            XCTAssertTrue(model.editor?.isNew == true)
            model.cancelEditing()
        }

        model.beginNewItem(.login)
        var tree = try await hosted.tree(containing: "Item name")
        for label in ["Item name", "Username", "Password", "Authenticator key"] {
            XCTAssertTrue(tree.contains(label), "\(label) field missing from the editor")
        }
        // Fill the fields the way an assistive client does.
        let typed = try await hosted.type(created, label: "Item name")
        XCTAssertTrue(typed, "Item name could not be typed into")
        try await hosted.type("ui-user", label: "Username")
        try await hosted.type("ui-password-1", label: "Password")
        try await hosted.type("https://example.org", identifier: "websiteField")
        XCTAssertEqual(model.editor?.draft.name, created)
        XCTAssertEqual(model.editor?.draft.login?.username, "ui-user")
        XCTAssertEqual(model.editor?.draft.login?.password, "ui-password-1")
        XCTAssertEqual(model.editor?.draft.login?.uris.first?.uri, "https://example.org")
        await model.saveEditor()
        XCTAssertNil(model.editor, model.editorError ?? "")
        let id = try summary(model, created).id
        XCTAssertEqual(model.selection, id)
        tree = try await hosted.tree(containing: "ui-user")
        XCTAssertTrue(tree.contains(created), "Created item not listed")
        XCTAssertTrue(tree.contains("ui-user"), "Created item not shown")

        // Edit: rename and save.
        model.beginEditing()
        tree = try await hosted.tree(containing: "Item name")
        XCTAssertTrue(tree.contains("Item name"))
        try await hosted.type(renamed, label: "Item name")
        await model.saveEditor()
        XCTAssertNil(model.editor, model.editorError ?? "")
        XCTAssertNotNil(model.items.first { $0.name == renamed }, "Rename not saved")
        XCTAssertNil(model.items.first { $0.name == created })
        tree = try await hosted.tree(containing: renamed)
        XCTAssertTrue(tree.contains(renamed))
        XCTAssertFalse(tree.contains(created))

        // Move it to the trash and find it there.
        await model.moveToTrash(id)
        XCTAssertFalse(model.visibleItems.contains { $0.id == id })
        model.show(.trash)
        XCTAssertTrue(model.visibleItems.contains { $0.id == id })
        tree = try await hosted.tree(containing: renamed)
        XCTAssertTrue(tree.contains(renamed), "Trashed item not listed under Trash")
        await model.deletePermanently(id)
        XCTAssertNil(model.items.first { $0.id == id })
    }

    // MARK: Lock, unlock, window close

    /// Old steps: lock (what the menu's Lock Vault runs), the locked window shows no items, unlock
    /// with the master password.
    func testLockHidesTheVaultAndMasterPasswordUnlocksIt() async throws {
        let account = try Self.account()
        let model = try await Self.signedIn(account)
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        var tree = try await hosted.tree(containing: "Seed Login")
        XCTAssertTrue(tree.contains("Seed Login"))

        await model.lock()
        XCTAssertEqual(model.phase, .locked)
        XCTAssertTrue(model.items.isEmpty)
        tree = try await hosted.tree(containing: "Vault Locked")
        XCTAssertTrue(tree.contains("Vault Locked"))
        XCTAssertFalse(tree.contains("Seed Login"), "Locked window must not show items")
        XCTAssertNotNil(tree.node(role: "AXSecureTextField", label: "Master password")
                        ?? tree.node(label: "Master password"))

        try await hosted.type(account.password, label: "Master password")
        XCTAssertEqual(model.password, account.password)
        await model.unlock()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        tree = try await hosted.tree(containing: "Seed Login")
        XCTAssertTrue(tree.contains("Seed Login"))
    }

    /// Old steps: closing the window keeps the resident session; with "lock when the window
    /// closes" on, closing locks. The real window's close button and the menu bar reopen stay in
    /// the UI test; what closing does to the vault is the delegate's `vaultWindowClosed`.
    func testClosingTheWindowLocksOnlyWhenTheSettingIsOn() async throws {
        let account = try Self.account()
        await SeededSession.finish() // this test signs in on the delegate's own model
        let delegate = AppDelegate()
        let model = delegate.model
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        addTeardownBlock { @MainActor in
            delegate.settings.lockOnWindowClose = false
            await model.logout()
        }
        model.email = account.email
        model.server = account.server
        model.password = account.password
        if model.phase == .locked { await model.logout(); model.email = account.email; model.server = account.server; model.password = account.password }
        await model.login()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")

        delegate.settings.lockOnWindowClose = false
        delegate.vaultWindowClosed()
        try await Task.sleep(for: .seconds(1))
        XCTAssertEqual(model.phase, .unlocked, "Closing the window must keep the session")
        XCTAssertFalse(model.items.isEmpty)

        delegate.settings.lockOnWindowClose = true
        delegate.vaultWindowClosed()
        let locked = Date().addingTimeInterval(10)
        while model.phase != .locked, Date() < locked { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertEqual(model.phase, .locked, "Close must lock")
        XCTAssertTrue(model.items.isEmpty)
    }

    /// Old step: while locked, security settings can't be loosened (read from the tree, as the UI
    /// test read it).
    func testSecuritySettingsAreReadOnlyWhileLocked() async throws {
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        let suite = "flow-settings-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults)

        model.phase = .locked
        let locked = HostedWindow(SettingsView(settings: settings, model: model, tab: .security), size: NSSize(width: 560, height: 500))
        var tree = try await locked.tree(containing: "Timeout")
        let lockedToggle = try XCTUnwrap(tree.node(identifier: "lockOnWindowClose"), "\(tree.texts)")
        XCTAssertFalse(lockedToggle.enabled, "Security settings must be read-only while locked")
        locked.close()

        model.phase = .unlocked
        let open = HostedWindow(SettingsView(settings: settings, model: model, tab: .security), size: NSSize(width: 560, height: 500))
        defer { open.close() }
        tree = try await open.tree(containing: "Timeout")
        let openToggle = try XCTUnwrap(tree.node(identifier: "lockOnWindowClose"))
        XCTAssertTrue(openToggle.enabled)
    }

    // MARK: Clone and advanced search

    /// Clone opens an unsaved copy of the shown item; saving it adds a new item and leaves the
    /// source alone.
    func testCloneSavesACopyAndLeavesTheSource() async throws {
        let account = try Self.account()
        let model = try await Self.signedIn(account)
        addTeardownBlock { @MainActor in
            for item in model.items where item.name == "Seed Login - Clone" {
                await model.moveToTrash(item.id)
                await model.deletePermanently(item.id)
            }
        }
        let source = try summary(model, "Seed Login")
        try await open(model, "Seed Login")
        model.beginCloning()
        let editor = try XCTUnwrap(model.editor)
        XCTAssertTrue(editor.isClone)
        XCTAssertTrue(editor.isNew)
        XCTAssertEqual(editor.draft.name, "Seed Login - Clone")
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        let tree = try await hosted.tree(containing: "Save the item first, then add attachments.")
        XCTAssertTrue(tree.contains("Save the item first, then add attachments."))
        await model.saveEditor()
        XCTAssertNil(model.editor, model.editorError ?? "")
        let copy = try summary(model, "Seed Login - Clone")
        XCTAssertNotEqual(copy.id, source.id)
        XCTAssertNotNil(model.items.first { $0.id == source.id }, "the source is still there")
        XCTAssertEqual(model.items.filter { $0.name == "Seed Login" }.count, 1)
        let detail = try await SDKClient.shared.item(id: copy.id)
        XCTAssertEqual(detail.item.login?.password, "Seed-Password-1")
        XCTAssertTrue(detail.passwordHistory.isEmpty)
    }

    /// A query starting with `>` searches by field; the window's list follows it, and clearing
    /// the search brings everything back.
    func testAdvancedSearchNarrowsTheListInTheWindow() async throws {
        let account = try Self.account()
        let model = try await Self.signedIn(account)
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        var tree = try await hosted.tree(containing: "Seed Login")
        XCTAssertTrue(tree.contains("Mail"))

        model.search = ">username:seed.user"
        tree = try await hosted.tree(without: "Mail")
        XCTAssertTrue(tree.contains("Seed Login"))
        XCTAssertFalse(tree.contains("Mail"), "advanced search by username excludes other logins")
        XCTAssertEqual(model.visibleItems.map(\.name), ["Seed Login"])

        model.search = ">type:card"
        tree = try await hosted.tree(without: "Seed Login")
        XCTAssertTrue(tree.contains("Travel Visa"))
        XCTAssertFalse(tree.contains("Seed Login"))

        model.search = ">name:seed -name:login"
        XCTAssertFalse(model.visibleItems.contains { $0.name == "Seed Login" })

        model.search = ""
        tree = try await hosted.tree(containing: "Mail")
        XCTAssertTrue(tree.contains("Seed Login"))
        XCTAssertTrue(tree.contains("Mail"))
    }
}

/// One sign-in to the seeded account per test class, ended when the class finishes.
@MainActor
enum SeededSession {
    static var model: VaultModel?

    static func finish() async {
        guard let model else { return }
        self.model = nil
        await model.logout()
    }

    /// Signs out (from the XCTest class hook, which is synchronous) so other classes start clean.
    nonisolated static func end() {
        MainActor.assumeIsolated {
            guard let model else { return }
            self.model = nil
            var finished = false
            Task { @MainActor in await model.logout(); finished = true }
            let deadline = Date().addingTimeInterval(20)
            while !finished, Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        }
    }
}
