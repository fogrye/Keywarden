import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// Renders every seeded item's detail and editor offscreen, so view-layer traps surface in CI.
@MainActor
final class DetailRenderingTests: XCTestCase {
    func testSecretValueRowRevealsOnlyWhenNotConcealed() async throws {
        let label = "Password"
        let secret = "Example-only-password"
        let reveal = String(localized: "Reveal \(label)")
        let hide = String(localized: "Hide \(label)")
        let copy = String(localized: "Copy \(label)")
        let window = HostedWindow(Form {
            ValueRow(label: label, value: secret, secret: true, monospaced: true)
        }.formStyle(.grouped))
        defer { window.close() }
        let hidden = try await window.tree()
        XCTAssertFalse(hidden.contains(secret))
        XCTAssertNotNil(hidden.node(role: "AXButton", label: reveal))
        let pressedReveal = try await window.press(label: reveal, role: "AXButton")
        XCTAssertTrue(pressedReveal)
        let revealed = try await window.tree(containing: secret)
        XCTAssertTrue(revealed.contains(secret))
        let pressedHide = try await window.press(label: hide, role: "AXButton")
        XCTAssertTrue(pressedHide)
        let hiddenAgain = try await window.tree(without: secret)
        XCTAssertFalse(hiddenAgain.contains(secret))

        let concealedWindow = HostedWindow(Form {
            ValueRow(label: label, value: secret, secret: true, concealed: true)
        }.formStyle(.grouped))
        defer { concealedWindow.close() }
        let concealed = try await concealedWindow.tree()
        XCTAssertFalse(concealed.contains(secret))
        XCTAssertNil(concealed.node(role: "AXButton", label: reveal))
        XCTAssertNil(concealed.node(role: "AXButton", label: copy))
    }

    func testEverySeededItemRendersInDetailAndEditor() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let client = SDKClient.shared
        let snapshot = try await client.login(email: email, password: password, server: server)
        defer { client.invalidateSession() }
        let model = VaultModel()
        for summary in snapshot.items {
            let detail = try await client.item(id: summary.id)
            render(ItemDetailView(model: model, detail: detail), summary.name)
            model.editor = ItemEditor(draft: detail.item, original: detail.item)
            render(ItemEditorView(model: model), "\(summary.name) editor")
            model.editor = nil
        }
        render(GeneratorView(), "generator")
        let suite = "render-settings-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        for tab in SettingsTab.allCases {
            let view = SettingsView(settings: AppSettings(defaults: defaults), model: model, tab: tab)
            render(view, "settings-\(tab)", height: nil)
        }
        try await client.logout()
    }

    /// Editors that need no server: a login with a passkey (before and after asking to remove it),
    /// a clone, and a new bank account.
    func testPasskeyCloneAndNewTypeEditorsRender() throws {
        let model = VaultModel()
        var login = ItemData.new(.login, folderId: nil)
        login.id = "x"
        login.name = "Mail"
        login.login = LoginData(username: "me", password: "pw", uris: [UriData(uri: "https://mail.example")])
        let passkey = ItemDetail.Passkey(rpId: "mail.example", userName: "me", creationDate: "2025-03-04T10:00:00Z")
        model.editor = ItemEditor(draft: login, original: login, passkeys: [passkey])
        render(ItemEditorView(model: model), "editor with passkey")
        model.editor?.draft.removePasskeys = true
        render(ItemEditorView(model: model), "editor with passkey removed")
        model.editor = ItemEditor(draft: login.cloned(), original: ItemData(type: 1), isClone: true)
        render(ItemEditorView(model: model), "clone editor")
        let bank = ItemData.new(.bankAccount, folderId: nil)
        model.editor = ItemEditor(draft: bank, original: bank)
        render(ItemEditorView(model: model), "new bank account editor")
        var card = ItemData.new(.card, folderId: nil)
        card.card = CardData(cardholderName: "Alex Example", expMonth: "4", expYear: "2031", code: "321",
                             brand: "Visa", number: "4111111111111111")
        model.editor = ItemEditor(draft: card, original: card)
        render(ItemEditorView(model: model), "card editor")
        model.editor = nil
    }

    /// The lock screen shows Keywarden's shield, the sign-in screen the app icon, and the Security
    /// settings tab the shield symbol (the toolbar itself isn't drawn offscreen, so the symbol is
    /// rendered on its own).
    func testLockSignInAndSettingsRender() async throws {
        let model = VaultModel()
        // Let the stored account load first, so the example values below aren't overwritten.
        try await wait { model.isReady }
        model.email = "me@example.com"
        model.server = "https://vault.example"
        model.phase = .locked
        render(LoginView(model: model), "lock screen", height: 520)
        model.phase = .loggedOut
        render(LoginView(model: model), "sign-in screen", height: 520)
        let suite = "rendering-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        render(SettingsView(settings: AppSettings(defaults: defaults), model: model), "security settings", height: 520)
        render(Label("Security", image: "ShieldKey").font(.system(size: 64)).labelStyle(.iconOnly),
               "security tab symbol", height: 120)
    }

    /// Attachments in the detail (with a download button) and in the editor (remove and add), and
    /// the note that a new item must be saved first.
    func testAttachmentSectionsRender() throws {
        let model = VaultModel()
        let attachments = try JSONDecoder().decode([ItemDetail.Attachment].self, from: Data("""
            [{"id":"a1","fileName":"tax-return-2025.pdf","size":"1.4 MB"},{"id":"a2","fileName":"recovery-codes.txt","size":"312 Bytes"}]
            """.utf8))
        render(Form { AttachmentsDetailSection(model: model, itemID: "x", attachments: attachments) }
            .formStyle(.grouped), "attachments detail", height: 200)
        var login = ItemData.new(.login, folderId: nil)
        login.id = "x"
        login.name = "Mail"
        model.editor = ItemEditor(draft: login, original: login, attachments: attachments)
        render(ItemEditorView(model: model), "editor with attachments")
        model.editor = ItemEditor(draft: login.cloned(), original: ItemData(type: 1), isClone: true)
        render(Form { AttachmentsEditorSection(model: model, itemID: nil, attachments: []) }
            .formStyle(.grouped), "attachments editor unsaved item", height: 120)
        model.editor = nil
    }

    /// The strength meter appears under the password once the SDK has scored it.
    func testLoginEditorShowsPasswordStrength() throws {
        let model = VaultModel()
        for (name, password) in [("weak", "password"), ("strong", "VeryStrong123@#")] {
            var login = ItemData.new(.login, folderId: nil)
            login.name = "Mail"
            login.login = LoginData(username: "me", password: password)
            model.editor = ItemEditor(draft: login, original: login)
            render(ItemEditorView(model: model), "editor strength \(name)", height: 500, settle: 1.5)
        }
        model.editor = nil
        render(PasswordStrengthMeter(password: "VeryStrong123@#", inputs: [], email: "").padding().frame(width: 300),
               "meter alone", height: 80, settle: 1.5)
    }

    /// The Export Vault sheet: the unencrypted warning, and both encrypted variants.
    func testExportSheetRenders() {
        let model = VaultModel()
        var account = ExportOptions()
        account.format = .encryptedJSON
        var password = account
        password.protection = .password
        password.filePassword = "hunter2"
        password.confirmation = "hunter3"
        for (name, options) in [("export plain json", ExportOptions()), ("export account restricted", account),
                                ("export password protected", password)] {
            // A sheet gets the window's background from AppKit; an offscreen host needs its own.
            render(ExportSheet(model: model, options: options).background(Color(nsColor: .windowBackgroundColor)), name, height: 480)
        }
    }

    /// The Import Data sheet in each step: choosing, asking for a file password, confirming, done.
    func testImportSheetRenders() throws {
        let model = VaultModel()
        let preview = try JSONDecoder().decode(ImportPreview.self, from: Data(
            #"{"items":12,"folders":2,"skipped":3,"types":[{"type":1,"count":8},{"type":3,"count":1},{"type":2,"count":3}]}"#.utf8))
        for (name, sheet) in [
            ("import choose", ImportSheet(model: model)),
            ("import password", ImportSheet(model: model, needsPassword: true)),
            ("import confirm", ImportSheet(model: model, preview: preview)),
            ("import done", ImportSheet(model: model, result: ImportSummary(items: 12, folders: 2))),
        ] {
            render(sheet.background(Color(nsColor: .windowBackgroundColor)), name, height: 360)
        }
    }

    /// Hosts the full window content and walks the selection like a user would.
    func testLiveWindowSelectionAndEditing() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let model = VaultModel()
        try await wait { model.isReady }
        model.email = email
        model.server = server
        model.password = password
        await model.login()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 660),
                              styleMask: [.titled, .resizable, .closable, .miniaturizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        let host = NSHostingView(rootView: RootView(model: model))
        host.sceneBridgingOptions = [.toolbars, .title]
        window.contentView = host
        window.orderFront(nil)
        defer { window.close() }
        if let login = model.items.first(where: { $0.name == "Seed Login" }) {
            model.select(login.id)
            try await wait { model.detail?.id == login.id }
            try await Task.sleep(for: .milliseconds(1500))
            snapshot(window, "window-light", .aqua)
            snapshot(window, "window-dark", .darkAqua)
        }
        for item in model.items {
            model.select(item.id)
            try await wait { model.detail?.id == item.id }
            try await Task.sleep(for: .milliseconds(item.hasTotp ? 1500 : 400))
            model.beginEditing()
            try await Task.sleep(for: .milliseconds(200))
            model.cancelEditing()
        }
        model.show(.trash)
        model.show(.type(.card))
        model.beginNewItem(.identity)
        try await Task.sleep(for: .milliseconds(300))
        model.cancelEditing()
        await model.lock()
        XCTAssertEqual(model.phase, .locked)
        try await Task.sleep(for: .milliseconds(300))
        await model.logout()
    }

    private func wait(timeout: TimeInterval = 15, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            guard Date() < deadline else { throw XCTSkip("Timed out waiting for condition") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    /// The sign-in screen for each server choice; needs no account.
    func testSignInRendersForEveryServerChoice() async throws {
        for (name, server) in [("us", ""), ("eu", "https://bitwarden.eu"), ("self-hosted", "https://vault.example.com")] {
            let model = VaultModel()
            try await wait { model.isReady }
            model.phase = .loggedOut
            model.email = ""
            model.server = server
            render(LoginView(model: model).background(Color(nsColor: .windowBackgroundColor)), "sign-in-\(name)", height: 620)
        }
    }

    /// Settings while the vault is locked; the unlock options must read as unavailable.
    func testLockedSecuritySettingsRender() async throws {
        let model = VaultModel()
        try await wait { model.isReady }
        model.phase = .locked
        model.biometricEnabled = true
        model.browserBiometricsEnabled = true
        let suite = "render-locked-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        for tab in [SettingsTab.security, .browsers, .app] {
            let view = SettingsView(settings: AppSettings(defaults: defaults), model: model, tab: tab)
            render(view, "locked-settings-\(tab)", height: nil)
        }
        // Unlocked with browser unlock off: the toggle leads and browsers can't be connected yet.
        model.phase = .unlocked
        model.biometricEnabled = false
        model.browserBiometricsEnabled = false
        render(SettingsView(settings: AppSettings(defaults: defaults), model: model, tab: .browsers),
               "browsers-unlock-off", height: nil)
    }

    /// Captures the whole window into `BW_RENDER_DIR`, when set; the README screenshots come from here.
    private func snapshot(_ window: NSWindow, _ name: String, _ appearance: NSAppearance.Name) {
        guard let directory = ProcessInfo.processInfo.environment["BW_RENDER_DIR"] else { return }
        NSApp.appearance = NSAppearance(named: appearance)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        RunLoop.main.run(until: Date().addingTimeInterval(1))
        // An offscreen render leaves the glass sidebar blank, so a real capture is needed, and the test app
        // has no Screen Recording permission. Leave the window number for a capture from outside
        // (`screencapture -l<number> <name>.png`) and wait up to 30 s for the file.
        let png = URL(fileURLWithPath: directory).appendingPathComponent("\(name).png")
        try? "\(window.windowNumber)".write(to: png.deletingPathExtension().appendingPathExtension("window"),
                                            atomically: true, encoding: .utf8)
        let deadline = Date().addingTimeInterval(30)
        while !FileManager.default.fileExists(atPath: png.path), Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        }
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
    }

    /// Renders offscreen; with `BW_RENDER_DIR` set, also writes a PNG there for review.
    private func render(_ view: some View, _ name: String, height: CGFloat? = 900, settle: TimeInterval = 0.2) {
        let host = NSHostingView(rootView: view.frame(width: height == nil ? nil : 520, height: height))
        host.frame = NSRect(origin: .zero, size: height == nil ? host.fittingSize : NSSize(width: 520, height: height!))
        host.appearance = NSAppearance(named: .darkAqua)
        // `.task` only starts once the view is in a window; the window stays out of sight.
        var window: NSWindow?
        if settle > 0.2 {
            let hosting = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            hosting.contentView = host
            hosting.alphaValue = 0
            hosting.orderFrontRegardless()
            window = hosting
        }
        defer { window?.orderOut(nil) }
        RunLoop.main.run(until: Date().addingTimeInterval(settle))
        host.layoutSubtreeIfNeeded()
        if settle > 0.2 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.3))
            host.layoutSubtreeIfNeeded()
            host.displayIfNeeded()
        }
        let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds)
        XCTAssertNotNil(bitmap, name)
        guard let bitmap else { return }
        host.cacheDisplay(in: host.bounds, to: bitmap)
        if let directory = ProcessInfo.processInfo.environment["BW_RENDER_DIR"],
           let png = bitmap.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("\(name).png"))
        }
    }
}
