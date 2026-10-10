import AppKit
import SwiftUI
import XCTest
import os
@testable import Keywarden

/// The generator window and the item editor, read and driven through the accessibility tree of a
/// hosted view. No server is needed: these are the local SDK generators and the editor's controls.
@MainActor
final class GeneratorFlowTests: XCTestCase {
    private let keys = ["generatorOptions", "usernameGeneratorOptions"]
    private var saved: [String: Data] = [:]

    override func setUp() async throws {
        for key in keys { saved[key] = UserDefaults.standard.data(forKey: key) }
        for key in keys { UserDefaults.standard.removeObject(forKey: key) }
    }

    override func tearDown() async throws {
        for key in keys {
            if let data = saved[key] { UserDefaults.standard.set(data, forKey: key) }
            else { UserDefaults.standard.removeObject(forKey: key) }
        }
        GeneratorHistory.shared.sessionChanged(unlocked: false)
    }

    private func generator() -> HostedWindow {
        HostedWindow(GeneratorView(), size: NSSize(width: 400, height: 700))
    }

    /// The Type control switches between the three generators, each with its own options.
    func testTypePickerSwitchesBetweenPasswordPassphraseAndUsername() async throws {
        let hosted = generator()
        defer { hosted.close() }
        var tree = try await hosted.tree(containing: "Length")
        for label in ["Length", "Minimum numbers", "Minimum special", "Avoid ambiguous characters"] {
            XCTAssertTrue(tree.contains(label), "\(label) missing in Password mode")
        }
        let passphrase = try await hosted.press(label: "Passphrase")
        XCTAssertTrue(passphrase)
        tree = try await hosted.tree(containing: "Words")
        XCTAssertTrue(tree.contains("Separator"))
        XCTAssertTrue(tree.contains("Include number"))
        XCTAssertFalse(tree.contains("Length"))
        XCTAssertEqual(GeneratorOptions.stored.mode, .passphrase)

        let username = try await hosted.press(label: "Username", role: "AXRadioButton")
        XCTAssertTrue(username, "Username segment missing: \(tree.texts)")
        tree = try await hosted.tree(containing: "Username type")
        XCTAssertTrue(tree.contains("Username type"))
        XCTAssertTrue(GeneratorOptions.stored.usernameSelected)
        XCTAssertFalse(tree.contains("Words"))

        let password = try await hosted.press(label: "Password", role: "AXRadioButton")
        XCTAssertTrue(password)
        tree = try await hosted.tree(containing: "Length")
        XCTAssertFalse(GeneratorOptions.stored.usernameSelected)
        XCTAssertEqual(GeneratorOptions.stored.mode, .password)
    }

    /// Choosing an email forwarder shows its service picker and only the fields that service needs.
    func testForwarderServicePickerShowsEachServicesFields() async throws {
        var options = GeneratorOptions()
        options.usernameSelected = true
        options.store()
        let extras: [ForwarderService: Set<String>] = [
            .simpleLogin: ["Server URL"], .addy: ["Server URL", "Domain"], .forwardEmail: ["Domain"],
            .firefoxRelay: [], .fastmail: [], .duckDuckGo: [],
        ]
        for service in ForwarderService.allCases {
            var username = UsernameOptions()
            username.kind = .forwarded
            username.service = service
            username.store()
            let hosted = generator()
            defer { hosted.close() }
            let tree = try await hosted.tree(containing: "Service")
            XCTAssertNotNil(tree.node(label: "Service"), "\(service.title): service picker missing")
            XCTAssertTrue(tree.contains(service.title), "\(service.title): picker doesn't show the service")
            XCTAssertTrue(tree.contains(service.secretTitle), "\(service.title): \(service.secretTitle) field missing")
            for field in ["Server URL", "Domain"] {
                XCTAssertEqual(tree.contains(field), extras[service, default: []].contains(field),
                               "\(service.title): \(field)")
            }
            // A forwarder creates an alias only on an explicit click, so the button says Generate.
            XCTAssertTrue(tree.contains("Generate"), "\(service.title)")
            XCTAssertFalse(tree.contains("Regenerate"), "\(service.title)")
        }
    }

    /// Word, plus-addressed and catch-all usernames generate locally; plus-addressed and catch-all
    /// ask for their address first.
    func testUsernameTypesShowTheirFieldsAndGenerateLocally() async throws {
        var options = GeneratorOptions()
        options.usernameSelected = true
        options.store()
        var username = UsernameOptions()
        username.kind = .plusAddressed
        username.email = "you@example.com"
        username.store()
        var hosted = generator()
        var tree = try await hosted.tree(containing: "Email")
        XCTAssertTrue(tree.contains("Email"))
        hosted.close()

        username.kind = .catchAll
        username.catchAllDomain = "example.org"
        username.store()
        hosted = generator()
        tree = try await hosted.tree(containing: "Domain")
        XCTAssertTrue(tree.contains("Domain"))
        hosted.close()

        username.kind = .word
        username.store()
        hosted = generator()
        defer { hosted.close() }
        tree = try await hosted.tree(containing: "Capitalize")
        XCTAssertTrue(tree.contains("Include number"))
        XCTAssertTrue(tree.contains("Regenerate"))
        // A word username generates on open; the result replaces the "No result" placeholder.
        try await Task.sleep(for: .seconds(1))
        tree = try await hosted.tree(settle: 0.2)
        XCTAssertFalse(tree.contains("No result"), "a word username generates on open: \(tree.texts)")
        XCTAssertNotNil(tree.node(label: "Regenerate"))
    }

    /// Regenerate records the username; the History sheet lists it, clears, and once the vault has
    /// locked it hides the values, counting the ones kept for after unlock.
    func testGeneratorHistorySheetListsClearsAndRespectsTheLock() async throws {
        var options = GeneratorOptions()
        options.usernameSelected = true
        options.store()
        GeneratorHistory.shared.sessionChanged(unlocked: true)
        let hosted = generator()
        defer { hosted.close() }
        _ = try await hosted.tree(containing: "Regenerate")
        let regenerated = try await hosted.press(label: "Regenerate")
        XCTAssertTrue(regenerated)
        let deadline = Date().addingTimeInterval(10)
        while GeneratorHistory.shared.entries.isEmpty, Date() < deadline { try await Task.sleep(for: .milliseconds(100)) }
        let entry = try XCTUnwrap(GeneratorHistory.shared.entries.first)
        XCTAssertEqual(entry.kind, .username)

        let opened = try await hosted.press(label: "History")
        XCTAssertTrue(opened)
        var sheet = try await hosted.sheetTree(containing: "Generator history")
        XCTAssertTrue(sheet.contains(entry.value), "the sheet lists the generated value")
        let cleared = try await hosted.press(label: "Clear All", sheet: true)
        XCTAssertTrue(cleared)
        XCTAssertTrue(GeneratorHistory.shared.entries.isEmpty)
        sheet = try await hosted.sheetTree(containing: "No history yet")
        XCTAssertTrue(sheet.contains("No history yet"))

        GeneratorHistory.shared.sessionChanged(unlocked: false)
        GeneratorHistory.shared.record("generated-while-locked", kind: .password)
        sheet = try await hosted.sheetTree(containing: "1 saved value")
        XCTAssertTrue(sheet.contains("Vault locked"))
        XCTAssertFalse(sheet.contains("generated-while-locked"), "values stay hidden while locked")
    }
}

@MainActor
final class EditorFlowTests: XCTestCase {
    private var savedGenerator: [String: Data] = [:]
    private let keys = ["generatorOptions", "usernameGeneratorOptions"]

    override func setUp() async throws {
        for key in keys { savedGenerator[key] = UserDefaults.standard.data(forKey: key); UserDefaults.standard.removeObject(forKey: key) }
    }

    override func tearDown() async throws {
        for key in keys {
            if let data = savedGenerator[key] { UserDefaults.standard.set(data, forKey: key) }
            else { UserDefaults.standard.removeObject(forKey: key) }
        }
    }

    private func login(named name: String = "Mail") -> ItemData {
        var login = ItemData.new(.login, folderId: nil)
        login.id = "x"
        login.name = name
        login.login = LoginData(username: "me", password: "pw", uris: [UriData(uri: "https://mail.example")])
        return login
    }

    /// The wand beside Username generates one with the stored generator options; the one beside
    /// Password generates a password.
    func testWandsGenerateAUsernameAndAPassword() async throws {
        let model = VaultModel()
        var draft = ItemData.new(.login, folderId: nil)
        draft.name = "New"
        model.editor = ItemEditor(draft: draft, original: draft)
        let hosted = HostedWindow(ItemEditorView(model: model), size: NSSize(width: 520, height: 900))
        defer { hosted.close() }
        var tree = try await hosted.tree(containing: "Username")
        XCTAssertEqual(tree.nodes.filter { $0.label == "Magic Wand With Sparkles" }.count, 2,
                       "a wand for the username and one for the password")
        XCTAssertEqual(model.editor?.draft.login?.username, "")
        let username = try await hosted.press(label: "Magic Wand With Sparkles", index: 0)
        XCTAssertTrue(username)
        let deadline = Date().addingTimeInterval(10)
        while model.editor?.draft.login?.username.isEmpty != false, Date() < deadline { try await Task.sleep(for: .milliseconds(100)) }
        XCTAssertFalse(model.editor?.draft.login?.username.isEmpty ?? true, "the wand filled the username")
        XCTAssertEqual(model.editor?.draft.login?.password, "")

        let password = try await hosted.press(label: "Magic Wand With Sparkles", index: 1)
        XCTAssertTrue(password)
        while model.editor?.draft.login?.password.isEmpty != false, Date() < deadline { try await Task.sleep(for: .milliseconds(100)) }
        XCTAssertGreaterThanOrEqual(model.editor?.draft.login?.password.count ?? 0, 8)
        tree = try await hosted.tree(settle: 0.2)
        XCTAssertTrue(model.editor?.isDirty == true)
    }

    /// The brand comes from the number's leading digits; it is never typed.
    func testCardBrandFollowsTheNumber() {
        let cases: [(String, String?)] = [
            ("", nil), ("4111 1111 1111 1111", "Visa"), ("5555555555554444", "Mastercard"),
            ("2223003122003222", "Mastercard"), ("378282246310005", "Amex"), ("6011111111111117", "Discover"),
            ("3056930009020004", "Diners Club"), ("3566002020360505", "JCB"), ("6759649826438453", "Maestro"),
            ("6200000000000005", "UnionPay"), ("6070000000000000", "RuPay"), ("9999", "Other"),
        ]
        for (number, brand) in cases { XCTAssertEqual(CardData.brand(forNumber: number), brand, number) }
        XCTAssertEqual(CardData.grouped("4111111111111111"), "4111 1111 1111 1111")
        XCTAssertEqual(CardData.grouped("378282246310005"), "3782 822463 10005")
        XCTAssertEqual(CardData.grouped("30569309025904"), "3056 930902 5904")
        XCTAssertEqual(CardData.grouped("4111-x"), "4111-x", "non-digits are left alone")
        XCTAssertEqual(CardData.masked("5555555555554444"), "•••• •••• •••• 4444")
        XCTAssertEqual(CardData.masked("378282246310005"), "•••• •••••• •0005")
    }

    /// Typing a card number sets its brand and drops pasted spaces; the editor has no Brand field.
    func testCardEditorDetectsTheBrandFromTheNumber() async throws {
        let model = VaultModel()
        let card = ItemData.new(.card, folderId: nil)
        model.editor = ItemEditor(draft: card, original: card)
        let hosted = HostedWindow(ItemEditorView(model: model), size: NSSize(width: 520, height: 900))
        defer { hosted.close() }
        let tree = try await hosted.tree(containing: "Cardholder name")
        XCTAssertTrue(tree.contains("Brand"))
        XCTAssertNil(tree.nodes(role: "AXTextField").first { $0.label == "Brand" }, "the brand is detected, not edited")
        XCTAssertNotNil(tree.node(label: "Expiration month"))
        XCTAssertNotNil(tree.node(label: "Expiration year"))

        let typed = try await hosted.type("3782 822463 10005", label: "Number")
        XCTAssertTrue(typed)
        XCTAssertEqual(model.editor?.draft.card?.number, "378282246310005")
        XCTAssertEqual(model.editor?.draft.card?.brand, "Amex")
        let shown = try await hosted.tree(containing: "American Express")
        XCTAssertEqual(shown.nodes.first { $0.role == "AXTextField" && $0.label == "Number" }?.value, "3782 822463 10005")
    }

    /// The card detail follows the editor: brand under the number, expiry as one row.
    func testCardDetailMatchesTheEditor() async throws {
        var item = ItemData.new(.card, folderId: nil)
        item.id = "c"
        item.name = "Travel"
        item.card = CardData(cardholderName: "Alex Example", expMonth: "4", expYear: "2031", code: "321",
                             brand: "Amex", number: "378282246310005")
        let detail = ItemDetail(item: item, organizationId: nil, editable: true, viewPassword: true, passkeys: [],
                                passwordHistory: [], attachments: [], creationDate: "2025-03-04T10:00:00Z",
                                revisionDate: "2025-03-04T10:00:00Z", deletedDate: nil, archivedDate: nil,
                                passwordRevisionDate: nil)
        let hosted = HostedWindow(ItemDetailView(model: VaultModel(), detail: detail), size: NSSize(width: 520, height: 900))
        defer { hosted.close() }
        let tree = try await hosted.tree(containing: "04/2031")
        XCTAssertTrue(tree.contains("•••• •••••• •0005"), "the number shows its last four, grouped")
        XCTAssertTrue(tree.texts.contains("•••"), "the code shows its length")
        XCTAssertFalse(tree.contains("378282246310005"))
        let order = ["Cardholder name", "Number", "Brand", "Expiration date", "Security code"]
            .compactMap { label in tree.texts.firstIndex(of: label) }
        XCTAssertEqual(order, order.sorted(), "\(tree.texts)")
        XCTAssertEqual(order.count, 5, "\(tree.texts)")
        XCTAssertTrue(tree.contains("American Express"))
        XCTAssertFalse(tree.contains("Expiration month"))
    }

    /// A login's passkeys are listed; Remove marks them for removal on save, Undo takes it back.
    func testPasskeyRemovalCanBeAskedForAndUndone() async throws {
        let model = VaultModel()
        let item = login()
        let passkey = ItemDetail.Passkey(rpId: "mail.example", userName: "me", creationDate: "2025-03-04T10:00:00Z")
        model.editor = ItemEditor(draft: item, original: item, passkeys: [passkey])
        let hosted = HostedWindow(ItemEditorView(model: model), size: NSSize(width: 520, height: 900))
        defer { hosted.close() }
        var tree = try await hosted.tree(containing: "Item name")
        XCTAssertTrue(tree.texts.contains { $0.hasPrefix("Passkey created") }, "\(tree.texts)")
        XCTAssertTrue(tree.contains("me · mail.example"))
        XCTAssertNil(model.editor?.draft.removePasskeys, "removal is opt-in")

        let removed = try await hosted.press(identifier: "removePasskey")
        XCTAssertTrue(removed)
        XCTAssertEqual(model.editor?.draft.removePasskeys, true)
        XCTAssertTrue(model.editor?.isDirty == true, "removal makes the editor saveable")
        tree = try await hosted.tree(containing: "Passkey will be removed")
        XCTAssertTrue(tree.contains("Passkey will be removed"))
        XCTAssertNil(tree.node(identifier: "removePasskey"))

        let undone = try await hosted.press(label: "Undo")
        XCTAssertTrue(undone)
        XCTAssertNil(model.editor?.draft.removePasskeys)
        XCTAssertFalse(model.editor?.isDirty ?? true)
        tree = try await hosted.tree(containing: "Remove")
        XCTAssertNotNil(tree.node(identifier: "removePasskey"))
    }

    /// The editor lists a saved item's attachments with Remove and Add; a new item or a clone
    /// asks to be saved first. (The panels behind Add are not opened here: AttachmentTests covers
    /// the model calls they feed.)
    func testAttachmentsAppearInTheEditorAndTheDetail() async throws {
        let model = VaultModel()
        let attachments = try JSONDecoder().decode([ItemDetail.Attachment].self, from: Data("""
            [{"id":"a1","fileName":"tax-return-2025.pdf","size":"1.4 MB"},{"id":"a2","fileName":"recovery-codes.txt","size":"312 Bytes"}]
            """.utf8))
        let item = login()
        model.editor = ItemEditor(draft: item, original: item, attachments: attachments)
        var hosted = HostedWindow(ItemEditorView(model: model), size: NSSize(width: 520, height: 1000))
        var tree = try await hosted.tree(containing: "Attachments")
        for name in ["tax-return-2025.pdf", "recovery-codes.txt", "1.4 MB"] {
            XCTAssertTrue(tree.contains(name), "\(name): \(tree.texts)")
        }
        XCTAssertEqual(tree.nodes.filter { $0.identifier == "removeAttachment" }.count, 2)
        XCTAssertNotNil(tree.node(identifier: "addAttachment"))
        XCTAssertNil(tree.node(label: "Save the item first, then add attachments."))
        hosted.close()

        // A clone is a new item: nothing to attach to until it is saved.
        model.editor = ItemEditor(draft: item.cloned(), original: ItemData(type: 1), isClone: true)
        XCTAssertEqual(model.editor?.draft.name, "Mail - Clone")
        hosted = HostedWindow(ItemEditorView(model: model), size: NSSize(width: 520, height: 1000))
        tree = try await hosted.tree(containing: "Save the item first, then add attachments.")
        XCTAssertTrue(tree.contains("Save the item first, then add attachments."))
        XCTAssertNil(tree.node(identifier: "addAttachment"))
        hosted.close()
        model.editor = nil

        // The read-only detail: a download button per file.
        let form = Form { AttachmentsDetailSection(model: model, itemID: "x", attachments: attachments) }.formStyle(.grouped)
        hosted = HostedWindow(form, size: NSSize(width: 520, height: 300))
        defer { hosted.close() }
        tree = try await hosted.tree(containing: "tax-return-2025.pdf")
        XCTAssertEqual(tree.nodes.filter { $0.identifier == "downloadAttachment" }.count, 2)
    }
}

/// The Browsers tab scans off the main thread and keeps the last result.
@MainActor
final class BrowserSettingsFlowTests: XCTestCase {
    private func settings() throws -> AppSettings {
        let suite = "browser-settings-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return AppSettings(defaults: defaults, secure: .memory())
    }

    /// While the scan is still running the tab shows progress and stays responsive; the browsers
    /// appear once it finishes.
    func testTabShowsProgressWhileScanRunsThenBrowsers() async throws {
        let gate = DispatchSemaphore(value: 0)
        let firefox = try XCTUnwrap(BrowserRegistry.browser("firefox"))
        let scanner = BrowserScanner {
            gate.wait()
            return Installer.Scan(browsers: [Installer.BrowserStatus(browser: firefox, app: nil, registration: .none,
                                                                     hasBackup: false, verifiable: true)],
                                  outdated: false, elsewhere: false)
        }
        let hosted = HostedWindow(SettingsView(settings: try settings(), model: VaultModel(), tab: .browsers, scanner: scanner),
                                  size: NSSize(width: 560, height: 600))
        defer { gate.signal(); hosted.close() }
        // The main thread is free to build and read this tree while the scan is blocked.
        let loading = try await hosted.tree(containing: "Looking for browsers…")
        XCTAssertTrue(loading.contains("Looking for browsers…"), "\(loading.texts)")
        XCTAssertTrue(scanner.isScanning)
        XCTAssertNil(scanner.scan)

        gate.signal()
        let done = try await hosted.tree(without: "Looking for browsers…")
        XCTAssertTrue(done.contains("Firefox"), "\(done.texts)")
        XCTAssertFalse(scanner.isScanning)
    }

    /// Asking again during a scan runs exactly one more; opening the tab during a scan adds none.
    func testRefreshDuringScanRunsOnceMore() async throws {
        let count = OSAllocatedUnfairLock(initialState: 0)
        let scanner = BrowserScanner {
            count.withLock { $0 += 1 }
            Thread.sleep(forTimeInterval: 0.1)
            return Installer.Scan(browsers: [], outdated: false, elsewhere: false)
        }
        scanner.refresh()
        scanner.refreshIfIdle()
        scanner.refresh()
        scanner.refresh()
        let deadline = Date().addingTimeInterval(5)
        while count.withLock({ $0 }) < 2 || scanner.isScanning, Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(count.withLock { $0 }, 2)
        XCTAssertEqual(scanner.scan?.browsers, [])
        // With nothing running, the tab appearing starts a scan of its own.
        scanner.refreshIfIdle()
        XCTAssertTrue(scanner.isScanning)
    }
}
