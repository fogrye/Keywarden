import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// The vault works from the keyboard: ↓/↑ and ⏎ from the search field drive the list, Esc goes
/// back, → enters the item's fields, which ↑/↓ walk and ⏎ copies. Copying from the Item menu goes
/// through the same gates as the detail: the shown item only, its re-prompt, and the secure clipboard.
@MainActor
final class KeyboardFlowTests: XCTestCase {
    // MARK: Fields the keyboard can copy

    func testCopyableFieldsFollowTheDetailAndLeaveConcealedValuesOut() {
        var login = ItemData(type: VaultItemType.login.rawValue, name: "Seed")
        login.login = LoginData(username: "me", password: "pw", totp: "JBSWY3DPEHPK3PXP",
                                uris: [UriData(uri: "https://github.com/login"), UriData(uri: ""), UriData(uri: "gist.github.com")])
        login.notes = "note"
        login.fields = [FieldData(name: "Code", value: "secret", type: 1), FieldData(name: "", value: "EU", type: 0),
                        FieldData(name: "On", value: "true", type: 2), FieldData(name: "Empty", value: "", type: 0)]
        let shown = detail(login, viewPassword: true).copyableFields
        XCTAssertEqual(shown.map(\.id), ["login.username", "login.password", "login.totp", "uri.0", "uri.2",
                                         "notes", "field.0", "field.1"])
        XCTAssertEqual(shown.map(\.label), ["Username", "Password", "One-time code", "github.com", "gist.github.com",
                                            "Notes", "Code", "Field"])
        XCTAssertEqual(shown.first { $0.id == "login.totp" }?.kind, .totp)

        // A "hide passwords" share: neither the password nor a hidden field can be copied.
        let concealed = detail(login, viewPassword: false).copyableFields.map(\.id)
        XCTAssertFalse(concealed.contains("login.password"))
        XCTAssertFalse(concealed.contains("field.0"))
        XCTAssertTrue(concealed.contains("login.username"))
    }

    func testCardAndIdentityFieldsKeepTheDetailOrder() {
        var card = ItemData(type: VaultItemType.card.rawValue, name: "Visa")
        card.card = CardData(cardholderName: "Alex", expMonth: "4", expYear: "2031", code: "321", brand: "Visa",
                             number: "4111111111111111")
        let fields = detail(card).copyableFields
        XCTAssertEqual(fields.map(\.id), ["card.name", "card.number", "card.brand", "card.expiration", "card.code"])
        XCTAssertEqual(fields.map(\.value), ["Alex", "4111111111111111", "Visa", "04/2031", "321"])
        XCTAssertEqual(fields[1].mask, "•••• •••• •••• 1111")
        XCTAssertEqual(fields[4].kind, .secret)

        var identity = ItemData(type: VaultItemType.identity.rawValue, name: "Alex")
        identity.identity = IdentityData(title: "Mx", firstName: "Alex", email: "alex@example.com")
        let ids = detail(identity).copyableFields.map(\.id)
        let index = { (path: WritableKeyPath<IdentityData, String?>) in
            CopyableField.specID(IdentityData.specs.firstIndex { $0.path == path }!)
        }
        XCTAssertEqual(ids, [index(\.title), index(\.firstName), index(\.email)])
    }

    // MARK: Search and list

    func testArrowsAndReturnFromSearchDriveTheList() async throws {
        let model = try await modelWithItems(["Alpha", "Bravo", "Charlie"])
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await Task.sleep(for: .seconds(1))
        XCTAssertTrue(searchFocused(window), "search isn't focused")
        let ids = model.visibleItems.map(\.id)

        try await key(window, .down, throughApp: true)
        XCTAssertEqual(model.selection, ids[0], "↓ selects the first result")
        try await key(window, .down, throughApp: true)
        XCTAssertEqual(model.selection, ids[1])
        try await key(window, .up, throughApp: true)
        XCTAssertEqual(model.selection, ids[0])
        XCTAssertTrue(searchFocused(window), "↓/↑ must leave focus in search")

        try await key(window, .return)
        XCTAssertTrue(listFocused(window), "⏎ moves to the list, \(String(describing: window.firstResponder))")
        XCTAssertEqual(model.selection, ids[0], "⏎ keeps a visible selection")

        try await key(window, .escape)
        XCTAssertTrue(searchFocused(window), "Esc in the list returns to search")
    }

    func testArrowNavigationKeepsTheSelectedRowVisible() async throws {
        let model = try await modelWithItems((0..<45).map { String(format: "Entry %02d", $0) })
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await Task.sleep(for: .seconds(1))
        let ids = model.visibleItems.map(\.id)

        func assertVisible(_ index: Int, file: StaticString = #filePath, line: UInt = #line) throws {
            func tables(_ view: NSView) -> [NSTableView] {
                ((view as? NSTableView).map { [$0] } ?? []) + view.subviews.flatMap(tables)
            }
            let host = try XCTUnwrap(window.contentView, file: file, line: line)
            let table = try XCTUnwrap(tables(host).first { $0.numberOfRows == ids.count }, file: file, line: line)
            XCTAssertEqual(model.selection, ids[index], file: file, line: line)
            XCTAssertEqual(table.selectedRow, index, file: file, line: line)
            XCTAssertTrue(table.visibleRect.contains(table.rect(ofRow: index)),
                          "Selected row \(index) is outside the list viewport", file: file, line: line)
        }

        for _ in 0..<25 { try await key(window, .down, throughApp: true) }
        try assertVisible(24)
        XCTAssertTrue(searchFocused(window), "scrolling must not steal search focus")

        // Search rebuilds the list even when the selected result survives.
        model.search = "Entry"
        try await Task.sleep(for: .milliseconds(500))
        try assertVisible(24)
        model.search = ""
        try await Task.sleep(for: .milliseconds(500))
        try assertVisible(24)

        if let directory = ProcessInfo.processInfo.environment["BW_RENDER_DIR"],
           let host = window.contentView, let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: bitmap)
            if let png = bitmap.representation(using: .png, properties: [:]) {
                try png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("keyboard-list-scroll.png"))
            }
        }

        for _ in 0..<24 { try await key(window, .up, throughApp: true) }
        try assertVisible(0)
        try await key(window, .return)
        XCTAssertTrue(listFocused(window))
        for _ in 0..<24 { try await key(window, .down) }
        try assertVisible(24)
        for _ in 0..<24 { try await key(window, .up) }
        try assertVisible(0)
    }

    func testArrowKeysActOnlyInTheirOwnWindow() async throws {
        let first = try await modelWithItems(["Alpha"])
        let (old, _) = vaultWindow(first)
        try await Task.sleep(for: .seconds(1))
        old.close()
        let other = try await modelWithItems(["Bravo"])
        let (background, _) = vaultWindow(other)
        defer { background.close() }
        let model = try await modelWithItems(["Charlie"])
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await Task.sleep(for: .seconds(1))
        try await key(window, .down, throughApp: true)
        XCTAssertEqual(model.selection, model.visibleItems.first?.id, "the key went to another window's list")
        XCTAssertNil(first.selection)
        XCTAssertNil(other.selection)
    }

    func testReturnSelectsTheFirstResultWhenNothingVisibleIsSelected() async throws {
        let model = try await modelWithItems(["Alpha", "Bravo"])
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await Task.sleep(for: .seconds(1))
        try await key(window, .return)
        XCTAssertEqual(model.selection, model.visibleItems.first?.id)
        XCTAssertTrue(listFocused(window))
    }

    func testFocusReachesARebuiltList() async throws {
        let model = try await modelWithItems(["Alpha", "Bravo"])
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await Task.sleep(for: .seconds(1))
        // As View › All Items (⌘1) does: a new destination rebuilds the list, which then takes focus.
        model.show(.favorites)
        model.show(.all)
        model.focusRequest = .list
        try await Task.sleep(for: .milliseconds(500))
        XCTAssertTrue(listFocused(window), "\(String(describing: window.firstResponder))")
    }

    // MARK: Against the server

    func testCopyUsesTheShownItemOnlyAndTheSecureClipboard() async throws {
        let model = try await VaultFlowTests.signedIn(try VaultFlowTests.account())
        try await open(model, "Seed Login")
        let pasteboard = NSPasteboard.general

        await model.copy(CopyableField.password)
        XCTAssertEqual(pasteboard.string(forType: .string), "Seed-Password-1")
        XCTAssertNotNil(pasteboard.data(forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")),
                        "copies must be marked concealed")
        await model.copy(CopyableField.username)
        XCTAssertEqual(pasteboard.string(forType: .string), "seed.user@example.com")
        await model.copy(CopyableField.totp)
        XCTAssertEqual(pasteboard.string(forType: .string)?.count, 6, "⌘T copies the current code, not the key")

        // Not while editing, and not a detail that belongs to another selection.
        SecureClipboard.copy("marker")
        model.beginEditing()
        await model.copy(CopyableField.password)
        XCTAssertEqual(pasteboard.string(forType: .string), "marker", "copied while the editor was open")
        model.cancelEditing()
        let mail = try XCTUnwrap(model.items.first { $0.name == "Mail" })
        model.select(mail.id)
        await model.copy(CopyableField.password) // Mail's detail hasn't loaded yet
        XCTAssertEqual(pasteboard.string(forType: .string), "marker", "copied before the selection's detail loaded")
        SecureClipboard.clearIfOwned()
    }

    func testRepromptItemsAskBeforeCopyingOncePerSelection() async throws {
        let model = try await VaultFlowTests.signedIn(try VaultFlowTests.account())
        let original = Reprompt.authenticate
        defer { Reprompt.authenticate = original }
        var asked = 0
        var answer = false
        Reprompt.authenticate = { _ in asked += 1; return answer }
        try await open(model, "Router admin")
        SecureClipboard.copy("marker")

        await model.copy(CopyableField.password)
        XCTAssertEqual(asked, 1)
        XCTAssertEqual(NSPasteboard.general.string(forType: .string), "marker", "a refused re-prompt must not copy")
        XCTAssertTrue(model.shownItemLocked)

        answer = true
        await model.copy(CopyableField.password)
        await model.copy(CopyableField.username)
        XCTAssertEqual(asked, 2, "a passed re-prompt lasts for the selection")
        XCTAssertEqual(NSPasteboard.general.string(forType: .string), "admin")
        XCTAssertFalse(model.shownItemLocked)

        try await open(model, "Mail")
        try await open(model, "Router admin")
        XCTAssertTrue(model.shownItemLocked, "selecting another item must ask again")
        SecureClipboard.clearIfOwned()
    }

    func testDetailRowsWalkWithTheKeyboard() async throws {
        let model = try await VaultFlowTests.signedIn(try VaultFlowTests.account())
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        defer { model.search = "" }
        model.search = "seed" // as typed: the list is rebuilt for the results
        try await open(model, "Seed Login")
        try await Task.sleep(for: .seconds(1))
        model.focusRequest = .list // as ⏎ in the search field does
        try await Task.sleep(for: .milliseconds(500))

        try await key(window, .right) // username
        try await focusLeavesTheList(window)
        try await key(window, .down) // password
        try await key(window, .return)
        XCTAssertEqual(NSPasteboard.general.string(forType: .string), "Seed-Password-1", "⏎ copies the focused row")

        try await key(window, .down) // one-time code
        try await key(window, .up) // password
        try await key(window, .space)
        let host = try XCTUnwrap(window.contentView)
        HostedWindow(EmptyView()).close() // turns on the accessibility tree that AXTree reads
        let deadline = Date().addingTimeInterval(5)
        while !AXTree(host).contains("Seed-Password-1"), Date() < deadline { try await Task.sleep(for: .milliseconds(200)) }
        XCTAssertTrue(AXTree(host).contains("Seed-Password-1"), "Space reveals the focused secret")

        try await key(window, .escape)
        XCTAssertTrue(listFocused(window), "Esc returns to the list, \(String(describing: window.firstResponder))")
        SecureClipboard.clearIfOwned()
    }

    func testEnteringARepromptItemAsksFirst() async throws {
        let model = try await VaultFlowTests.signedIn(try VaultFlowTests.account())
        let original = Reprompt.authenticate
        defer { Reprompt.authenticate = original }
        var asked = 0
        Reprompt.authenticate = { _ in asked += 1; return true }
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        try await open(model, "Router admin")
        try await Task.sleep(for: .seconds(1))
        model.focusRequest = .list
        try await Task.sleep(for: .milliseconds(500))

        try await key(window, .right)
        try await focusLeavesTheList(window)
        XCTAssertEqual(asked, 1, "→ asks for the re-prompt")
        try await key(window, .return) // the first row, the username
        XCTAssertEqual(NSPasteboard.general.string(forType: .string), "admin")
        SecureClipboard.clearIfOwned()
    }

    // MARK: Helpers

    private func detail(_ item: ItemData, viewPassword: Bool = true) -> ItemDetail {
        ItemDetail(item: item, organizationId: nil, editable: true, viewPassword: viewPassword, passkeys: [],
                   passwordHistory: [], attachments: [], creationDate: "", revisionDate: "", deletedDate: nil,
                   archivedDate: nil, passwordRevisionDate: nil)
    }

    /// A vault of logins without the server. The model restores its stored state first, which
    /// would otherwise replace the items.
    private func modelWithItems(_ names: [String]) async throws -> VaultModel {
        let items = names.map { name in
            #"{"id":"\#(UUID().uuidString)","name":"\#(name)","type":1,"favorite":false,"folderId":null,"organizationId":null,"subtitle":"","searchValues":[],"hasTotp":false,"hasPasskey":false,"deleted":false,"archived":false,"revisionDate":"2026-01-01T00:00:00Z","iconHost":null}"#
        }
        let json = #"{"email":"a@example.test","server":"http://127.0.0.1:1","accountId":"\#(UUID().uuidString)","accountHash":"\#(String(repeating: "a", count: 64))","generation":1,"lastSync":null,"items":[\#(items.joined(separator: ","))],"folders":[],"failures":[]}"#
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        model.loadForTesting(try JSONDecoder().decode(VaultSnapshot.self, from: Data(json.utf8)))
        return model
    }

    /// Selects an item and waits until its detail is loaded.
    private func open(_ model: VaultModel, _ name: String) async throws {
        let item = try XCTUnwrap(model.items.first { $0.name == name }, "\(name) missing")
        model.select(item.id)
        let deadline = Date().addingTimeInterval(15)
        while model.detail?.id != item.id, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertEqual(model.detail?.id, item.id, "\(name) detail did not load")
    }

    /// Like the `Window` scene: a unified toolbar that the SwiftUI view fills in (as `WindowChromeTests`).
    private func vaultWindow(_ model: VaultModel) -> (NSWindow, NSView) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 660),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.toolbarStyle = .unified
        let host = NSHostingView(rootView: RootView(model: model))
        host.sceneBridgingOptions = [.toolbars, .title]
        window.contentView = host
        window.makeKeyAndOrderFront(nil)
        return (window, host)
    }

    private enum Key {
        case up, down, left, right, `return`, escape, space

        var code: (UInt16, String, NSEvent.ModifierFlags) {
            let arrow: NSEvent.ModifierFlags = [.numericPad, .function]
            return switch self {
            case .up: (126, String(UnicodeScalar(UInt32(NSUpArrowFunctionKey))!), arrow)
            case .down: (125, String(UnicodeScalar(UInt32(NSDownArrowFunctionKey))!), arrow)
            case .left: (123, String(UnicodeScalar(UInt32(NSLeftArrowFunctionKey))!), arrow)
            case .right: (124, String(UnicodeScalar(UInt32(NSRightArrowFunctionKey))!), arrow)
            case .return: (36, "\r", [])
            case .escape: (53, "\u{1b}", [])
            case .space: (49, " ", [])
            }
        }
    }

    /// Presses a key in the window. `throughApp` sends it through the app, where event monitors see
    /// it (the search field's arrows).
    private func key(_ window: NSWindow, _ key: Key, throughApp: Bool = false) async throws {
        let (code, characters, flags) = key.code
        for type in [NSEvent.EventType.keyDown, .keyUp] {
            let event = try XCTUnwrap(NSEvent.keyEvent(
                with: type, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber, context: nil, characters: characters,
                charactersIgnoringModifiers: characters, isARepeat: false, keyCode: code))
            if throughApp { NSApp.sendEvent(event) } else { window.sendEvent(event) }
        }
        try await Task.sleep(for: .milliseconds(400))
    }

    /// Waits for → to move focus into the item's rows, which happens after the detail answers.
    private func focusLeavesTheList(_ window: NSWindow) async throws {
        let deadline = Date().addingTimeInterval(5)
        while listFocused(window), Date() < deadline { try await Task.sleep(for: .milliseconds(100)) }
        XCTAssertFalse(listFocused(window), "→ didn't move focus into the item")
        try await Task.sleep(for: .milliseconds(200))
    }

    private func searchFocused(_ window: NSWindow) -> Bool {
        (window.firstResponder as? NSTextView)?.delegate is NSSearchField
    }

    /// The item list has focus: a table in the content column, right of the sidebar.
    private func listFocused(_ window: NSWindow) -> Bool {
        guard let table = window.firstResponder as? NSTableView else { return false }
        return table.convert(table.bounds, to: nil).minX > 150
    }
}
