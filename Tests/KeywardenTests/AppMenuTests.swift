import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// The running app's main menu and reopen handling, driven in-process: shortcuts go through
/// AppKit's key-equivalent matching on the real menu, and a reopen is the delegate call macOS makes
/// when a launcher (Spotlight, Raycast, the Dock) opens the running app. Signs in on the app's own
/// model, which the menu acts on.
@MainActor
final class AppMenuTests: XCTestCase {
    func testShortcutsGeneratorAndReopen() async throws {
        let account = try VaultFlowTests.account()
        await SeededSession.finish() // one session at a time: this test signs in on the app's model
        let delegate = try XCTUnwrap(AppDelegate.current)
        let model = delegate.model
        var deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        if model.phase == .locked { await model.logout() }
        model.email = account.email
        model.server = account.server
        model.password = account.password
        await model.login()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        defer {
            for window in NSApp.windows where window.identifier?.rawValue.hasPrefix("vault") == true
                || window.identifier?.rawValue.hasPrefix("generator") == true { window.close() }
            SecureClipboard.clearIfOwned()
        }

        // The Item menu copies from the selected item.
        let seed = try XCTUnwrap(model.items.first { $0.name == "Seed Login" })
        model.select(seed.id)
        deadline = Date().addingTimeInterval(15)
        while model.detail?.id != seed.id, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        let pasteboard = NSPasteboard.general
        XCTAssertTrue(try shortcut("p"), "⌘P isn't a menu shortcut")
        await expect("⌘P must copy the password") { pasteboard.string(forType: .string) == "Seed-Password-1" }
        XCTAssertTrue(try shortcut("u"))
        await expect("⌘U must copy the username") { pasteboard.string(forType: .string) == "seed.user@example.com" }
        XCTAssertTrue(try shortcut("t"))
        await expect("⌘T must copy the one-time code") { pasteboard.string(forType: .string)?.count == 6 }
        Self.refreshMenus()
        let item = try XCTUnwrap(NSApp.mainMenu?.items.first { $0.title == "Item" }?.submenu, "no Item menu")
        let titles = item.items.map(\.title)
        for title in ["Copy Username", "Copy Password", "Copy Verification Code", "Copy", "Open Website", "Edit", "Clone",
                      "Move to Folder", "Archive", "Move to Trash"] {
            XCTAssertTrue(titles.contains(title), "Item › \(title) missing: \(titles)")
        }
        let copy = try XCTUnwrap(item.items.first { $0.title == "Copy" }?.submenu)
        XCTAssertEqual(copy.items.first?.keyEquivalent, "1", "Item › Copy's first field has ⌥⌘1")

        // A launcher's "open app" opens the vault ready to search, and does again while it is open
        // with focus elsewhere.
        _ = NSApp.delegate?.applicationShouldHandleReopen?(NSApp, hasVisibleWindows: false)
        var vault: NSWindow?
        await expect("reopen must show the vault with search focused") { vault = Self.window("vault"); return vault.map(Self.searchFocused) == true }
        let window = try XCTUnwrap(vault)
        let list = try XCTUnwrap(Self.tables(window).max { $0.convert($0.bounds, to: nil).minX < $1.convert($1.bounds, to: nil).minX })
        window.makeFirstResponder(list)
        XCTAssertFalse(Self.searchFocused(window))
        _ = NSApp.delegate?.applicationShouldHandleReopen?(NSApp, hasVisibleWindows: true)
        await expect("a repeated reopen must focus search") { Self.searchFocused(window) }

        // ⌘G opens the generator, where ⌘R regenerates rather than running Vault › Sync.
        XCTAssertTrue(try shortcut("g"))
        var generator: NSWindow?
        await expect("⌘G must open the generator") { generator = Self.window("generator"); return generator != nil }
        let generatorWindow = try XCTUnwrap(generator)
        try await Task.sleep(for: .seconds(1)) // the window's first value
        // AppKit offers a shortcut to the key window before the main menu, so the window claiming ⌘R
        // means Vault › Sync never sees it. Regenerate records each value it makes in the history.
        let before = GeneratorHistory.shared.entries.count
        XCTAssertTrue(generatorWindow.performKeyEquivalent(with: try Self.keyEvent("r", window: generatorWindow)),
                      "the generator window must claim ⌘R")
        await expect("⌘R in the generator must regenerate") { GeneratorHistory.shared.entries.count > before }

        await model.logout()
    }

    // MARK: Helpers

    /// Presses ⌘`key` through the main menu, as AppKit does for a shortcut no window claims. The
    /// menus are brought up to date first, as AppKit does before showing them: SwiftUI defers that
    /// while the app isn't frontmost, which a test run usually isn't.
    private func shortcut(_ key: String) throws -> Bool {
        Self.refreshMenus()
        return NSApp.mainMenu?.performKeyEquivalent(with: try Self.keyEvent(key, window: nil)) ?? false
    }

    private static func refreshMenus() {
        func refresh(_ menu: NSMenu) {
            menu.delegate?.menuNeedsUpdate?(menu)
            menu.update()
            for item in menu.items { if let submenu = item.submenu { refresh(submenu) } }
        }
        NSApp.mainMenu.map(refresh)
    }

    private static func keyEvent(_ key: String, window: NSWindow?) throws -> NSEvent {
        try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command,
                                       timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: window?.windowNumber ?? 0, context: nil, characters: key,
                                       charactersIgnoringModifiers: key, isARepeat: false, keyCode: 0))
    }

    private func expect(_ message: String, file: StaticString = #filePath, line: UInt = #line,
                        _ condition: () -> Bool) async {
        let met = await eventually(condition)
        XCTAssertTrue(met, message, file: file, line: line)
    }

    private func eventually(_ condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(10)
        while !condition(), Date() < deadline { try? await Task.sleep(for: .milliseconds(100)) }
        return condition()
    }

    private static func window(_ id: String) -> NSWindow? {
        NSApp.windows.first { $0.identifier?.rawValue.hasPrefix(id) == true && $0.isVisible }
    }

    private static func searchFocused(_ window: NSWindow) -> Bool {
        (window.firstResponder as? NSTextView)?.delegate is NSSearchField
    }

    private static func tables(_ window: NSWindow) -> [NSTableView] {
        func walk(_ view: NSView) -> [NSTableView] { ((view as? NSTableView).map { [$0] } ?? []) + view.subviews.flatMap(walk) }
        return window.contentView.map(walk) ?? []
    }
}
