import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// The vault window keeps the same title bar whatever it shows, so the close, minimize and zoom
/// buttons stay put when the lock screen gives way to the vault and back. The vault opens with
/// its search field focused.
@MainActor
final class WindowChromeTests: XCTestCase {
    func testTitleBarKeepsItsHeightAcrossLockScreenAndVault() async throws {
        let model = try await readyModel()
        let (window, host) = vaultWindow(model)
        defer { window.close() }

        func chrome() async throws -> (closeButton: CGFloat, content: CGFloat) {
            try await Task.sleep(for: .milliseconds(500))
            host.layoutSubtreeIfNeeded()
            let button = try XCTUnwrap(window.standardWindowButton(.closeButton))
            return (button.convert(button.bounds, to: nil).midY, window.contentLayoutRect.maxY)
        }

        var shown: [VaultModel.Phase: (closeButton: CGFloat, content: CGFloat)] = [:]
        for phase in [VaultModel.Phase.loggedOut, .unlocked, .locked, .loading] {
            model.phase = phase
            shown[phase] = try await chrome()
        }
        let vault = try XCTUnwrap(shown[.unlocked])
        for phase in [VaultModel.Phase.loggedOut, .locked, .loading] {
            let screen = try XCTUnwrap(shown[phase])
            XCTAssertEqual(screen.closeButton, vault.closeButton, accuracy: 0.5, "window buttons move on \(phase)")
            XCTAssertEqual(screen.content, vault.content, accuracy: 0.5, "title bar height changes on \(phase)")
        }
    }

    func testVaultOpensWithTheSearchFieldFocused() async throws {
        let model = try await readyModel()
        let (window, host) = vaultWindow(model)
        defer { window.close() }
        model.phase = .unlocked
        try await Task.sleep(for: .seconds(1))
        XCTAssertTrue(searchFocused(window), "search isn't focused, \(String(describing: window.firstResponder))")

        // ⌘F brings focus back from the list.
        let list = try XCTUnwrap(host.firstDescendant(NSOutlineView.self))
        XCTAssertTrue(window.makeFirstResponder(list))
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertFalse(searchFocused(window))
        model.focusRequest = .search
        try await Task.sleep(for: .milliseconds(500))
        XCTAssertTrue(searchFocused(window), "⌘F doesn't focus search")
    }

    func testNewItemKeepsFocusWhenTheVaultOpens() async throws {
        let model = try await readyModel()
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        model.beginNewItem(.login)
        model.phase = .unlocked
        try await Task.sleep(for: .seconds(1))
        XCTAssertFalse(searchFocused(window), "search took focus from the new item")
    }

    /// The item's toolbar buttons stay put, and lit, when the selection moves, also while the next
    /// item decrypts. They belonged to the detail, which is rebuilt for every item, so they were taken
    /// away and put back, animated, each time.
    func testItemToolbarStaysWhileTheSelectionMoves() async throws {
        let model = try await VaultFlowTests.signedIn(try VaultFlowTests.account())
        let (window, _) = vaultWindow(model)
        defer { window.close() }
        func select(_ name: String) throws {
            model.select(try XCTUnwrap(model.items.first { $0.name == name }, "\(name) missing").id)
        }
        func items() -> [ObjectIdentifier] { (window.toolbar?.items ?? []).map(ObjectIdentifier.init) }

        try select("Seed Login")
        try await Task.sleep(for: .seconds(1))
        let shown = items()
        XCTAssertTrue(window.toolbar?.items.contains { $0.label == "Edit" } == true, "no Edit button")
        // Edit stays on while Mail decrypts: switching it off for those moments dimmed the pencil and
        // lit it again at every selection change.
        HostedWindow(EmptyView()).close() // turns on the accessibility tree that AXTree reads
        let edit = try XCTUnwrap(window.toolbar?.items.first { $0.label == "Edit" }?.view)
        try select("Mail")
        let deadline = Date().addingTimeInterval(2)
        while model.detail?.id != model.selection, Date() < deadline {
            let button = AXTree(edit).nodes.first { $0.role == "AXButton" }
            XCTAssertNotEqual(button?.enabled, false, "Edit went off while the next item loaded")
            try await Task.sleep(for: .milliseconds(5))
        }
        XCTAssertEqual(items(), shown, "the buttons went away while the next item loaded")
        try await Task.sleep(for: .seconds(1))
        XCTAssertEqual(items(), shown, "the buttons were replaced")
    }

    private func readyModel() async throws -> VaultModel {
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        return model
    }

    /// Like the `Window` scene: a unified toolbar that the SwiftUI view fills in.
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

    private func searchFocused(_ window: NSWindow) -> Bool {
        (window.firstResponder as? NSTextView)?.delegate is NSSearchField
    }
}

private extension NSView {
    func firstDescendant<T: NSView>(_ type: T.Type) -> T? {
        for view in subviews {
            if let match = view as? T ?? view.firstDescendant(type) { return match }
        }
        return nil
    }
}
