import AppKit
import XCTest

/// A short smoke test of what only a separate app process can show. Everything about the vault
/// itself (lists, details, editing, trash, lock and unlock, settings, generator, export and
/// import) is tested in-process in `Tests/KeywardenTests`; see CONTRIBUTING.md > Tests.
///
/// What stays here, and why:
/// - launching the real app and signing in through the real window against the server, the one
///   end-to-end check that app, UI and server work together;
/// - the menu bar extra, the main menu and keyboard shortcuts, which need a real menu bar and
///   real key dispatch;
/// - windows opening, closing and reopening, and what closing does to the session, which needs
///   the real scene lifecycle;
/// - a read of the real accessibility tree for the detail, editor, generator and settings, since
///   XCUITest reads it across processes (the in-process walk could not reproduce the old
///   `LabeledContent` stack overflow).
///
/// Drives the real app against a disposable server seeded by `cargo test seed_demo_vault`.
/// Pass the account through the runner environment, e.g. `TEST_RUNNER_BW_UI_TEST_SERVER=…`.
@MainActor
final class VaultUITests: XCTestCase {
    private var app: XCUIApplication!

    func testSignInMenusShortcutsAndWindowLifecycle() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_UI_TEST_SERVER"],
              let email = environment["BW_UI_TEST_EMAIL"],
              let password = environment["BW_UI_TEST_PASSWORD"] else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        continueAfterFailure = false
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("keywarden-ui-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = URL(fileURLWithPath: "/tmp/bw-ui-app-\(UUID().uuidString).log")
        app = XCUIApplication()
        app.launchEnvironment["BW_UI_TEST_DATA_DIR"] = directory.path
        app.launchEnvironment["BW_UI_TEST_NAMESPACE"] = UUID().uuidString
        app.launchEnvironment["BW_UI_TEST_LOG"] = log.path
        // The flow finds controls by their English titles, whatever language this Mac uses.
        app.launchArguments += ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()
        defer {
            app.terminate()
            let output = XCTAttachment(contentsOfFile: log)
            output.name = "app-stderr"
            output.lifetime = .keepAlways
            add(output)
        }

        // Sign in through the real window, to the self-hosted server.
        let emailField = app.textFields["Account email"]
        XCTAssertTrue(emailField.waitForExistence(timeout: 15), app.debugDescription)
        emailField.click()
        emailField.typeText(email)
        app.popUpButtons["serverRegion"].firstMatch.click()
        app.menuItems["Self-hosted"].firstMatch.click()
        let serverField = app.textFields["Account server"]
        XCTAssertTrue(serverField.waitForExistence(timeout: 5))
        serverField.click()
        serverField.typeText(server)
        let passwordField = app.secureTextFields["Master password"]
        passwordField.click()
        passwordField.typeText(password + "\r")
        let seedLogin = app.staticTexts["Seed Login"].firstMatch
        XCTAssertTrue(seedLogin.waitForExistence(timeout: 30), app.debugDescription)

        // The real accessibility tree of the detail pane, which once overflowed the stack.
        seedLogin.click()
        XCTAssertTrue(app.staticTexts["One-time code"].waitForExistence(timeout: 10), "TOTP row missing")
        XCTAssertFalse(app.staticTexts["Seed-Password-1"].exists, "Password must start masked")

        // Main menu and shortcuts: ⌘N opens the editor (its tree is read too), the File menu carries
        // the item types, and ⇧⌘E and ⇧⌘I open their sheets.
        app.typeKey("n", modifierFlags: .command)
        XCTAssertTrue(app.textFields["Item name"].waitForExistence(timeout: 5), "⌘N must open the editor")
        app.buttons["Cancel"].firstMatch.click()
        app.menuBars.menuBarItems["File"].click()
        for title in ["New Login", "New Secure Note", "New Card", "New Identity", "New Bank Account",
                      "New Driver’s License", "New Passport", "Import Data…", "Export Vault…"] {
            XCTAssertTrue(app.menuBars.menuItems[title].firstMatch.exists, "File > \(title) missing")
        }
        app.typeKey(.escape, modifierFlags: [])
        app.typeKey("e", modifierFlags: [.command, .shift])
        XCTAssertTrue(app.staticTexts["Export Vault"].firstMatch.waitForExistence(timeout: 5), "⇧⌘E must open Export")
        app.typeKey(.escape, modifierFlags: [])
        app.typeKey("i", modifierFlags: [.command, .shift])
        XCTAssertTrue(app.staticTexts["Import Data"].firstMatch.waitForExistence(timeout: 5), "⇧⌘I must open Import")
        app.typeKey(.escape, modifierFlags: [])

        // ⌘F focuses the toolbar search field.
        app.typeKey("f", modifierFlags: .command)
        let search = app.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        XCTAssertEqual(search.value(forKey: "hasKeyboardFocus") as? Bool, true, "⌘F must focus search")

        // ⌘G opens the generator window; its tree is read as well.
        app.typeKey("g", modifierFlags: .command)
        XCTAssertTrue(app.windows["generator"].firstMatch.waitForExistence(timeout: 5)
                      || app.staticTexts["Regenerate"].firstMatch.waitForExistence(timeout: 5),
                      "⌘G must open the generator")
        app.typeKey("w", modifierFlags: .command)

        // The menu bar extra locks the vault; the master password unlocks it.
        statusMenu("Lock Vault")
        XCTAssertTrue(app.staticTexts["Vault Locked"].waitForExistence(timeout: 10))
        let unlockField = app.secureTextFields["Master password"]
        XCTAssertTrue(unlockField.isEnabled, "Opening a locked vault must not wait on global keys")
        XCTAssertEqual(unlockField.value(forKey: "hasKeyboardFocus") as? Bool, false)
        app.typeKey(.tab, modifierFlags: [])
        XCTAssertEqual(unlockField.value(forKey: "hasKeyboardFocus") as? Bool, true,
                       "Tab explicitly starts secure entry")
        app.typeKey(.tab, modifierFlags: .shift)
        app.typeKey("g", modifierFlags: .command)
        XCTAssertTrue(app.windows["generator"].firstMatch.waitForExistence(timeout: 5))
        app.typeKey("w", modifierFlags: .command)
        XCTAssertEqual(unlockField.value(forKey: "hasKeyboardFocus") as? Bool, false,
                       "Returning from another window must not restore secure entry")
        unlockField.click()
        app.typeKey("h", modifierFlags: .command)
        XCTAssertTrue(app.wait(for: .runningBackground, timeout: 5), "⌘H must still hide secure entry")
        app.activate()
        XCTAssertTrue(unlockField.waitForExistence(timeout: 5))
        XCTAssertEqual(unlockField.value(forKey: "hasKeyboardFocus") as? Bool, false)
        unlockField.click()
        unlockField.typeText(password + "\r")
        XCTAssertTrue(app.staticTexts["Seed Login"].firstMatch.waitForExistence(timeout: 30))

        // Closing the window keeps the resident session. A launcher reopening the menu-bar-only app
        // brings it in front of the app in use, unlocked; it used to stay behind it, last in ⌘Tab.
        app.windows["vault"].firstMatch.buttons[XCUIIdentifierCloseWindow].click()
        XCTAssertTrue(app.staticTexts["Seed Login"].firstMatch.waitForNonExistence(timeout: 5))
        try reopenFromLauncher()
        XCTAssertTrue(app.staticTexts["Seed Login"].firstMatch.waitForExistence(timeout: 10),
                      "Reopening must keep the vault unlocked")

        // With "lock when the window closes" on (settings tree read here), closing locks.
        statusMenu("Settings…")
        let closeToggle = app.switches["lockOnWindowClose"].firstMatch
        XCTAssertTrue(closeToggle.waitForExistence(timeout: 10), app.debugDescription)
        closeToggle.click()
        app.typeKey("w", modifierFlags: .command)
        app.windows["vault"].firstMatch.buttons[XCUIIdentifierCloseWindow].click()
        statusMenu("Open Vault")
        XCTAssertTrue(app.staticTexts["Vault Locked"].waitForExistence(timeout: 10), "Close must lock")
        XCTAssertTrue(app.secureTextFields["Master password"].isEnabled)
        XCTAssertEqual(app.secureTextFields["Master password"].value(forKey: "hasKeyboardFocus") as? Bool, false)
        // Closing the locked vault and opening it from a launcher leaves unlocking available: the
        // password field and Touch ID wait for the window to be key in the active app.
        app.windows["vault"].firstMatch.buttons[XCUIIdentifierCloseWindow].click()
        XCTAssertTrue(app.staticTexts["Vault Locked"].waitForNonExistence(timeout: 5))
        try reopenFromLauncher()
        XCTAssertTrue(app.staticTexts["Vault Locked"].waitForExistence(timeout: 10))
        let enabled = XCTNSPredicateExpectation(predicate: NSPredicate(format: "isEnabled == true"),
                                                object: app.secureTextFields["Master password"])
        XCTAssertEqual(XCTWaiter.wait(for: [enabled], timeout: 5), .completed,
                       "Unlocking must be available after a launcher reopens the locked vault")
        app.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 5), "⌘Q must work from neutral login focus")
    }

    /// Opens the running app again the way Spotlight or a launcher does, while Finder is in front.
    private func reopenFromLauncher() throws {
        XCUIApplication(bundleIdentifier: "com.apple.finder").activate()
        waitUntilInFront("com.apple.finder")
        let bundle = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: "xyz.kuvshynov.Keywarden")
            .first?.bundleURL)
        let opened = expectation(description: "LaunchServices reopened Keywarden")
        NSWorkspace.shared.openApplication(at: bundle, configuration: NSWorkspace.OpenConfiguration()) { _, _ in
            opened.fulfill()
        }
        wait(for: [opened], timeout: 10)
        waitUntilInFront("xyz.kuvshynov.Keywarden")
    }

    /// The app owns the menu bar. An app that AppKit counts as active can still leave the menu bar,
    /// and ⌘Tab's first place, to the app before it.
    private func waitUntilInFront(_ bundleID: String, file: StaticString = #filePath, line: UInt = #line) {
        let owner = NSPredicate { _, _ in NSWorkspace.shared.menuBarOwningApplication?.bundleIdentifier == bundleID }
        let result = XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: owner, object: nil)], timeout: 5)
        XCTAssertEqual(result, .completed, "\(bundleID) doesn't own the menu bar: "
                       + "\(NSWorkspace.shared.menuBarOwningApplication?.bundleIdentifier ?? "none")", file: file, line: line)
    }

    /// Chooses an item from the menu bar extra (the app menu bar has some of the same titles).
    private func statusMenu(_ title: String) {
        let item = app.statusItems["Keywarden"].firstMatch
        item.click()
        item.descendants(matching: .menuItem)[title].firstMatch.click()
    }
}
