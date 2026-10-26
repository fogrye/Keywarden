import AppKit
import LocalAuthentication
import SwiftUI
import XCTest
@testable import Keywarden

/// Touch ID prompts say who is asking, and a browser request can never hold the prompt the app
/// needs for its own unlock.
final class TouchIDPromptTests: XCTestCase {
    private let coordinator = BiometricCoordinator.shared
    private let browser: UInt64 = 77_001
    private let other: UInt64 = 77_002

    override func tearDown() {
        coordinator.cancel(browser)
        coordinator.cancel(other)
        coordinator.cancel(BiometricCoordinator.appConnection)
    }

    /// Browser unlock is on only while its Keychain item exists. A flag planted in UserDefaults,
    /// where earlier builds kept it, never turns it on and is discarded.
    @MainActor func testPlantedBrowserUnlockFlagIsIgnored() {
        let hash = (0..<64).map { _ in String("0123456789abcdef".randomElement()!) }.joined()
        defer { BrowserUnlockPreference.set(false, hash) }
        AppSettings.accountDefaults.set(true, forKey: "firefoxBiometrics.\(hash)")
        XCTAssertFalse(BrowserUnlockPreference.isEnabled(hash))
        XCTAssertNil(AppSettings.accountDefaults.object(forKey: "firefoxBiometrics.\(hash)"))
        BrowserUnlockPreference.set(true, hash)
        XCTAssertTrue(BrowserUnlockPreference.isEnabled(hash))
        BrowserUnlockPreference.set(false, hash)
        XCTAssertFalse(BrowserUnlockPreference.isEnabled(hash))
    }

    func testPromptsNameTheRequestingBrowser() {
        coordinator.register(connection: browser, requester: "Zen")
        let key = coordinator.reason(connection: browser, email: "me@example.com", server: "https://vault", releasesKey: true)
        XCTAssertEqual(key, "send the vault key for me@example.com to Zen")
        let confirm = coordinator.reason(connection: browser, email: "me@example.com", server: "https://vault", releasesKey: false)
        XCTAssertEqual(confirm, "confirm me@example.com for Zen")
        XCTAssertTrue(coordinator.reason(connection: other, email: "a", server: "b", releasesKey: true)
            .hasSuffix("an unidentified app"), "Unregistered connections must not look trustworthy")
        XCTAssertEqual(coordinator.reason(connection: BiometricCoordinator.appConnection, email: "me@example.com",
                                          server: "https://vault", releasesKey: true),
                       "unlock me@example.com (https://vault)")
    }

    func testAppUnlockDisplacesABrowserPromptButNotTheReverse() {
        let first = LAContext(), second = LAContext(), app = LAContext(), late = LAContext()
        XCTAssertEqual(coordinator.claimPrompt(first, connection: browser)?.count, 0)
        XCTAssertNil(coordinator.claimPrompt(second, connection: other), "One browser prompt at a time")
        let displaced = coordinator.claimPrompt(app, connection: BiometricCoordinator.appConnection)
        XCTAssertTrue(displaced?.first === first, "The app's unlock cancels the pending browser prompt")
        XCTAssertNil(coordinator.claimPrompt(late, connection: browser), "Browsers wait while the app prompts")
        // The displaced browser request finishing must not free the app's slot.
        coordinator.release(first, connection: browser)
        XCTAssertNil(coordinator.claimPrompt(late, connection: other))
        coordinator.release(app, connection: BiometricCoordinator.appConnection)
        XCTAssertNotNil(coordinator.claimPrompt(late, connection: other))
        coordinator.release(late, connection: other)
    }

    @MainActor func testSecureEntryRequiresExplicitFocusAcrossWindowLifecycle() async throws {
        let account = try VaultFlowTests.account()
        let model = try await isolatedSession(account)
        await model.lock()
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "Master password")

        // Tab enters the native secure field; ordinary text goes through its field editor.
        try await key(hosted.window, code: 48, characters: "\t")
        XCTAssertTrue(secureFocused(hosted.window), "Tab must reach the password from neutral focus")
        try await enter("first entry", in: hosted, label: "Master password", click: false)
        XCTAssertEqual(model.password, "first entry")

        let other = HostedWindow(TextField("Other window", text: .constant("")))
        defer { other.close() }
        try await activate(other)
        XCTAssertTrue(NSApp.isActive, "This must exercise key loss without app deactivation")
        XCTAssertFalse(secureFocused(hosted.window))
        _ = try await other.tree()
        let typedOther = try await other.type("other entry", label: "Other window")
        XCTAssertTrue(typedOther)
        let otherResponder = other.window.firstResponder
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "Master password")
        try await enter("second entry", in: hosted, label: "Master password")
        XCTAssertEqual(model.password, "second entry")

        let finder = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.finder").first)
        NSApp.yieldActivation(to: finder)
        XCTAssertTrue(finder.activate(options: []))
        try await wait { !NSApp.isActive }
        XCTAssertFalse(secureFocused(hosted.window), "Deactivation must release the secure editor")
        XCTAssertEqual(model.password, "second entry", "Backgrounding must not discard entered text")
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "Master password")
        try await enter("before close", in: hosted, label: "Master password")

        // Close the actual owner, not just a notification; queued callbacks must not touch another window.
        hosted.close()
        try await activate(other)
        XCTAssertTrue(other.window.makeFirstResponder(otherResponder))
        _ = try await other.tree()
        XCTAssertFalse(hosted.window.isVisible)
        XCTAssertFalse(secureFocused(hosted.window))
        XCTAssertTrue(other.window.firstResponder === otherResponder)
        // The vault scene shows a closed window again with the same lock screen still in it.
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "Master password")
        hosted.close()
        let reopened = HostedWindow(RootView(model: model))
        defer { reopened.close() }
        try await activate(reopened)
        try await assertNeutralEntry(reopened, label: "Master password")
        try await enter(account.password, in: reopened, label: "Master password")
        try await key(reopened.window, code: 36, characters: "\r")
        try await wait { model.phase == .unlocked }
        try await assertSeedContent(reopened)
    }

    @MainActor func testPinAndMasterPasswordModesRemainUsable() async throws {
        let account = try VaultFlowTests.account()
        let model = try await isolatedSession(account)
        let enabled = await model.enablePin("472691")
        XCTAssertTrue(enabled, model.errorMessage ?? "")
        await model.lock()
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "PIN")
        try await enter("000000", in: hosted, label: "PIN")
        try await press(hosted, label: "Unlock vault")
        try await wait { model.errorMessage != nil && !model.isBusy }
        XCTAssertEqual(model.phase, .locked)
        try await dismissError(hosted, model: model)
        let pinControl = try await secureControl(hosted, label: "PIN")
        XCTAssertTrue(pinControl.isEnabled)
        try await enter("472691", in: hosted, label: "PIN")
        try await press(hosted, label: "Unlock vault")
        try await wait { model.phase == .unlocked }
        try await assertSeedContent(hosted)

        await model.lock()
        try await assertNeutralEntry(hosted, label: "PIN")
        try await press(hosted, label: "Use master password")
        _ = try await secureControl(hosted, label: "Master password")
        XCTAssertTrue(secureFocused(hosted.window), "Explicit mode switches may focus secure entry")
        try await press(hosted, label: "Use PIN")
        _ = try await secureControl(hosted, label: "PIN")
        XCTAssertTrue(secureFocused(hosted.window))
        try await press(hosted, label: "Use master password")
        try await enter(account.password, in: hosted, label: "Master password")
        try await key(hosted.window, code: 36, characters: "\r")
        try await wait { model.phase == .unlocked }
        try await assertSeedContent(hosted)
        await model.disablePin()
        XCTAssertFalse(model.pinEnabled)
    }

    /// Uses isolated Debug credentials and real SDK key material, not a physical fingerprint.
    @MainActor func testBiometricFailureDoesNotStrandSecureEntryAndRetryUnlocks() async throws {
        let account = try VaultFlowTests.account()
        var model = try await isolatedSession(account)
        try await SDKClient.shared.enrollBiometrics(generation: SDKClient.shared.generation())
        await model.lock()
        model = try await restoredLockedModel()
        XCTAssertTrue(model.biometricEnabled, "Enrollment must be discovered from credentials")
        let status = try await SDKClient.shared.status()
        let hash = try XCTUnwrap(status.accountHash)
        let hosted = HostedWindow(RootView(model: model))
        defer { hosted.close() }
        try await activate(hosted)
        try await assertNeutralEntry(hosted, label: "Master password")
        try PlatformCredentials.delete(PlatformCredentials.biometric, hash)
        XCTAssertTrue(model.biometricEnabled, "The visible flag deliberately precedes enrollment removal")
        try await enter("partial entry", in: hosted, label: "Master password")
        try await press(hosted, label: "Unlock with Touch ID")
        try await wait { model.errorMessage != nil && !model.isBusy }
        XCTAssertEqual(model.phase, .locked)
        try await dismissError(hosted, model: model)
        try await assertNeutralEntry(hosted, label: "Master password")
        try await enter(account.password, in: hosted, label: "Master password")
        try await key(hosted.window, code: 36, characters: "\r")
        try await wait { model.phase == .unlocked }
        try await assertSeedContent(hosted)
        hosted.close()

        try await SDKClient.shared.enrollBiometrics(generation: SDKClient.shared.generation())
        await model.lock()
        model = try await restoredLockedModel()
        let retry = HostedWindow(RootView(model: model))
        defer { retry.close() }
        try await activate(retry)
        try await assertNeutralEntry(retry, label: "Master password")
        try await press(retry, label: "Unlock with Touch ID")
        try await wait { model.phase == .unlocked }
        try await assertSeedContent(retry)
        XCTAssertNil(model.errorMessage)
        await model.disableBiometrics()
    }

    /// The automatic prompt follows the lock screen being brought to the front, never a lock that
    /// happens in front of the user. Isolated credentials answer it without a fingerprint.
    @MainActor func testAutomaticTouchIDAsksOnlyWhenBroughtToFront() async throws {
        let account = try VaultFlowTests.account()
        var model = try await isolatedSession(account)
        try await SDKClient.shared.enrollBiometrics(generation: SDKClient.shared.generation())
        await model.lock()
        model = try await restoredLockedModel()
        let hosted = HostedWindow(RootView(model: model, autoTouchID: true))
        defer { hosted.close() }
        // Starting locked: opening the window asks.
        try await activate(hosted)
        try await wait { model.phase == .unlocked }

        await model.lock()
        try await Task.sleep(for: .seconds(1))
        XCTAssertEqual(model.phase, .locked, "Locking in front of the user must not ask")
        try await assertNeutralEntry(hosted, label: "Master password")

        try await deactivate()
        try await activate(hosted)
        try await wait { model.phase == .unlocked }

        try await deactivate()
        await model.lock()
        try await Task.sleep(for: .milliseconds(500))
        XCTAssertEqual(model.phase, .locked, "Nothing may ask while Keywarden is in the background")
        try await activate(hosted)
        try await wait { model.phase == .unlocked }
        await model.disableBiometrics()
    }

    @MainActor func testCancelledEnrollmentReadCannotDisplaceBrowserPrompt() async throws {
        let account = try VaultFlowTests.account()
        var model = try await isolatedSession(account)
        try await SDKClient.shared.enrollBiometrics(generation: SDKClient.shared.generation())
        await model.lock()
        model = try await restoredLockedModel()
        let status = try await SDKClient.shared.status()
        let id = try XCTUnwrap(status.accountId)
        let hash = try XCTUnwrap(status.accountHash)
        func restoreIdentity() {
            coordinator.configure(id: id, hash: hash, server: account.server, email: account.email)
            coordinator.setBrowserEnabled(model.browserBiometricsEnabled)
        }
        defer { restoreIdentity() }
        let disposableID = UUID().uuidString
        coordinator.configure(id: disposableID, hash: String(repeating: "a", count: 64),
                              server: account.server, email: account.email)
        let held = LAContext(), late = LAContext()
        defer { coordinator.release(held, connection: browser); coordinator.release(late, connection: other) }
        XCTAssertNotNil(coordinator.claimPrompt(held, connection: browser))
        let read = Task.detached {
            // Cancellation-aware suspension guarantees the actual read runs with cancellation set.
            try? await Task.sleep(for: .seconds(30))
            return BiometricCoordinator.shared.readAuthorizedEnrollment(
                id: disposableID, connection: BiometricCoordinator.appConnection, browser: false)
        }
        read.cancel()
        let authorization = await read.value
        XCTAssertNil(authorization)
        XCTAssertNil(coordinator.claimPrompt(late, connection: other),
                     "The cancelled app read must not displace the browser's held context")
        coordinator.release(held, connection: browser)
        XCTAssertNotNil(coordinator.claimPrompt(late, connection: other))
        coordinator.release(late, connection: other)
        restoreIdentity()

        let cancelled = Task { @MainActor in
            try? await Task.sleep(for: .seconds(30))
            await model.unlockBiometrics()
        }
        cancelled.cancel()
        await cancelled.value
        let afterCancellation = try await SDKClient.shared.status()
        XCTAssertEqual(afterCancellation.phase, .locked)
        XCTAssertEqual(model.phase, .locked)
        XCTAssertFalse(model.isBusy)
        XCTAssertNil(model.errorMessage)
        await model.unlockBiometrics()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        XCTAssertTrue(model.items.contains { $0.name == "Seed Login" })
        await model.disableBiometrics()
    }

    // MARK: Real account and native responder helpers

    @MainActor private func isolatedSession(_ account: VaultFlowTests.Account) async throws -> VaultModel {
        #if !DEBUG
        throw XCTSkip("These credential regressions require the isolated Debug credential store")
        #else
        guard ProcessInfo.processInfo.environment["BW_TEST_NAMESPACE"].flatMap(UUID.init(uuidString:)) != nil else {
            throw XCTSkip("An isolated Debug credential namespace is required")
        }
        let model = try await VaultFlowTests.signedIn(account)
        addTeardownBlock { @MainActor in
            if let status = try? await SDKClient.shared.status(), let hash = status.accountHash {
                try? PlatformCredentials.delete(PlatformCredentials.biometric, hash)
                BrowserUnlockPreference.set(false, hash)
                try? PlatformCredentials.delete(PlatformCredentials.pin, hash)
            }
            await SeededSession.finish()
        }
        return model
        #endif
    }

    @MainActor private func restoredLockedModel() async throws -> VaultModel {
        let model = VaultModel()
        try await wait { model.isReady }
        XCTAssertEqual(model.phase, .locked)
        SeededSession.model = model
        return model
    }

    @MainActor private func wait(_ predicate: () -> Bool, timeout: TimeInterval = 15,
                                 file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !predicate(), Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertTrue(predicate(), "The expected real UI/authentication transition did not finish", file: file, line: line)
    }

    @MainActor private func activate(_ hosted: HostedWindow) async throws {
        NSApp.unhide(nil)
        NSApp.activate(ignoringOtherApps: true)
        hosted.window.makeKeyAndOrderFront(nil)
        try await wait { NSApp.isActive && hosted.window.isKeyWindow }
        _ = try await hosted.tree()
        // Accessibility priming can finish the app's initial scene presentation.
        // Establish this fixture's ownership after that presentation has settled.
        hosted.window.makeKeyAndOrderFront(nil)
        try await wait { NSApp.isActive && hosted.window.isKeyWindow }
        try await Task.sleep(for: .milliseconds(100))
    }

    @MainActor private func deactivate() async throws {
        let finder = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.finder").first)
        NSApp.yieldActivation(to: finder)
        XCTAssertTrue(finder.activate(options: []))
        try await wait { !NSApp.isActive }
    }

    @MainActor private func secureFocused(_ window: NSWindow) -> Bool {
        (window.firstResponder as? NSTextView)?.delegate is NSSecureTextField
    }

    @MainActor private func secureControl(_ hosted: HostedWindow, label: String) async throws -> NSSecureTextField {
        let tree = try await hosted.tree(containing: label)
        let controls = tree.nodes.filter { $0.label == label }.compactMap { node -> NSSecureTextField? in
            let target = (node.element as? NSCell)?.controlView ?? node.element
            return target as? NSSecureTextField
        }
        return try XCTUnwrap(controls.first, "Entry must remain a native secure text field")
    }

    @MainActor private func assertNeutralEntry(_ hosted: HostedWindow, label: String,
                                               file: StaticString = #filePath, line: UInt = #line) async throws {
        let control = try await secureControl(hosted, label: label)
        XCTAssertTrue(control.isEnabled,
                      "active=\(NSApp.isActive) key=\(hosted.window.isKeyWindow) visible=\(hosted.window.isVisible)",
                      file: file, line: line)
        XCTAssertFalse(secureFocused(hosted.window), "Presentation/activation must not own secure entry")
    }

    @MainActor private func enter(_ text: String, in hosted: HostedWindow, label: String,
                                  click: Bool = true) async throws {
        let control = try await secureControl(hosted, label: label)
        if click {
            let point = control.convert(NSPoint(x: control.bounds.midX, y: control.bounds.midY), to: nil)
            for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                let event = try XCTUnwrap(NSEvent.mouseEvent(
                    with: type, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                    windowNumber: hosted.window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1))
                hosted.window.sendEvent(event)
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertTrue(secureFocused(hosted.window),
                      "Explicit entry: enabled=\(control.isEnabled) active=\(NSApp.isActive) key=\(hosted.window.isKeyWindow), responder=\(String(describing: type(of: hosted.window.firstResponder)))")
        let editor = try XCTUnwrap(control.currentEditor())
        editor.selectAll(nil)
        editor.insertText(text)
        try await Task.sleep(for: .milliseconds(100))
    }

    @MainActor private func key(_ window: NSWindow, code: UInt16, characters: String) async throws {
        for type in [NSEvent.EventType.keyDown, .keyUp] {
            let event = try XCTUnwrap(NSEvent.keyEvent(
                with: type, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber, context: nil, characters: characters,
                charactersIgnoringModifiers: characters, isARepeat: false, keyCode: code))
            window.sendEvent(event)
        }
        try await Task.sleep(for: .milliseconds(300))
    }

    @MainActor private func press(_ hosted: HostedWindow, label: String) async throws {
        let tree = try await hosted.tree(containing: label)
        XCTAssertEqual(tree.node(label: label)?.enabled, true,
                       "\(label): active=\(NSApp.isActive) key=\(hosted.window.isKeyWindow)")
        let pressed = try await hosted.press(label: label)
        XCTAssertTrue(pressed, "\(label) must be available")
    }

    @MainActor private func assertSeedContent(_ hosted: HostedWindow) async throws {
        let tree = try await hosted.tree(containing: "Seed Login")
        XCTAssertTrue(tree.contains("Seed Login"))
    }

    @MainActor private func dismissError(_ hosted: HostedWindow, model: VaultModel) async throws {
        let alert = try await hosted.sheetTree(containing: "OK")
        XCTAssertTrue(alert.contains("OK"), "The real authentication error alert must appear")
        let dismissed = try await hosted.press(label: "OK", sheet: true)
        XCTAssertTrue(dismissed)
        try await wait { model.errorMessage == nil && hosted.window.attachedSheet == nil }
        try await activate(hosted)
    }
}
