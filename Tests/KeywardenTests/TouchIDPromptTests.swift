import AppKit
import LocalAuthentication
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

    /// The lock screen's password field holds Secure Input, which hides key releases from a
    /// launcher's or remapper's event tap. It stays disabled and unfocused while a hotkey's keys are
    /// held, so they can't be left pressed, and takes focus once they're let go.
    @MainActor func testLockScreenWaitsForHeldKeysBeforeFocusingThePassword() async throws {
        var held = true
        let original = LoginView.keysHeld
        LoginView.keysHeld = { held }
        defer { LoginView.keysHeld = original }
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        model.phase = .locked
        let hosted = HostedWindow(LoginView(model: model), size: NSSize(width: 420, height: 520))
        defer { hosted.close() }

        // The PIN field when a PIN is set up, else the master password field.
        func secureField(_ tree: AXTree) -> AXTree.Node? { tree.nodes.first { ["PIN", "Master password"].contains($0.label) } }
        var tree = try await hosted.tree(containing: "Vault Locked")
        var field = try XCTUnwrap(secureField(tree), "\(tree.texts)")
        XCTAssertFalse(field.enabled, "The field must wait while a modifier is held")
        XCTAssertFalse(hosted.window.firstResponder is NSTextView, "Nothing may take Secure Input yet")

        try await Task.sleep(for: .milliseconds(2300))
        tree = try await hosted.tree()
        field = try XCTUnwrap(secureField(tree))
        XCTAssertFalse(field.enabled, "Holding a hotkey longer than two seconds must not enable Secure Input")
        XCTAssertFalse(hosted.window.firstResponder is NSTextView)

        held = false
        tree = try await hosted.tree()
        field = try XCTUnwrap(secureField(tree))
        XCTAssertTrue(field.enabled)
        let editor = try XCTUnwrap(hosted.window.firstResponder as? NSTextView)
        XCTAssertTrue(editor.delegate is NSSecureTextField, "The field takes focus once the keys are up")

        held = true
        NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
        NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: NSApp)
        tree = try await hosted.tree()
        XCTAssertFalse(try XCTUnwrap(secureField(tree)).enabled)

        // A pending wait must not restore focus after the app goes back into the background.
        NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
        held = false
        tree = try await hosted.tree()
        XCTAssertFalse(try XCTUnwrap(secureField(tree)).enabled)
        XCTAssertFalse(hosted.window.firstResponder is NSTextView)

        NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: NSApp)
        tree = try await hosted.tree()
        XCTAssertTrue(try XCTUnwrap(secureField(tree)).enabled)
        XCTAssertTrue((hosted.window.firstResponder as? NSTextView)?.delegate is NSSecureTextField)
    }

    @MainActor func testLetterHotkeysWaitForHardwareAndRemappedKeyRelease() async throws {
        let original = LoginView.keyIsDown
        var held = true
        var source = CGEventSourceStateID.hidSystemState
        // L, with no modifier flags: a launcher can release Control before its letter.
        LoginView.keyIsDown = { held && $0 == source && $1 == 37 }
        defer { LoginView.keyIsDown = original }
        let model = VaultModel()
        let deadline = Date().addingTimeInterval(15)
        while !model.isReady, Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        model.phase = .locked
        let hosted = HostedWindow(LoginView(model: model), size: NSSize(width: 420, height: 520))
        defer { hosted.close() }

        for state in [CGEventSourceStateID.hidSystemState, .combinedSessionState] {
            source = state
            held = true
            NotificationCenter.default.post(name: NSApplication.didResignActiveNotification, object: NSApp)
            NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: NSApp)
            var tree = try await hosted.tree(containing: "Vault Locked")
            func field(_ tree: AXTree) throws -> AXTree.Node {
                try XCTUnwrap(tree.nodes.first { ["PIN", "Master password"].contains($0.label) })
            }
            XCTAssertFalse(try field(tree).enabled, "A letter alone must keep Secure Input off")
            XCTAssertFalse(hosted.window.firstResponder is NSTextView)
            held = false
            tree = try await hosted.tree()
            XCTAssertTrue(try field(tree).enabled)
            XCTAssertTrue((hosted.window.firstResponder as? NSTextView)?.delegate is NSSecureTextField)
        }
    }
}
