import Foundation
import XCTest
@testable import Keywarden

@MainActor
final class AutoLockTests: XCTestCase {
    func testSettingsShorteningExpiresFromLastActivity() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults, secure: .memory())
        var clock: TimeInterval = 100
        var locks = 0
        let controller = AutoLockController(settings: settings, now: { clock }) { locks += 1 }
        controller.setUnlocked(true)
        clock = 121
        settings.vaultTimeout = .minutes(1)
        XCTAssertEqual(locks, 0)
        settings.vaultTimeout = .onRestart
        clock = 200
        controller.settingsChanged()
        XCTAssertEqual(locks, 0)
        settings.vaultTimeout = .minutes(1)
        XCTAssertEqual(locks, 1)
    }

    func testRealActivityExtendsDeadlineWithoutResettingOnSettingsChange() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults, secure: .memory())
        var clock: TimeInterval = 0
        var locks = 0
        let controller = AutoLockController(settings: settings, now: { clock }) { locks += 1 }
        controller.setUnlocked(true)
        clock = 270
        controller.recordActivity()
        settings.vaultTimeout = .minutes(1)
        XCTAssertEqual(locks, 0)
        clock = 331
        controller.settingsChanged()
        XCTAssertEqual(locks, 1)
    }

    func testTimeoutChoicesDecideWhichSystemEventsLock() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SecuritySettingsStore.memory()
        let settings = AppSettings(defaults: defaults, secure: store)
        settings.vaultTimeout = .onRestart
        XCTAssertFalse(settings.locksOn(sleep: true))
        XCTAssertFalse(settings.locksOn(sleep: false))
        settings.vaultTimeout = .onSleep
        XCTAssertTrue(settings.locksOn(sleep: true))
        XCTAssertFalse(settings.locksOn(sleep: false))
        settings.vaultTimeout = .onSystemLock
        XCTAssertTrue(settings.locksOn(sleep: false))
        settings.vaultTimeout = .minutes(5)
        settings.lockOnSystemLock = false
        XCTAssertFalse(settings.locksOn(sleep: true))
        // A reload keeps the choice.
        XCTAssertEqual(AppSettings(defaults: defaults, secure: store).vaultTimeout, .minutes(5))
    }

    func testAutomaticTouchIDIsOnByDefaultAndPersists() throws {
        let suite = "autotouch-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults, secure: .memory())
        XCTAssertTrue(settings.autoTouchID)
        settings.autoTouchID = false
        XCTAssertFalse(AppSettings(defaults: defaults, secure: .memory()).autoTouchID)
    }

    func testEarlierMinutesSettingMigrates() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(0, forKey: "vaultTimeoutMinutes")
        XCTAssertEqual(AppSettings(defaults: defaults, secure: .memory()).vaultTimeout, .onRestart)
        defaults.set(30, forKey: "vaultTimeoutMinutes")
        XCTAssertEqual(AppSettings(defaults: defaults, secure: .memory()).vaultTimeout, .minutes(30))
    }

    /// Security settings live in the Keychain. Once the record exists, whatever another process
    /// writes to UserDefaults is ignored.
    func testSettingsPlantedInUserDefaultsAreIgnored() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("5", forKey: "vaultTimeout")
        defaults.set(false, forKey: "lockOnSystemLock")
        let store = SecuritySettingsStore.memory()
        let migrated = AppSettings(defaults: defaults, secure: store)
        XCTAssertEqual(migrated.vaultTimeout, .minutes(5))
        XCTAssertFalse(migrated.lockOnSystemLock)
        XCTAssertNotNil(try store.load(), "Migration writes the Keychain record at once")
        XCTAssertNil(defaults.object(forKey: "vaultTimeout"), "Migrated keys leave UserDefaults")

        defaults.set("onRestart", forKey: "vaultTimeout")
        defaults.set("logOut", forKey: "timeoutAction")
        defaults.set(0, forKey: "clearClipboardSeconds")
        let reloaded = AppSettings(defaults: defaults, secure: store)
        XCTAssertEqual(reloaded.vaultTimeout, .minutes(5))
        XCTAssertEqual(reloaded.timeoutAction, .lock)
        XCTAssertEqual(reloaded.clearClipboardSeconds, 60)
        XCTAssertFalse(reloaded.lockOnSystemLock)
    }

    /// A fresh install writes the defaults straight away, so a later planted value has nothing to
    /// migrate into.
    func testFreshInstallCreatesTheRecord() throws {
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SecuritySettingsStore.memory()
        XCTAssertEqual(AppSettings(defaults: defaults, secure: store).vaultTimeout, .minutes(15))
        XCTAssertNotNil(try store.load())
        defaults.set("onRestart", forKey: "vaultTimeout")
        XCTAssertEqual(AppSettings(defaults: defaults, secure: store).vaultTimeout, .minutes(15))
    }

    /// When the Keychain can't be read, the safe defaults apply and nothing is written over the
    /// stored settings, even when a setting changes.
    func testUnreadableKeychainUsesDefaultsAndWritesNothing() throws {
        struct Unreadable: Error {}
        let suite = "autolock-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("onRestart", forKey: "vaultTimeout")
        var writes = 0
        let store = SecuritySettingsStore(load: { throw Unreadable() }, save: { _ in writes += 1 })
        let settings = AppSettings(defaults: defaults, secure: store)
        XCTAssertEqual(settings.vaultTimeout, .minutes(15))
        XCTAssertTrue(settings.lockOnSystemLock)
        settings.vaultTimeout = .minutes(5)
        XCTAssertEqual(writes, 0)
        XCTAssertEqual(defaults.string(forKey: "vaultTimeout"), "onRestart", "Legacy keys stay until a migration succeeds")
    }
}
