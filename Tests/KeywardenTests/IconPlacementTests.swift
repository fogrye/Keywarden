import Foundation
import XCTest
@testable import Keywarden

@MainActor
final class IconPlacementTests: XCTestCase {
    func testDefaultsToMenuBarAndPersists() throws {
        let suite = "icon-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults)
        XCTAssertEqual(settings.iconPlacement, .menuBar)
        settings.iconPlacement = .both
        XCTAssertEqual(AppSettings(defaults: defaults).iconPlacement, .both)
    }

    func testEarlierBackgroundSettingMigrates() throws {
        let suite = "icon-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(false, forKey: "keepRunningInBackground")
        XCTAssertEqual(AppSettings(defaults: defaults).iconPlacement, .dock)
        defaults.set(true, forKey: "keepRunningInBackground")
        XCTAssertEqual(AppSettings(defaults: defaults).iconPlacement, .menuBar)
    }

    func testRemovingMenuBarIconFallsBackToDock() throws {
        let suite = "icon-test-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = AppSettings(defaults: defaults)
        var changes = 0
        settings.onAppearanceChange = { changes += 1 }
        settings.showsMenuBarIcon = false
        XCTAssertEqual(settings.iconPlacement, .dock)
        settings.showsMenuBarIcon = true
        XCTAssertEqual(settings.iconPlacement, .both)
        settings.showsMenuBarIcon = false
        XCTAssertEqual(settings.iconPlacement, .dock)
        XCTAssertEqual(changes, 3)
        XCTAssertFalse(AppIconPlacement.menuBar.showsDockIcon)
        XCTAssertFalse(AppIconPlacement.dock.showsMenuBarIcon)
    }
}
