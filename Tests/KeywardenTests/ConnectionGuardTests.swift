import Foundation
import os
import XCTest
@testable import Keywarden

/// Taking back a browser connection another app replaced.
final class ConnectionGuardTests: XCTestCase {
    func testOnlyKeptInstalledBrowsersRegisteredElsewhereAreReclaimed() {
        let ours = Installer.Registration.this(app: URL(fileURLWithPath: "/Applications/Keywarden.app"))
        let bitwarden = Installer.Registration.other(path: "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy")
        XCTAssertTrue(Installer.needsReclaim(bitwarden, kept: true, installed: true))
        XCTAssertTrue(Installer.needsReclaim(.none, kept: true, installed: true), "A removed host is restored too")
        XCTAssertFalse(Installer.needsReclaim(ours, kept: true, installed: true))
        XCTAssertFalse(Installer.needsReclaim(bitwarden, kept: false, installed: true), "Disconnected or never connected")
        XCTAssertFalse(Installer.needsReclaim(bitwarden, kept: true, installed: false))
    }

    func testEarlierConnectionsAreKeptEvenIfAlreadyTakenOver() throws {
        let firefox = try XCTUnwrap(BrowserRegistry.browser("firefox"))
        let zen = try XCTUnwrap(BrowserRegistry.browser("zen"))
        let chrome = try XCTUnwrap(BrowserRegistry.browser("chrome"))
        let bitwarden = Installer.Registration.other(path: "/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy")
        func status(_ browser: KnownBrowser, _ registration: Installer.Registration, backup: Bool) -> Installer.BrowserStatus {
            Installer.BrowserStatus(browser: browser, app: nil, registration: registration, hasBackup: backup, verifiable: true)
        }
        let statuses = [status(firefox, bitwarden, backup: true), status(zen, bitwarden, backup: false),
                        status(chrome, bitwarden, backup: false)]
        XCTAssertEqual(Installer.seedKept(statuses, pinned: ["chrome"]), ["firefox", "chrome"])
        XCTAssertEqual(Installer.seedKept([status(zen, .this(app: URL(fileURLWithPath: "/Applications/Keywarden.app")), backup: false)],
                                          pinned: []), ["zen"])
    }

    func testChangeToTheBitwardenHostTriggersACheck() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let checks = OSAllocatedUnfairLock(initialState: 0)
        let checked = expectation(description: "checked after the manifest changed")
        checked.assertForOverFulfill = false
        let guarding = ConnectionGuard(folders: [folder], latency: 0.1, reclaim: { _ in
            if checks.withLock({ $0 += 1; return $0 }) > 2 { checked.fulfill() }
            return []
        })
        guarding.start()
        defer { guarding.stop() }
        guarding.checkNow()
        XCTAssertEqual(checks.withLock { $0 }, 2, "One check at start, one asked for")
        try Data("{}".utf8).write(to: folder.appendingPathComponent("com.1password.json"), options: .atomic)
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertEqual(checks.withLock { $0 }, 2, "Other apps' hosts are ignored")
        try Data("{}".utf8).write(to: folder.appendingPathComponent("com.8bit.bitwarden.json"), options: .atomic)
        wait(for: [checked], timeout: 10)
    }

    func testStopsReclaimingABrowserAnotherAppKeepsRewriting() {
        let clock = OSAllocatedUnfairLock(initialState: Date(timeIntervalSince1970: 0))
        let skipped = OSAllocatedUnfairLock(initialState: [Set<String>]())
        let guarding = ConnectionGuard(folders: [], limit: 3, window: 600, now: { clock.withLock { $0 } },
                                        reclaim: { skipping in
            skipped.withLock { $0.append(skipping) }
            return ["firefox", "chrome"].filter { !skipping.contains($0) }
        })
        let reclaimed = OSAllocatedUnfairLock(initialState: [[String]]())
        guarding.onReclaim = { ids in reclaimed.withLock { $0.append(ids) } }
        for _ in 0..<4 {
            guarding.checkNow()
            clock.withLock { $0 += 60 }
        }
        XCTAssertEqual(reclaimed.withLock { $0 }.count, 3)
        XCTAssertEqual(skipped.withLock { $0 }.last, ["firefox", "chrome"])
        // Once the window has passed, reclaiming resumes.
        clock.withLock { $0 += 600 }
        guarding.checkNow()
        XCTAssertEqual(reclaimed.withLock { $0 }.last, ["firefox", "chrome"])
    }
}
