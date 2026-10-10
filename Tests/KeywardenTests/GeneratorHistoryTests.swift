import Foundation
import XCTest
@testable import Keywarden

@MainActor
final class GeneratorHistoryTests: XCTestCase {
    override func setUp() async throws { GeneratorHistory.shared.sessionChanged(unlocked: false, loggedOut: true) }
    override func tearDown() async throws { GeneratorHistory.shared.sessionChanged(unlocked: false, loggedOut: true) }

    func testValuesGeneratedWhileLockedAreKeptAndShownAfterUnlock() {
        let history = GeneratorHistory()
        history.record("locked-value", kind: .password)
        XCTAssertEqual(history.entries.map(\.value), ["locked-value"])
        XCTAssertFalse(history.isVisible)
        history.sessionChanged(unlocked: true)
        XCTAssertTrue(history.isVisible)
        history.record("unlocked-value", kind: .password)
        XCTAssertEqual(history.entries.map(\.value), ["unlocked-value", "locked-value"])
    }

    func testNewestFirstWithKindAndTimestamp() {
        let history = GeneratorHistory()
        history.sessionChanged(unlocked: true)
        let first = Date(timeIntervalSince1970: 1_000), second = Date(timeIntervalSince1970: 2_000)
        history.record("one", kind: .password, date: first)
        history.record("two", kind: .username, date: second)
        XCTAssertEqual(history.entries.map(\.value), ["two", "one"])
        XCTAssertEqual(history.entries.map(\.kind), [.username, .password])
        XCTAssertEqual(history.entries.map(\.date), [second, first])
    }

    func testRepeatingTheNewestValueAndEmptyValuesAreIgnored() {
        let history = GeneratorHistory()
        history.sessionChanged(unlocked: true)
        history.record("same", kind: .passphrase)
        history.record("same", kind: .passphrase)
        history.record("", kind: .passphrase)
        XCTAssertEqual(history.entries.count, 1)
        history.record("other", kind: .passphrase)
        history.record("same", kind: .passphrase)
        XCTAssertEqual(history.entries.count, 3)
    }

    func testHistoryKeepsTheNewestHundred() {
        let history = GeneratorHistory()
        history.sessionChanged(unlocked: true)
        for index in 0..<(GeneratorHistory.capacity + 25) { history.record("value-\(index)", kind: .password) }
        XCTAssertEqual(GeneratorHistory.capacity, 100)
        XCTAssertEqual(history.entries.count, 100)
        XCTAssertEqual(history.entries.first?.value, "value-124")
        XCTAssertEqual(history.entries.last?.value, "value-25")
    }

    func testClearAllEmptiesTheList() {
        let history = GeneratorHistory()
        history.sessionChanged(unlocked: true)
        history.record("x", kind: .password)
        history.clear()
        XCTAssertTrue(history.entries.isEmpty)
        XCTAssertTrue(history.isVisible)
    }

    func testLockingHidesTheSharedHistoryAndLoggingOutWipesIt() {
        let model = VaultModel()
        model.phase = .unlocked
        XCTAssertTrue(GeneratorHistory.shared.isVisible)
        GeneratorHistory.shared.record("before-lock", kind: .password)
        model.phase = .locked
        XCTAssertFalse(GeneratorHistory.shared.isVisible)
        GeneratorHistory.shared.record("while-locked", kind: .password)
        XCTAssertEqual(GeneratorHistory.shared.entries.map(\.value), ["while-locked", "before-lock"])
        model.phase = .unlocked
        XCTAssertTrue(GeneratorHistory.shared.isVisible)
        model.phase = .loggedOut
        XCTAssertTrue(GeneratorHistory.shared.entries.isEmpty)
        XCTAssertFalse(GeneratorHistory.shared.isVisible)
    }

    func testHistoryIsNeverPersisted() {
        let secret = "history-\(UUID().uuidString)"
        GeneratorHistory.shared.sessionChanged(unlocked: true)
        GeneratorHistory.shared.record(secret, kind: .password)
        XCTAssertFalse(String(describing: UserDefaults.standard.dictionaryRepresentation()).contains(secret))
        // It is a plain in-memory array: the type has no file or Keychain API at all.
        XCTAssertEqual(GeneratorHistory.shared.entries.first?.value, secret)
    }
}
