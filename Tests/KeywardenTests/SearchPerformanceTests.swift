import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// Times search changes in the real window with a large synthetic vault.
@MainActor
final class SearchPerformanceTests: XCTestCase {
    func testWideningSearchStaysResponsive() throws {
        let kinds = ["Mail", "Bank", "Shop", "Work"]
        let items: [[String: Any]] = (0..<5_000).map { index in
            var item: [String: Any] = ["id": UUID().uuidString, "type": 1 + index % 4]
            item["name"] = "\(kinds[index % 4]) account \(index)"
            item["favorite"] = index % 50 == 0
            item["folderId"] = NSNull()
            item["organizationId"] = NSNull()
            item["subtitle"] = "user\(index)@example.com"
            item["searchValues"] = ["https://site\(index).example.com"]
            item["hasTotp"] = false
            item["hasPasskey"] = false
            item["deleted"] = false
            item["archived"] = index % 100 == 0
            item["revisionDate"] = "2026-01-01T00:00:00Z"
            item["iconHost"] = "site\(index % 30).example.com"
            return item
        }
        let json = try JSONSerialization.data(withJSONObject: [
            "email": "perf@example.test", "server": "http://127.0.0.1:18088/api",
            "accountId": UUID().uuidString, "accountHash": String(repeating: "a", count: 64), "generation": 1,
            "lastSync": NSNull(), "items": items, "folders": [], "failures": [],
        ])
        let snapshot = try JSONDecoder().decode(VaultSnapshot.self, from: json)
        let model = VaultModel()
        model.loadForTesting(snapshot)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1080, height: 660),
                              styleMask: [.titled, .resizable, .closable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: RootView(model: model))
        window.orderFront(nil)
        defer { window.close() }
        settle()
        // Let the first screen of icons arrive, as in a real session.
        RunLoop.main.run(until: Date().addingTimeInterval(2))

        var stalls: [(String, Double)] = []
        // "sh" matches a few items; one character (no filter) brings back the whole vault.
        for (label, text) in [("narrow to 2 chars", "sho"), ("few matches", "Shop account 12"),
                              ("widen to 1 char", "S"), ("narrow again", "Shop account 12"), ("clear", "")] {
            model.search = text
            stalls.append((label, longestStall(over: 1.0)))
            withAnimation { model.search = "" }
            _ = longestStall(over: 0.3)
            withAnimation { model.search = text }
            stalls.append((label + " (animated)", longestStall(over: 1.0)))
        }
        let report = stalls.map { "\($0.0): longest main-thread stall \(Int($0.1 * 1000)) ms" }
        try? report.joined(separator: "\n").write(toFile: "/tmp/bw-search-perf.txt", atomically: true, encoding: .utf8)
        for (label, seconds) in stalls {
            XCTAssertLessThan(seconds, 0.15, "\(label) froze the UI for \(Int(seconds * 1000)) ms")
        }
    }

    /// Pings the main run loop every 10 ms and returns the longest gap: the user-visible freeze.
    private func longestStall(over duration: TimeInterval) -> TimeInterval {
        nonisolated(unsafe) var last = Date()
        nonisolated(unsafe) var longest: TimeInterval = 0
        let end = Date().addingTimeInterval(duration)
        let timer = Timer(timeInterval: 0.01, repeats: true) { _ in
            let now = Date()
            longest = max(longest, now.timeIntervalSince(last))
            last = now
        }
        RunLoop.main.add(timer, forMode: .common)
        while Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
        timer.invalidate()
        return max(longest, Date().timeIntervalSince(last))
    }

    /// Runs the run loop until layout and display for the change are done.
    private func settle() {
        for _ in 0..<3 { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
        NSApp.windows.forEach { $0.displayIfNeeded() }
    }
}
