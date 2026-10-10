import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// Renders the generator window for every type offscreen, so view-layer traps (such as the
/// LabeledContent accessibility recursion) surface without a server. Set `BW_RENDER_DIR` to keep the PNGs.
@MainActor
final class GeneratorRenderingTests: XCTestCase {
    private let keys = ["generatorOptions", "usernameGeneratorOptions"]
    private var saved: [String: Data] = [:]

    override func setUp() async throws {
        for key in keys { saved[key] = UserDefaults.standard.data(forKey: key) }
    }

    override func tearDown() async throws {
        for key in keys {
            if let data = saved[key] { UserDefaults.standard.set(data, forKey: key) }
            else { UserDefaults.standard.removeObject(forKey: key) }
        }
        GeneratorHistory.shared.sessionChanged(unlocked: false)
    }

    func testEveryGeneratorTypeRenders() throws {
        var options = GeneratorOptions()
        var username = UsernameOptions()
        username.email = "you@example.com"
        username.catchAllDomain = "example.org"
        var screens: [(String, GeneratorOptions, UsernameOptions)] = []
        screens.append(("password", options, username))
        options.mode = .passphrase
        screens.append(("passphrase", options, username))
        options.usernameSelected = true
        for kind in UsernameOptions.Kind.allCases {
            username.kind = kind
            if kind == .forwarded {
                for service in ForwarderService.allCases {
                    username.service = service
                    screens.append(("username-forwarded-\(service.backendName)", options, username))
                }
            } else {
                screens.append(("username-\(kind)", options, username))
            }
        }
        for (name, options, username) in screens {
            options.store()
            username.store()
            render(GeneratorView(), name)
        }
    }

    func testHistoryListRendersWithEntries() throws {
        GeneratorHistory.shared.sessionChanged(unlocked: true)
        for index in 0..<5 { GeneratorHistory.shared.record("Sample-\(index)-value", kind: .password) }
        render(GeneratorView(), "generator-with-history")
    }

    private func render(_ view: some View, _ name: String) {
        let host = NSHostingView(rootView: view)
        host.frame = NSRect(origin: .zero, size: host.fittingSize)
        host.appearance = NSAppearance(named: .darkAqua)
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))
        host.layoutSubtreeIfNeeded()
        let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds)
        XCTAssertNotNil(bitmap, name)
        guard let bitmap else { return }
        host.cacheDisplay(in: host.bounds, to: bitmap)
        if let directory = ProcessInfo.processInfo.environment["BW_RENDER_DIR"],
           let png = bitmap.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: directory).appendingPathComponent("generator-\(name).png"))
        }
    }
}
