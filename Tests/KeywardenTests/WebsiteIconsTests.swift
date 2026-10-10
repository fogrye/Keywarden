import AppKit
import XCTest
@testable import Keywarden

/// Website icons are fetched once per unlock, held in memory only and forgotten on lock.
@MainActor
final class WebsiteIconsTests: XCTestCase {
    private let icon = URL(string: "https://icons.example.test/site.example/icon.png")!
    private let absent = URL(string: "https://icons.example.test/none.example/icon.png")!

    override func setUp() {
        StubIconProtocol.reset()
    }

    private func makeIcons() -> WebsiteIcons {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubIconProtocol.self]
        configuration.urlCache = nil
        return WebsiteIcons(session: URLSession(configuration: configuration))
    }

    func testRowsAskingAtOnceShareOneFetch() async {
        let icons = makeIcons()
        let url = icon
        let rows = (0..<3).map { _ in Task { await icons.image(for: url) } }
        var results: [NSImage?] = []
        for row in rows { results.append(await row.value) }
        XCTAssertTrue(results.allSatisfy { $0 != nil })
        XCTAssertEqual(StubIconProtocol.requests(for: icon), 1)
        XCTAssertNotNil(icons.cached(icon))
        _ = await icons.image(for: icon)
        XCTAssertEqual(StubIconProtocol.requests(for: icon), 1)
    }

    func testLargeIconsAreKeptSmall() throws {
        let large = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 512, pixelsHigh: 256, bitsPerSample: 8,
                                     samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                     colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        let data = try XCTUnwrap(large.representation(using: .png, properties: [:]))
        let image = try XCTUnwrap(WebsiteIcons.downscaled(data))
        let pixels = try XCTUnwrap(image.cgImage(forProposedRect: nil, context: nil, hints: nil))
        XCTAssertEqual(pixels.width, WebsiteIcons.maxPixels)
        XCTAssertEqual(pixels.height, WebsiteIcons.maxPixels / 2)
    }

    func testMissingIconIsNotAskedForAgain() async {
        let icons = makeIcons()
        let first = await icons.image(for: absent)
        let second = await icons.image(for: absent)
        XCTAssertNil(first)
        XCTAssertNil(second)
        XCTAssertEqual(StubIconProtocol.requests(for: absent), 1)
    }

    func testClearForgetsIconsAndMisses() async {
        let icons = makeIcons()
        _ = await icons.image(for: icon)
        _ = await icons.image(for: absent)
        icons.clear()
        XCTAssertNil(icons.cached(icon))
        _ = await icons.image(for: icon)
        _ = await icons.image(for: absent)
        XCTAssertEqual(StubIconProtocol.requests(for: icon), 2)
        XCTAssertEqual(StubIconProtocol.requests(for: absent), 2)
    }

    func testLockDropsWebsiteIcons() async throws {
        let image = try XCTUnwrap(NSImage(data: StubIconProtocol.png))
        WebsiteIcons.shared.storeForTesting(image, for: icon)
        let model = VaultModel()
        model.loadForTesting(try JSONDecoder().decode(VaultSnapshot.self, from: Data("""
            {"email":"icons@example.test","server":"http://127.0.0.1:18088/api","accountId":"a",
             "accountHash":"\(String(repeating: "a", count: 64))","generation":1,"lastSync":null,
             "items":[],"folders":[],"failures":[]}
            """.utf8)))
        await model.lock()
        XCTAssertNil(WebsiteIcons.shared.cached(icon), "locking must forget the vault's website icons")
    }

    func testTurningIconsOffDropsThem() throws {
        let image = try XCTUnwrap(NSImage(data: StubIconProtocol.png))
        WebsiteIcons.shared.storeForTesting(image, for: icon)
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "WebsiteIconsTests-\(UUID())"))
        let settings = AppSettings(defaults: defaults, secure: .memory())
        settings.showWebsiteIcons = false
        XCTAssertNil(WebsiteIcons.shared.cached(icon))
    }
}

/// Serves a PNG for `site.example` and a 404 for anything else, counting requests per URL.
final class StubIconProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) private static var counts: [URL: Int] = [:]
    private static let lock = NSLock()

    static let png: Data = {
        let image = NSImage(size: NSSize(width: 4, height: 4), flipped: false) { rect in
            NSColor.systemBlue.setFill()
            rect.fill()
            return true
        }
        let rep = NSBitmapImageRep(data: image.tiffRepresentation!)!
        return rep.representation(using: .png, properties: [:])!
    }()

    static func reset() { lock.withLock { counts = [:] } }
    static func requests(for url: URL) -> Int { lock.withLock { counts[url] ?? 0 } }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        Self.lock.withLock { Self.counts[url, default: 0] += 1 }
        let found = url.path.contains("site.example")
        let response = HTTPURLResponse(url: url, statusCode: found ? 200 : 404, httpVersion: nil,
                                       headerFields: ["Content-Type": "image/png"])!
        // Answer later, so concurrent callers overlap with the request in flight.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { [self] in
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if found { client?.urlProtocol(self, didLoad: Self.png) }
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {}
}
