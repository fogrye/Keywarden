import AppKit
import XCTest

/// The menu bar, lock screen and Security settings show these shields; a missing asset would leave them blank.
final class MenuBarIconTests: XCTestCase {
    func testBothStatesShipAsTemplateImages() throws {
        for name in ["MenuBarLocked", "MenuBarUnlocked"] {
            let image = try XCTUnwrap(NSImage(named: name), "\(name) missing from the asset catalog")
            XCTAssertTrue(image.isTemplate, "\(name) must be a template image so macOS tints it")
            XCTAssertEqual(image.size, NSSize(width: 18, height: 18), "\(name) should be 18 pt")
            XCTAssertTrue(image.representations.contains { $0 is NSPDFImageRep }, "\(name) should stay vector to scale up on the lock screen")
            XCTAssertGreaterThan(drawnPixels(image), 200, "\(name) draws blank (a PDF with a soft mask does)")
        }
    }

    /// Settings toolbar tabs draw only symbol images; the Security tab uses this custom symbol.
    func testShieldSymbolLoads() {
        XCTAssertNotNil(NSImage(named: "ShieldKey"), "ShieldKey symbol missing from the asset catalog")
    }

    /// Draws `image` at 2x menu bar size the way AppKit does and counts the pixels it covers.
    private func drawnPixels(_ image: NSImage) -> Int {
        let side = 36
        guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side,
                                            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0) else { return 0 }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        image.draw(in: NSRect(x: 0, y: 0, width: side, height: side))
        NSGraphicsContext.restoreGraphicsState()
        var covered = 0
        for x in 0..<side {
            for y in 0..<side where (bitmap.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.5 { covered += 1 }
        }
        return covered
    }
}
