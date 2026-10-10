import AppKit
import ImageIO

/// Website icons for the vault lists, fetched once per unlock and kept in memory only.
/// Icon URLs name the vault's websites, so nothing goes to disk and everything is dropped on lock.
@MainActor
final class WebsiteIcons {
    static let shared = WebsiteIcons()

    private let session: URLSession
    private let images = NSCache<NSURL, NSImage>()
    /// URLs the server answered without a usable image. Network errors are retried on next use.
    private var missing: Set<URL> = []
    private var loading: [URL: Task<NSImage?, Never>] = [:]
    private var generation = 0

    init(session: URLSession? = nil) {
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil
            configuration.timeoutIntervalForRequest = 15
            self.session = URLSession(configuration: configuration)
        }
        images.countLimit = 1_000
    }

    func cached(_ url: URL) -> NSImage? {
        images.object(forKey: url as NSURL)
    }

    /// The icon at `url`, fetched at most once however many rows ask for it at the same time.
    func image(for url: URL) async -> NSImage? {
        if let image = cached(url) { return image }
        if missing.contains(url) { return nil }
        let task: Task<NSImage?, Never>
        if let running = loading[url] {
            task = running
        } else {
            let session = session
            let started = generation
            task = Task {
                let result = await Self.fetch(url, session: session)
                // A lock while this was in flight has already dropped everything; keep nothing.
                guard started == self.generation else { return nil }
                self.loading[url] = nil
                switch result {
                case .image(let image): self.images.setObject(image, forKey: url as NSURL)
                case .missing: self.missing.insert(url)
                case .failed: break
                }
                return result.image
            }
            loading[url] = task
        }
        return await task.value
    }

    /// Forgets every icon and which websites were asked for.
    func clear() {
        generation += 1
        loading.values.forEach { $0.cancel() }
        loading = [:]
        missing = []
        images.removeAllObjects()
    }

    #if DEBUG
    func storeForTesting(_ image: NSImage, for url: URL) {
        images.setObject(image, forKey: url as NSURL)
    }
    #endif

    private enum FetchResult {
        case image(NSImage), missing, failed
        var image: NSImage? { if case .image(let image) = self { image } else { nil } }
    }

    private nonisolated static func fetch(_ url: URL, session: URLSession) async -> FetchResult {
        guard let (data, response) = try? await session.data(from: url),
              let status = (response as? HTTPURLResponse)?.statusCode else { return .failed }
        guard status == 200, let image = downscaled(data) else {
            return (400..<500).contains(status) || status == 200 ? .missing : .failed
        }
        return .image(image)
    }

    /// The largest icon drawn is 44 pt, so keep at most 88 px (Retina) instead of the served size.
    nonisolated static let maxPixels = 88

    nonisolated static func downscaled(_ data: Data) -> NSImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                  kCGImageSourceCreateThumbnailFromImageAlways: true,
                  kCGImageSourceCreateThumbnailWithTransform: true,
                  kCGImageSourceShouldCacheImmediately: true,
                  kCGImageSourceThumbnailMaxPixelSize: maxPixels,
              ] as CFDictionary) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: image.width / 2, height: image.height / 2))
    }
}
