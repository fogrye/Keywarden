import AppKit
import Foundation
import UniformTypeIdentifiers

// Export and import of the vault as Bitwarden files. The file contents never reach Swift: the Rust
// core reads and writes the files by path and replies with counts only.

/// What the user asked for in the Export Vault sheet.
struct ExportOptions: Equatable {
    enum Format: String, CaseIterable, Identifiable {
        case json, csv, encryptedJSON
        var id: String { rawValue }
        var title: String {
            switch self {
            case .json: ".json"
            case .csv: ".csv"
            case .encryptedJSON: String(localized: ".json (Encrypted)")
            }
        }
    }

    enum Protection: String, CaseIterable, Identifiable {
        case account, password
        var id: String { rawValue }
        var title: String { self == .account ? String(localized: "Account restricted") : String(localized: "Password protected") }
    }

    var format: Format = .json
    var protection: Protection = .account
    var filePassword = ""
    var confirmation = ""

    var isEncrypted: Bool { format == .encryptedJSON }
    var needsFilePassword: Bool { isEncrypted && protection == .password }
    var fileExtension: String { format == .csv ? "csv" : "json" }

    /// The `format` the Rust core expects.
    var requestFormat: String {
        switch format {
        case .json: "json"
        case .csv: "csv"
        case .encryptedJSON: protection == .account ? "jsonEncryptedAccount" : "jsonEncryptedPassword"
        }
    }

    /// Why the export can't start yet, or nil when it can.
    func problem(masterPassword: String) -> String? {
        if needsFilePassword {
            if filePassword.isEmpty { return String(localized: "Enter a file password.") }
            if filePassword != confirmation { return String(localized: "The file passwords don’t match.") }
        }
        if masterPassword.isEmpty { return String(localized: "Enter your master password.") }
        return nil
    }
}

enum ExportFileName {
    /// `bitwarden_export_<yyyyMMddHHmmss>.<ext>`, in local time, as Bitwarden Desktop names exports.
    static func suggested(extension ext: String, now: Date = Date(), timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: now)
        let stamp = String(format: "%04d%02d%02d%02d%02d%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0,
                           c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
        return "bitwarden_export_\(stamp).\(ext)"
    }
}

/// The counts an export reports. `omitted` is what the format can't hold (or couldn't be decrypted).
struct ExportSummary: Decodable, Equatable, Sendable {
    let items: Int
    let folders: Int
    let omitted: Int

    var text: String { TransferCounts.text(items: items, folders: folders) }
}

enum TransferCounts {
    /// "12 items and 2 folders".
    static func text(items: Int, folders: Int) -> String {
        let itemText = String(localized: "\(items) items")
        guard folders > 0 else { return itemText }
        let folderText = String(localized: "\(folders) folders")
        return String(localized: "\(itemText) and \(folderText)")
    }
}

/// What the core read from an import file, before anything is uploaded.
struct ImportPreview: Decodable, Equatable, Sendable {
    struct TypeCount: Decodable, Equatable, Sendable {
        let type: Int
        let count: Int
    }
    let items: Int
    let folders: Int
    /// Entries the file holds that can't be imported: trashed items and types Bitwarden files can't carry.
    let skipped: Int
    let types: [TypeCount]

    /// "12 items and 2 folders".
    var text: String { TransferCounts.text(items: items, folders: folders) }

    /// "8 Logins, 2 Cards".
    var breakdown: String {
        types.compactMap { entry in
            guard let type = VaultItemType(rawValue: entry.type) else { return nil }
            return type.counted(entry.count)
        }.joined(separator: ", ")
    }
}

/// The core's reply to a committed import. The snapshot is missing if the follow-up sync failed.
struct ImportCommit: Decodable, Sendable {
    let items: Int
    let folders: Int
    let snapshot: VaultSnapshot?
}

struct ImportSummary: Equatable, Sendable {
    let items: Int
    let folders: Int

    var text: String { ImportPreview(items: items, folders: folders, skipped: 0, types: []).text }
}

enum ExportOutcome: Equatable {
    case cancelled
    case saved(ExportSummary, URL)
}

/// The file panels. The model only ever sees the URLs they return, so its flows are testable
/// without opening a window.
@MainActor
protocol TransferPanels {
    /// Where to save the export, or nil if the user cancelled.
    func chooseExportDestination(suggestedName: String, fileExtension: String) -> URL?
    /// The file to import, or nil if the user cancelled.
    func chooseImportFile() -> URL?
}

@MainActor
struct SystemTransferPanels: TransferPanels {
    func chooseExportDestination(suggestedName: String, fileExtension: String) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [fileExtension == "csv" ? .commaSeparatedText : .json]
        panel.isExtensionHidden = false
        panel.canCreateDirectories = true
        panel.title = String(localized: "Export Vault")
        panel.prompt = String(localized: "Export")
        return panel.runModal() == .OK ? panel.url : nil
    }

    func chooseImportFile() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json, .commaSeparatedText]
        panel.title = String(localized: "Import Data")
        panel.message = String(localized: "Choose a Bitwarden export (.json, .csv or encrypted .json).")
        return panel.runModal() == .OK ? panel.url : nil
    }
}

extension VaultModel {
    /// Re-authenticates with the master password, asks where to save, then writes the file. A
    /// wrong master password stops before the panel opens and again inside the write, so no file
    /// exists unless the password was right. Throws a `VaultError` the sheet shows.
    func exportVault(_ options: ExportOptions, masterPassword: String, panels: TransferPanels,
                     now: Date = Date()) async throws -> ExportOutcome {
        try requireUnlocked()
        if let problem = options.problem(masterPassword: masterPassword) {
            throw VaultError(code: "invalidInput", message: problem)
        }
        try await SDKClient.shared.verifyMasterPassword(masterPassword)
        try requireUnlocked()
        guard let url = panels.chooseExportDestination(
            suggestedName: ExportFileName.suggested(extension: options.fileExtension, now: now),
            fileExtension: options.fileExtension) else { return .cancelled }
        try requireUnlocked()
        let summary = try await SDKClient.shared.exportVault(
            format: options.requestFormat, filePassword: options.needsFilePassword ? options.filePassword : nil,
            masterPassword: masterPassword, to: url)
        return .saved(summary, url)
    }

    /// Reads the file and shows what it holds, importing nothing. Throws `passwordRequired` for a
    /// password-protected file and `invalidFilePassword` for a wrong file password.
    func prepareImport(from url: URL, filePassword: String? = nil) async throws -> ImportPreview {
        try requireUnlocked()
        let preview = try await SDKClient.shared.prepareImport(from: url, filePassword: filePassword?.isEmpty == false ? filePassword : nil)
        try requireUnlocked()
        return preview
    }

    /// Drops what `prepareImport` read (a cancelled sheet).
    func discardImport() {
        Task { await SDKClient.shared.discardImport() }
    }

    func requireUnlocked() throws {
        guard phase == .unlocked else { throw VaultError(code: "locked", message: String(localized: "Unlock the vault first.")) }
    }
}
