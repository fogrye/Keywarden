import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Bitwarden's limit for one attachment, checked against the plain file before anything is read.
enum AttachmentLimits {
    static let maxBytes: Int64 = 500 * 1024 * 1024

    /// Why the file can't be attached, or nil when it can.
    static func problem(with url: URL) -> String? {
        // A fresh URL, so sizes cached on the caller's copy are never used.
        guard let values = try? URL(fileURLWithPath: url.path).resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
              values.isRegularFile == true else { return String(localized: "Choose a file to attach.") }
        if Int64(values.fileSize ?? 0) > maxBytes { return String(localized: "Attachments can be at most 500 MB.") }
        return nil
    }
}

/// The two file panels. The model only ever sees the URLs they return, so its logic is testable
/// without opening a window.
@MainActor
enum AttachmentPanels {
    /// Where to save a downloaded attachment, or nil if the user cancelled.
    static func chooseDestination(for fileName: String) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName(fileName)
        panel.canCreateDirectories = true
        panel.title = String(localized: "Save Attachment")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// The file to attach, or nil if the user cancelled.
    static func chooseFile() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.title = String(localized: "Add Attachment")
        panel.message = String(localized: "Choose a file to encrypt and attach (up to 500 MB).")
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Attachment names are user data and may hold path separators.
    static func suggestedName(_ name: String) -> String {
        let cleaned = name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? String(localized: "Attachment") : cleaned
    }
}

/// Attachments in the read-only detail: name, size and a download button.
struct AttachmentsDetailSection: View {
    let model: VaultModel
    let itemID: String
    let attachments: [ItemDetail.Attachment]

    var body: some View {
        Section("Attachments") {
            ForEach(attachments) { attachment in
                HStack(spacing: 8) {
                    Label(attachment.fileName, systemImage: "paperclip")
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    Spacer(minLength: 8)
                    Text(attachment.size ?? "").foregroundStyle(.secondary)
                    if model.attachmentActivity == .downloading(attachment.id) {
                        ProgressView().controlSize(.small)
                    } else {
                        Button {
                            guard let url = AttachmentPanels.chooseDestination(for: attachment.fileName) else { return }
                            Task { await model.downloadAttachment(itemID: itemID, attachment, to: url) }
                        } label: {
                            Image(systemName: "arrow.down.circle")
                        }
                        .buttonStyle(.borderless)
                        .help("Download “\(attachment.fileName)”")
                        .accessibilityIdentifier("downloadAttachment")
                        .disabled(model.attachmentActivity != nil)
                    }
                }
            }
        }
    }
}

/// Attachments in the editor: remove (after asking) and add. A new item has to be saved first,
/// as in Bitwarden Desktop, because attachments belong to a saved item.
struct AttachmentsEditorSection: View {
    let model: VaultModel
    let itemID: String?
    let attachments: [ItemDetail.Attachment]
    @State private var removing: ItemDetail.Attachment?

    var body: some View {
        Section {
            if let itemID {
                ForEach(attachments) { attachment in
                    HStack(spacing: 8) {
                        Label(attachment.fileName, systemImage: "paperclip")
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 8)
                        Text(attachment.size ?? "").foregroundStyle(.secondary)
                        if model.attachmentActivity == .removing(attachment.id) {
                            ProgressView().controlSize(.small)
                        } else {
                            Button("Remove", role: .destructive) { removing = attachment }
                                .buttonStyle(.borderless)
                                .foregroundStyle(.red)
                                .disabled(model.attachmentActivity != nil)
                                .accessibilityIdentifier("removeAttachment")
                        }
                    }
                }
                HStack(spacing: 8) {
                    Button("Add Attachment…") {
                        guard let url = AttachmentPanels.chooseFile() else { return }
                        Task { await model.addAttachment(itemID: itemID, from: url) }
                    }
                    .disabled(model.attachmentActivity != nil || model.isSaving)
                    .accessibilityIdentifier("addAttachment")
                    if model.attachmentActivity == .uploading {
                        ProgressView().controlSize(.small)
                        Text("Encrypting and uploading…").foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("Save the item first, then add attachments.").foregroundStyle(.secondary)
            }
        } header: {
            Text("Attachments")
        } footer: {
            if itemID != nil { Text("Files are encrypted before they leave this Mac. The limit is 500 MB each.") }
        }
        .confirmationDialog("Remove “\(removing?.fileName ?? "")”?", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }), presenting: removing) { attachment in
            Button("Remove Attachment", role: .destructive) {
                guard let itemID else { return }
                Task { await model.removeAttachment(itemID: itemID, attachment) }
            }
        } message: { _ in
            Text("This deletes the attachment from the server. It can’t be undone.")
        }
    }
}
