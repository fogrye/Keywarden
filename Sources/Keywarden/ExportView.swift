import AppKit
import SwiftUI

/// File › Export Vault. Asks for the format, the master password (as Bitwarden Desktop does) and,
/// for password-protected files, a file password; unencrypted formats carry a warning.
struct ExportSheet: View {
    let model: VaultModel
    let panels: TransferPanels
    @State private var options: ExportOptions
    @State private var masterPassword = ""
    @State private var working = false
    @State private var error: String?
    @State private var saved: (summary: ExportSummary, url: URL)?
    @Environment(\.dismiss) private var dismiss

    init(model: VaultModel, panels: TransferPanels = SystemTransferPanels(), options: ExportOptions = ExportOptions()) {
        self.model = model
        self.panels = panels
        _options = State(initialValue: options)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Export Vault").font(.headline)
            if let saved { done(saved.summary, saved.url) } else { form }
        }
        .padding(20)
        .frame(width: 440)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 14) {
            Picker("File format", selection: $options.format) {
                ForEach(ExportOptions.Format.allCases) { Text($0.title).tag($0) }
            }
            .accessibilityIdentifier("exportFormat")
            if options.isEncrypted {
                Picker("Encryption", selection: $options.protection) {
                    ForEach(ExportOptions.Protection.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.radioGroup)
                .accessibilityIdentifier("exportProtection")
                Text(options.protection == .account
                     ? "Encrypted with your account’s key. Only this account can import the file."
                     : "Encrypted with a password you choose. Anyone with the file and the password can read it, and it can’t be recovered if you forget it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if options.needsFilePassword {
                    SecureField("File password", text: $options.filePassword)
                    SecureField("Confirm file password", text: $options.confirmation)
                }
            }
            SecureField("Master password", text: $masterPassword)
                .onSubmit(start)
                .accessibilityIdentifier("exportMasterPassword")
            Text("Confirm your master password to export. Only the individual vault is exported, not items shared through organizations or the trash.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !options.isEncrypted { warning }
            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("exportError")
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Export Vault", action: start)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || options.problem(masterPassword: masterPassword) != nil)
                    .accessibilityIdentifier("exportConfirm")
            }
        }
        .disabled(working)
        .onChange(of: options) { _, _ in error = nil }
    }

    private var warning: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("This export contains your vault data in an unencrypted format. Don’t store or send the file over insecure channels such as email, and delete it as soon as you’re done with it.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
        .accessibilityIdentifier("exportWarning")
    }

    private func done(_ summary: ExportSummary, _ url: URL) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Exported \(summary.text)", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
            Text("Saved as \(url.lastPathComponent).")
                .textSelection(.enabled)
            if summary.omitted > 0 {
                Text("\(summary.omitted) items were left out because this format can’t hold them (or they couldn’t be decrypted).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("exportDone")
            }
        }
    }

    private func start() {
        guard !working, options.problem(masterPassword: masterPassword) == nil else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                switch try await model.exportVault(options, masterPassword: masterPassword, panels: panels) {
                case .cancelled: break
                case .saved(let summary, let url):
                    masterPassword = ""
                    options.filePassword = ""
                    options.confirmation = ""
                    saved = (summary, url)
                }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
