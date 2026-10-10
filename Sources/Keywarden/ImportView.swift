import SwiftUI

/// File › Import Data. Pick a Bitwarden export, see what it holds, confirm, import. Nothing is
/// uploaded until the counts are confirmed, and the decrypted file stays inside the core.
struct ImportSheet: View {
    let model: VaultModel
    let panels: TransferPanels
    @State private var file: URL?
    @State private var filePassword = ""
    @State private var needsPassword = false
    @State private var preview: ImportPreview?
    @State private var result: ImportSummary?
    @State private var working = false
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    init(model: VaultModel, panels: TransferPanels = SystemTransferPanels(),
         preview: ImportPreview? = nil, needsPassword: Bool = false, result: ImportSummary? = nil) {
        self.model = model
        self.panels = panels
        _preview = State(initialValue: preview)
        _needsPassword = State(initialValue: needsPassword)
        _result = State(initialValue: result)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Import Data").font(.headline)
            if let result { done(result) } else if let preview { confirm(preview) } else { choose }
        }
        .padding(20)
        .frame(width: 440)
        .onDisappear { model.discardImport() }
    }

    private var choose: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Import a Bitwarden export into your vault. Supported files are Bitwarden .json, .csv and encrypted .json (account restricted or password protected).")
                .fixedSize(horizontal: false, vertical: true)
            if needsPassword {
                Text("“\(file?.lastPathComponent ?? String(localized: "This file"))” is protected with a password.")
                    .fixedSize(horizontal: false, vertical: true)
                SecureField("File password", text: $filePassword)
                    .onSubmit(readAgain)
                    .accessibilityIdentifier("importFilePassword")
            }
            Text("Items are added next to what you already have. Nothing is replaced, so importing the same file twice makes duplicates.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("importError")
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if needsPassword {
                    Button("Continue", action: readAgain)
                        .keyboardShortcut(.defaultAction)
                        .disabled(working || filePassword.isEmpty)
                        .accessibilityIdentifier("importContinue")
                    Button("Choose Another File…", action: pickFile)
                        .disabled(working)
                } else {
                    Button("Choose File…", action: pickFile)
                        .keyboardShortcut(.defaultAction)
                        .disabled(working)
                        .accessibilityIdentifier("importChoose")
                }
            }
        }
        .disabled(working)
    }

    private func confirm(_ preview: ImportPreview) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import \(preview.text)?")
                .font(.title3.weight(.semibold))
                .accessibilityIdentifier("importCount")
            if let file { Text("From \(file.lastPathComponent).").foregroundStyle(.secondary) }
            if !preview.breakdown.isEmpty { Text(preview.breakdown) }
            if preview.skipped > 0 {
                Text("\(preview.skipped) other entries can’t be imported: items in the trash, and types Bitwarden files can’t carry.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("importError")
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button("Import \(preview.items) Items", action: commit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || preview.items == 0)
                    .accessibilityIdentifier("importConfirm")
            }
        }
    }

    private func done(_ result: ImportSummary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Imported \(result.text)", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityIdentifier("importResult")
            Text("They are in your vault now. Delete the file if it isn’t encrypted.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("importDone")
            }
        }
    }

    private func pickFile() {
        guard let url = panels.chooseImportFile() else { return }
        file = url
        filePassword = ""
        needsPassword = false
        read(url, password: nil)
    }

    private func readAgain() {
        guard let file, !filePassword.isEmpty else { return }
        read(file, password: filePassword)
    }

    private func read(_ url: URL, password: String?) {
        guard !working else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                preview = try await model.prepareImport(from: url, filePassword: password)
                filePassword = ""
            } catch let failure as VaultError where failure.code == "passwordRequired" {
                needsPassword = true
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func commit() {
        guard !working else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do { result = try await model.commitImport() }
            catch { self.error = error.localizedDescription }
        }
    }
}
