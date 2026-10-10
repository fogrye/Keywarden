import SwiftUI

struct ItemListView: View {
    @Bindable var model: VaultModel
    @FocusState private var focused: Bool

    private var selection: Binding<String?> {
        Binding(get: { model.selection }, set: { model.select($0) })
    }

    var body: some View {
        let items = model.visibleItems
        ScrollViewReader { proxy in
            List(selection: selection) {
                ForEach(items) { item in
                    ItemRow(item: item, iconURL: model.iconURL(item.iconHost))
                        .id(item.id)
                        .tag(item.id)
                        .contextMenu { menu(for: item) }
                }
            }
            // Search arrows change selection while focus stays in the toolbar, so the table
            // doesn't scroll itself. Also reveal a surviving selection when the list rebuilds.
            .onChange(of: model.selection, initial: true) { _, id in
                if let id { proxy.scrollTo(id) }
            }
        }
        // → moves into the item's fields, Esc back to the search field.
        .focused($focused)
        .onKeyPress(.rightArrow) {
            guard model.selection != nil, model.editor == nil else { return .ignored }
            model.focusRequest = .detail
            return .handled
        }
        .onExitCommand { model.focusRequest = .search }
        // Rebuild rather than diff when the result set changes wholesale. A diff inserts rows one by
        // one and the table measures each inserted row's height on the main thread, which froze
        // the window for seconds when a search widened back to the whole vault.
        .id(ListIdentity(destination: model.destination, search: model.effectiveSearch))
        .onChange(of: model.focusRequest, initial: true) { _, pane in
            guard pane == .list else { return }
            focused = true
            model.focusRequest = nil
        }
        .overlay {
            if items.isEmpty { emptyState }
        }
        .navigationTitle(title)
        .navigationSubtitle(items.isEmpty ? "" : String(localized: "\(items.count) items"))
        .onDeleteCommand {
            guard let item = model.selectedSummary, model.editor == nil else { return }
            if item.deleted { model.confirmingDelete = item.id } else { Task { await model.moveToTrash(item.id) } }
        }
        // The one "Delete permanently?" for the list, the detail and the Item menu.
        .confirmationDialog("Delete “\(confirmingName)” permanently?", isPresented: Binding(
            get: { model.confirmingDelete != nil }, set: { if !$0 { model.confirmingDelete = nil } }
        ), presenting: model.confirmingDelete) { id in
            Button("Delete Permanently", role: .destructive) { Task { await model.deletePermanently(id) } }
        } message: { _ in
            Text("This can’t be undone.")
        }
    }

    private var confirmingName: String {
        model.items.first { $0.id == model.confirmingDelete }?.name ?? ""
    }

    private var title: String {
        switch model.destination {
        case .all, .generator: String(localized: "All Items")
        case .favorites: String(localized: "Favorites")
        case .type(let type): type.pluralTitle
        case .folder(let id): model.folderName(id) ?? String(localized: "Folder")
        case .noFolder: String(localized: "No Folder")
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Trash")
        }
    }

    @ViewBuilder private var emptyState: some View {
        if model.search.trimmingCharacters(in: .whitespaces).count >= 2 {
            ContentUnavailableView.search(text: model.search)
        } else if model.destination == .archive {
            ContentUnavailableView("Archive Is Empty", systemImage: "archivebox",
                                   description: Text("Archived items are kept out of your vault lists and autofill."))
        } else if model.destination == .trash {
            ContentUnavailableView("Trash Is Empty", systemImage: "trash",
                                   description: Text("Deleted items stay here until you remove them."))
        } else {
            ContentUnavailableView("No Items", systemImage: "tray",
                                   description: Text("Use the + button to add one."))
        }
    }

    @ViewBuilder private func menu(for item: VaultItemSummary) -> some View {
        if item.deleted {
            Button("Restore") { Task { await model.restoreFromTrash(item.id) } }
            Button("Delete Permanently…", role: .destructive) { model.confirmingDelete = item.id }
        } else {
            Button(item.favorite ? "Remove from Favorites" : "Add to Favorites") {
                Task { await model.setFavorite(item.id, !item.favorite) }
            }
            Menu("Move to Folder") {
                Button("No Folder") { Task { await model.move(item.id, toFolder: nil) } }
                    .disabled(item.folderId == nil)
                ForEach(model.folders) { folder in
                    Button(folder.name) { Task { await model.move(item.id, toFolder: folder.id) } }
                        .disabled(item.folderId == folder.id)
                }
            }
            Button(item.archived ? "Unarchive" : "Archive") {
                Task { await model.setArchived(item.id, !item.archived) }
            }
            Divider()
            Button("Move to Trash", role: .destructive) { Task { await model.moveToTrash(item.id) } }
        }
    }
}

struct ItemRow: View {
    let item: VaultItemSummary
    var iconURL: URL?

    var body: some View {
        HStack(spacing: 10) {
            ItemIcon(type: item.kind, size: 28, url: iconURL)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(item.name).lineLimit(1)
                    if item.favorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(.yellow)
                            .accessibilityLabel("Favorite")
                    }
                }
                if !item.subtitle.isEmpty {
                    Text(item.subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            if item.organizationId != nil {
                Image(systemName: "person.2")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help("Shared through an organization")
            }
        }
        .padding(.vertical, 3)
    }
}

/// A rounded, type-coloured glyph in the style of the system Passwords app, or the website's icon.
struct ItemIcon: View {
    let type: VaultItemType
    var size: CGFloat = 28
    var url: URL?
    @State private var fetched: (url: URL, image: NSImage?)?

    var body: some View {
        // A cached icon draws at once, so rebuilding the list (every search change) doesn't flicker.
        let image = url.flatMap { url in fetched?.url == url ? fetched?.image : WebsiteIcons.shared.cached(url) }
        Group {
            if let image {
                Image(nsImage: image).resizable()
                    .interpolation(.high)
                    .scaledToFit()
                    .padding(size * 0.12)
                    .frame(width: size, height: size)
                    .background(.background, in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                        .strokeBorder(.separator, lineWidth: 0.5))
                    .accessibilityHidden(true)
            } else {
                glyph
            }
        }
        .task(id: url) {
            guard let url, WebsiteIcons.shared.cached(url) == nil else { return }
            let image = await WebsiteIcons.shared.image(for: url)
            if !Task.isCancelled { fetched = (url, image) }
        }
    }

    private var glyph: some View {
        Image(systemName: type.symbol)
            .font(.system(size: size * 0.48, weight: .medium))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(type.tint.gradient, in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
            .accessibilityHidden(true)
    }
}

extension VaultItemType {
    var tint: Color {
        switch self {
        case .login: .blue
        case .note: .yellow
        case .card: .green
        case .identity: .purple
        case .sshKey: .gray
        case .bankAccount: .teal
        case .driversLicense: .orange
        case .passport: .indigo
        }
    }
}

private struct ListIdentity: Hashable {
    let destination: SidebarItem
    let search: String
}
