# Keyboard & search

[← Keywarden](../README.md)

## Shortcuts

App shortcuts, not global hotkeys. Item actions apply to the current selection; copy and reveal actions respect re-prompt and organization restrictions.

| Action | Shortcut |
| --- | --- |
| Search | ⌘F |
| Copy username / password / one-time code | ⌘U / ⌘P / ⌘T |
| Copy field 1–9 in Item › Copy | ⌥⌘1–⌥⌘9 |
| Open website | ⇧⌘O |
| Edit / clone | ⌘E / ⌘D |
| Save in editor | ⌘S |
| New login / folder | ⌘N / ⇧⌘N |
| All Items / Favorites / Archive / Trash | ⌘1 / ⌘2 / ⌘3 / ⌘4 |
| Toggle sidebar | ⌃⌘S |
| Sync | ⌘R |
| Lock | ⌘L |
| Generator | ⌘G |
| Regenerate / copy in generator | ⌘R / ⇧⌘C |
| Import / export | ⇧⌘I / ⇧⌘E |
| Open Vault from menu-bar menu | ⌘O |
| Settings / quit | ⌘, / ⌘Q |

### Moving through the vault

| Focus | Keys |
| --- | --- |
| Search | ↑ ↓ select results; Return focuses the list |
| List | ↑ ↓ select items; → enters fields; Esc returns to search |
| Fields | ↑ ↓ move; Return copies; Space toggles a secret; ← or Esc returns to the list |
| Editor | Esc cancels |
| List deletion | ⌫ moves to Trash; in Trash, requests permanent deletion |

Return in search keeps the selected result, or selects the first one if needed. Tab navigation follows the macOS Keyboard navigation setting.

## Search expressions

Plain search matches names, usernames, websites and text custom fields from two characters onward. Start with `>` to search specific fields.

| Query | Matches |
| --- | --- |
| `>login.username:alice` | Username containing “alice” |
| `>name:git*` | Name with a word beginning “git” |
| `>+folder:Work -type:card` | Work folder, excluding cards |
| `>fields.Region:EU` | Region custom field containing “EU” |
| `>name:"my git"` | Name containing “my git” |

`+` requires a term, `-` excludes it, `*` is a wildcard. Without `+`, any positive term can match. Field scopes also cover notes, websites, card brand, identity details and attachment filenames. Invalid syntax falls back to plain search.

Secret values are never searchable. Re-prompt-protected items also exclude notes and custom fields.

## Worth knowing

- **Edits need a connection.** Offline access uses the encrypted cache. Sync runs after unlock and on window open if the last sync is over five minutes old.
- **SSH key material is read-only.** Name, folder, notes and custom fields remain editable. Other item types can be created and fully edited.
- **Attachments need a saved item.** Add or remove them in the editor; download from details. Maximum 500 MB each.
- **Clipboard clears after 60 seconds by default.** Session locking and clipboard policy are in Settings › Security and Preferences.
- **Import adds; it does not merge.** Bitwarden files only, up to 64 MB and 7,000 items. Importing twice creates duplicates. Account-restricted encrypted files require the same account.
- **Export requires the master password.** JSON and CSV are plaintext unless encrypted JSON is selected. Trash and organization-owned items are excluded; CSV supports logins and notes only, and JSON excludes bank accounts, driver's licenses and passports.

[Browser connection](browser-touch-id.md) · [Security details](security.md)
