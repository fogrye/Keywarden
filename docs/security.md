# Security notes

- The disk cache (`~/Library/Application Support/Keywarden/Vault/`) holds only SDK-encrypted records, wrapped keys and non-secret metadata, under strict permission checks. Tokens live in the data-protection Keychain. The Touch ID enrolment uses a biometry-current-set access control. Security settings (timeout, timeout action, lock on sleep or window close, clipboard clearing) and the browser Touch ID opt-in live there too, not in preferences, so another app running as you can't loosen them.
- Edits start from the decrypted SDK item and patch only the fields the editor shows. Passkeys, attachments, password history, URI match rules and per-item keys survive saves.
- Attachments are encrypted and decrypted by the SDK (a per-attachment key, wrapped by the item key). Uploads read only the file you pick. Downloads are decrypted in memory and written only to the file you choose in the save panel; nothing is cached or put in a temporary file. File contents never pass through the app's JSON API, and attachment names, keys and contents are never logged.
- Exports ask for the master password (checked against the account's wrapped key on a scratch client) before anything is written. The export is built in memory, never through a temporary file, and its contents never pass through the app's JSON API or the log. Unencrypted exports are your responsibility once written.
- Generator history (up to 100 values) lives in memory only. Values generated while the vault is locked are kept too, but the list is shown only while it is unlocked; it is wiped when you log out or quit. Email forwarder API keys and tokens are kept in the Keychain, not in preferences.
- Locking discards decrypted state, drafts, revealed fields and owned clipboard contents.
- Server errors are logged to stderr (`[keywarden] …`) without request bodies.

