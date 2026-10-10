# Agent guide

Keywarden: native macOS client for Bitwarden-compatible vaults. It's a SwiftUI menu bar app and acts as the browser extension's native-messaging host, so browsers can unlock with Touch ID. Vault logic is Bitwarden's Rust SDK in `RustIpc/`, called through the JSON dispatch in `bw_app_request`.

## Every change

1. Work on a focused branch from current `origin/main`; reuse an existing branch only for the same task and an open PR. Never commit directly to `main`.
2. After adding or removing files, run `xcodegen generate`. The `.xcodeproj` comes from `project.yml` and isn't tracked.
3. For behaviour changes, update tests in the same commit, at the lowest level that shows the behaviour:
   - Rust: `#[cfg(test)]` in the module.
   - Swift and almost all UI: `Tests/KeywardenTests`. Host the real view with `HostedWindow` and drive it through its accessibility tree, as `VaultFlowTests` does. Rendering tests write PNGs when `TEST_RUNNER_BW_RENDER_DIR` is set; look at them.
   - `Tests/UITests` (XCUITest) only for what needs a separate app process: launch and sign-in, the menu bar extra, the main menu and shortcuts, window close and reopen. Keep it a short smoke flow.
4. Run local checks for the affected code; CI does not replace hosted Swift or UI tests:
   - `cargo test --manifest-path RustIpc/Cargo.toml`
   - `xcodebuild … test -only-testing:KeywardenTests[/Class[/method]]`. Needs the disposable server from CONTRIBUTING.md › Tests.
   - Run `KeywardenUITests` only when you change menus, shortcuts, window lifecycle or sign-in. Quit the installed app first (`/Applications/Keywarden.app/Contents/MacOS/keywarden --quit`); otherwise the single-instance handoff makes the test app exit. Otherwise just `build-for-testing` it.
   - Docs-only changes: check links and command accuracy; no app tests or installation.
5. Update docs only when setup or documented behaviour changes. Keep `CONTRIBUTING.md` limited to getting development running; no implementation diaries or test inventories.
6. Commit with a short message that says what changed for the user: a subject line, plus a line or two of body only when the reason isn't obvious. Don't describe the diff.
7. For app changes, run `scripts/install.sh` and report the build number.
8. Push the branch to `fogrye/Keywarden` and open or update a PR against `main`. Keep its description short: user-visible change, checks actually run and any blockers. Inspect GitHub Actions for the latest commit; fix failures caused by the change and report the PR URL and check status.
9. Do not merge PRs or push version tags unless requested. Version tags trigger signed, notarized GitHub releases through `.github/workflows/release.yml`.

## Gotchas

- No `.accessibilityLabel` on views inside a `LabeledContent` label or content. It overflows the stack under VoiceOver or XCUITest, and `AXTree` doesn't reproduce it.
- The item list is rebuilt with `.id(ListIdentity(…))` on search or destination change. Diffing rows froze the UI.
- Keychain writes fail while the screen is locked. Debug test namespaces (`BW_TEST_NAMESPACE`) use in-memory credentials.
- SDK request types aren't exported. Build them by type inference or serde JSON, as `items.rs` does.
- Security boundary: the helper's parent-browser checks (`Browsers.swift`, `PeerIdentity.swift`) and Touch ID gating (`BiometricCoordinator`). Changes there need tests in `BrowserMatchingTests`, `TouchIDPromptTests` or `FirefoxProtocolTests`.
- Never log secrets, keys, tokens or item contents.
- e2e tests only ever run against a disposable server, never a real account.
- The app is Keywarden. Say "Bitwarden" only for the service, the official extension, Bitwarden Desktop or the SDK. Never change the host name `com.8bit.bitwarden` or the SDK crate names.
- License is `GPL-3.0-only`. No crate from the SDK's `bitwarden_license/` folder and no GPL-incompatible dependency. After changing Rust dependencies, run `scripts/third-party-licenses.sh` and commit `ThirdPartyLicenses.txt`.
- Localization (`Localizable.xcstrings`):
  - A `String` shown in the UI needs `String(localized:)`. User data stays verbatim. Counts use plural keys with every CLDR form.
  - After changing text: `scripts/sync-strings.sh`, then `scripts/import-bitwarden-translations.py`, then translate the rest as `needs_review`. `translated` means it came from Bitwarden or a person checked it, so never mark AI output `translated`.
  - Touch ID reasons complete the system sentence "Keywarden is trying to …" and must keep the browser and account.
- Icons: edit `Branding/*.svg`. The assets are committed renders; `scripts/render-icon.sh` regenerates them. No SVG masks: AppKit draws a soft-masked PDF as empty.
