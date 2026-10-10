# Contributing

Contributions are accepted under the project's license, GPL-3.0-only. `AGENTS.md` describes the layout, the workflow for every change and the known pitfalls.

## Build

Requires macOS 26+, Apple Silicon, Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen), Rust/Cargo, and a signing team. `project.yml` uses team `X6MQJZ5R84`; change it for another machine.

```sh
xcodegen generate
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden \
  -configuration Release -derivedDataPath .build/xcode -allowProvisioningUpdates build
```

Editors that use SourceKit-LSP (Zed, VS Code) can't read an Xcode project, and report every type from another file as missing. [xcode-build-server](https://github.com/SolaWing/xcode-build-server) gives them the flags from the Xcode build log:

```sh
brew install xcode-build-server
xcode-build-server config -project Keywarden.xcodeproj -scheme Keywarden --build_root "$PWD/.build/xcode"
```

It learns a target's flags when a build compiles it, so run one `clean build-for-testing` in Debug first, then restart the language server.

## Tests

```sh
cargo test --manifest-path RustIpc/Cargo.toml          # unit tests; HTTP fixtures use loopback only
```

End-to-end tests need a **disposable** server. Never point them at a real account: they register accounts and create and delete items. The suite signs in a dozen times, so the server needs a relaxed login rate limit, which `scripts/test-server.sh` sets; the server's default refills one sign-in a minute. HTTP 429 produces a rate-limit message, not an unsupported-authentication error.

Authentication regression tests in `RustIpc/src/api.rs` cover a version-enforcing identity server and distinguish incorrect credentials, missing or rejected client versions, new-device email verification, two-step login, SSO, CAPTCHA, rate limits and server outages. Identity requests (including token refresh) and SDK API requests send Keywarden's product version, not a fabricated newer Bitwarden client version. Servers may still refuse an account whose encryption requires a newer compatible client.

```sh
scripts/test-server.sh   # a disposable Bitwarden-compatible server on 127.0.0.1:18088 (Docker)
BW_E2E_SERVER=http://127.0.0.1:18088 cargo test --manifest-path RustIpc/Cargo.toml e2e -- --ignored
# Seed an account with one item of every kind for the Swift tests:
BW_E2E_SERVER=http://127.0.0.1:18088 BW_SEED_EMAIL=… BW_SEED_PASSWORD=… \
  cargo test --manifest-path RustIpc/Cargo.toml seed_demo_vault -- --ignored
```

The Rust e2e test covers the whole write path through the same JSON entry point the app uses:
- create, edit (password history kept), TOTP, favorite and move;
- folder create, rename and delete;
- trash, restore and permanent delete;
- sync agreement, lock, then password unlock from the encrypted cache.

The Swift tests (`xcodebuild … test`) read the seeded account from the runner environment. Pass `TEST_RUNNER_BW_TEST_SERVER/EMAIL/PASSWORD/DATA_DIR/NAMESPACE`, where `DATA_DIR` is an absolute directory with mode 700, and `TEST_RUNNER_BW_UI_TEST_SERVER/EMAIL/PASSWORD` for the UI test. The Mac must be unlocked, because Keychain writes fail while the screen is locked.

Use a fresh test data directory and a UUID for `NAMESPACE`; a stale account pointer can fail before sign-in, and a non-UUID namespace does not enable in-memory credentials. The UI-test app receives Foundation's single-dash UserDefaults arguments (`-AppleLanguages`, `-AppleLocale`, etc.) even when `XCTestSessionIdentifier` is absent. The launch parser accepts those key/value pairs while keeping Keywarden's explicit commands strict; `LaunchArgumentsTests` covers this contract. If XCUITest stalls in `app.launch()`, inspect the `/tmp/bw-ui-app-*.log` captured stderr before blaming debugger warnings: a rejected launch argument makes the app exit before any UI automation.

Tests live at the lowest level that can show the behaviour:

| Where | What it covers | Cost |
| --- | --- | --- |
| `cargo test` (`RustIpc/`) | SDK bridge logic; the e2e test signs in, syncs, saves and locks against the server | no screen |
| `KeywardenTests` (`-only-testing:KeywardenTests`) | model, settings and controllers, plus the real SwiftUI views hosted in an unseen window and read or driven through their accessibility tree (`AXTree`, `HostedWindow`): sign-in, list, details, editor, trash, lock and unlock, close-window locking, read-only settings while locked, generator, history, attachments, passkeys, clone, advanced search, export and import sheets | about a minute, no screen takeover |
| `KeywardenUITests` (`-only-testing:KeywardenUITests`) | one smoke flow in a real app process: launch and sign-in, menu bar extra, main menu and shortcuts, window close and reopen, and a read of the real accessibility tree | takes over the screen for under a minute; quit the installed copy first |

Anything a hosted test can check does not belong in the UI test.

CI (`.github/workflows/ci.yml`) runs the Rust unit tests, the license check, an unsigned `build-for-testing` and the Rust e2e test against a throwaway server. `KeywardenTests` and the UI test need signing and a seeded account, so they stay local.

`KeywardenTests/DetailRenderingTests/testSecretValueRowRevealsOnlyWhenNotConcealed` exercises secret reveal, hide and concealed-share controls in a hosted window without a server account.

## Install a local build

```sh
scripts/install.sh          # build a signed Release, quit the running copy, install to /Applications, relaunch
scripts/install.sh --test   # run the Rust unit tests first
```

The build number shown in **Settings › App** is the git commit count. Account, Keychain items, Touch ID enrolment and the browser connection carry over between builds signed by the same team.

`scripts/release.sh` builds the Developer ID-signed, notarized zip for distribution. Pushing a semantic version tag (`v1.2.0`, or `v1.2.0-beta.1` for a prerelease) runs it in CI (`.github/workflows/release.yml`, which lists the secrets it needs) and attaches the zip to a GitHub release, with a build provenance attestation once the repository is public (`gh attestation verify <zip> --repo fogrye/keywarden`).

Only the final, stapled `.build/release/Keywarden-*.zip` is attested and published; `upload.zip` stays private to the build.

## Screenshots

The README screenshots come from `DetailRenderingTests.testLiveWindowSelectionAndEditing` against the seeded demo account, never a real vault. With `TEST_RUNNER_BW_RENDER_DIR` set, the test leaves a `<name>.window` file holding the window number and waits up to 30 s for `<name>.png`. Something with Screen Recording permission takes the capture from outside the test app (`screencapture -o -l<number> <name>.png`). Copy the PNGs into `docs/screenshots/`.
