# Contributing

GPL-3.0-only. See `AGENTS.md` for the development workflow and known pitfalls.

## Build

Requires macOS 26+, Apple Silicon, Xcode, [XcodeGen](https://github.com/yonaskolb/XcodeGen), Rust/Cargo, and a signing team. `project.yml` uses team `X6MQJZ5R84`; change it for another machine.

CI and releases use Xcode 27.0 on the `xcode-27` runner, pinned to its stable compiler rather than the installed betas. Xcode 26.5 and 26.6 crash during Release IR generation for an async actor reabstraction. The app's deployment target remains macOS 26.

```sh
xcodegen generate
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden \
  -configuration Release -derivedDataPath .build/xcode -allowProvisioningUpdates build
```

Optional SourceKit-LSP setup for Zed or VS Code:

```sh
brew install xcode-build-server
xcode-build-server config -project Keywarden.xcodeproj -scheme Keywarden --build_root "$PWD/.build/xcode"
```

Run a Debug `clean build-for-testing` once, then restart the language server.

## Tests

```sh
cargo test --manifest-path RustIpc/Cargo.toml
```

End-to-end and Swift tests require Docker and a disposable server. Never use a real account: tests create and delete vault data.

```sh
scripts/test-server.sh   # a disposable Bitwarden-compatible server on 127.0.0.1:18088 (Docker)
BW_E2E_SERVER=http://127.0.0.1:18088 cargo test --manifest-path RustIpc/Cargo.toml e2e -- --ignored
# Seed an account with one item of every kind for the Swift tests:
export BW_SEED_EMAIL=developer@example.test
export BW_SEED_PASSWORD="$(uuidgen)"
BW_E2E_SERVER=http://127.0.0.1:18088 \
  cargo test --manifest-path RustIpc/Cargo.toml seed_demo_vault -- --ignored
```

For Swift tests, use the seeded account above:

```sh
export TEST_RUNNER_BW_TEST_SERVER=http://127.0.0.1:18088
export TEST_RUNNER_BW_TEST_EMAIL="$BW_SEED_EMAIL"
export TEST_RUNNER_BW_TEST_PASSWORD="$BW_SEED_PASSWORD"
export TEST_RUNNER_BW_TEST_DATA_DIR="$(mktemp -d)"
export TEST_RUNNER_BW_TEST_NAMESPACE="$(uuidgen)"
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden \
  -configuration Debug -derivedDataPath .build/xcode -allowProvisioningUpdates \
  test -only-testing:KeywardenTests
```

Keep the Mac unlocked. Use a fresh data directory (mode 700) and UUID namespace for each run.

Use `KeywardenTests` for Swift logic and hosted views. Run `KeywardenUITests` only for sign-in, menus, shortcuts or window lifecycle changes:

```sh
export TEST_RUNNER_BW_UI_TEST_SERVER="$TEST_RUNNER_BW_TEST_SERVER"
export TEST_RUNNER_BW_UI_TEST_EMAIL="$BW_SEED_EMAIL"
export TEST_RUNNER_BW_UI_TEST_PASSWORD="$BW_SEED_PASSWORD"
/Applications/Keywarden.app/Contents/MacOS/keywarden --quit
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden \
  -configuration Debug -derivedDataPath .build/xcode -allowProvisioningUpdates \
  test -only-testing:KeywardenUITests
```

## Install a local build

```sh
scripts/install.sh          # build a signed Release, quit the running copy, install to /Applications, relaunch
scripts/install.sh --test   # run the Rust unit tests first
```

