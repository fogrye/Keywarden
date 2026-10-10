#!/bin/zsh
# Builds a signed Release and installs it into /Applications, replacing a running copy.
#
#   scripts/install.sh            build, install, relaunch
#   scripts/install.sh --test     run the Rust unit tests first
#   scripts/install.sh --no-open  don't relaunch afterwards
#
# Your account, Keychain items, Touch ID enrolment and Firefox connection carry over: they are
# tied to the signing team and bundle ID, and an app in /Applications is registered with Firefox
# in place.
set -euo pipefail
cd "${0:A:h}/.."

DEST="${BW_INSTALL_DIR:-/Applications}"
APP_NAME="Keywarden.app"
BUNDLE_ID="xyz.kuvshynov.Keywarden"
OPEN=1
# The app binary with or without arguments (Firefox launches it with --background).
RUNNING="/Contents/MacOS/keywarden( |$)"
for arg in "$@"; do
  case "$arg" in
    --test) cargo test --locked --manifest-path RustIpc/Cargo.toml ;;
    --no-open) OPEN=0 ;;
    *) print -u2 "Unknown option: $arg"; exit 2 ;;
  esac
done

BUILD=$(git rev-list --count HEAD)
COMMIT=$(git rev-parse --short HEAD)
git diff --quiet HEAD -- Sources RustIpc/src project.yml || COMMIT="$COMMIT + uncommitted changes"

print "Building build $BUILD ($COMMIT)…"
xcodegen generate --quiet
LOG=$(mktemp -t keywarden-build)
if ! xcodebuild -project Keywarden.xcodeproj -scheme Keywarden \
    -configuration Release -derivedDataPath .build/xcode -allowProvisioningUpdates \
    CURRENT_PROJECT_VERSION="$BUILD" build >"$LOG" 2>&1; then
  grep -E "error:|\*\* BUILD" "$LOG" | head -20
  print -u2 "Build failed; full log: $LOG"
  exit 1
fi
rm -f "$LOG"

SOURCE=".build/xcode/Build/Products/Release/$APP_NAME"
codesign --verify --strict "$SOURCE"
codesign --verify --strict "$SOURCE/Contents/Helpers/keywarden-native-host"

# Quit any running copy (it locks the vault on the way out) before replacing the bundle.
if pgrep -qf "$RUNNING"; then
  print "Quitting the running copy…"
  "$SOURCE/Contents/MacOS/keywarden" --quit || true
  for _ in {1..50}; do pgrep -qf "$RUNNING" || break; sleep 0.2; done
  if pgrep -qf "$RUNNING"; then
    # Builds older than --quit support: ask through Apple Events instead.
    osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
    for _ in {1..50}; do pgrep -qf "$RUNNING" || break; sleep 0.2; done
  fi
  if pgrep -qf "$RUNNING"; then
    print -u2 "Keywarden is still running; quit it from the menu bar and run this again."
    exit 1
  fi
fi

mkdir -p "$DEST"
rm -rf "$DEST/$APP_NAME.new"
ditto "$SOURCE" "$DEST/$APP_NAME.new"
rm -rf "$DEST/$APP_NAME"
mv "$DEST/$APP_NAME.new" "$DEST/$APP_NAME"
print "Installed $DEST/$APP_NAME — build $BUILD ($COMMIT)"

if (( OPEN )); then
  open "$DEST/$APP_NAME"
fi
