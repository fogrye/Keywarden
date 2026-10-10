#!/bin/zsh
# Builds a Developer ID-signed, notarized zip that runs on other Macs.
#
#   scripts/release.sh               archive, export, notarize, staple, zip into .build/release
#   scripts/release.sh --no-notarize stop after signing (testers will have to right-click › Open)
#
# BW_VERSION sets the semantic version (1.2.0, or 1.2.0-beta.1 for a prerelease); the app shows the
# part before the hyphen. Without it the version is project.yml's MARKETING_VERSION, labelled beta.
#
# Notarization needs a stored credential profile, created once with:
#   xcrun notarytool store-credentials keywarden --apple-id <id> --team-id X6MQJZ5R84
# CI (.github/workflows/release.yml) instead sets BW_ASC_KEY_PATH, BW_ASC_KEY_ID and BW_ASC_ISSUER_ID to
# an App Store Connect API key, which both signing and notarization then use.
# The build has the installed app's bundle ID, so it replaces it rather than sitting alongside.
set -euo pipefail
cd "${0:A:h}/.."

TEAM="X6MQJZ5R84"
PROFILE="${BW_NOTARY_PROFILE:-keywarden}"
NOTARIZE=1
xcauth=() notary=(--keychain-profile "$PROFILE")
if [[ -n ${BW_ASC_KEY_PATH:-} ]]; then
  xcauth=(-authenticationKeyPath "$BW_ASC_KEY_PATH" -authenticationKeyID "$BW_ASC_KEY_ID"
    -authenticationKeyIssuerID "$BW_ASC_ISSUER_ID")
  notary=(--key "$BW_ASC_KEY_PATH" --key-id "$BW_ASC_KEY_ID" --issuer "$BW_ASC_ISSUER_ID")
fi
for arg in "$@"; do
  case "$arg" in
    --no-notarize) NOTARIZE=0 ;;
    *) print -u2 "Unknown option: $arg"; exit 2 ;;
  esac
done

BUILD=$(git rev-list --count HEAD)
VERSION=${BW_VERSION:-$(sed -n 's/^ *MARKETING_VERSION: "\(.*\)"/\1/p' project.yml | head -1)-beta}
OUT=".build/release"
ARCHIVE="$OUT/Keywarden-$BUILD.xcarchive"
APP="$OUT/export/Keywarden.app"
ZIP="$OUT/Keywarden-$VERSION-$BUILD.zip"
git diff --quiet HEAD -- Sources RustIpc/src project.yml || print -u2 "Warning: uncommitted changes are in this build."

rm -rf "$OUT" && mkdir -p "$OUT"
LOG="$OUT/build.log"
fail() { grep -E "error:|\*\* (ARCHIVE|EXPORT)" "$LOG" | head -20; print -u2 "$1; full log: $LOG"; exit 1; }

print "Archiving build $BUILD…"
xcodegen generate --quiet
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden -configuration Release \
  -derivedDataPath .build/xcode -archivePath "$ARCHIVE" -allowProvisioningUpdates "${xcauth[@]}" \
  MARKETING_VERSION="${VERSION%%-*}" CURRENT_PROJECT_VERSION="$BUILD" archive >"$LOG" 2>&1 || fail "Archive failed"

cat >"$OUT/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>signingStyle</key><string>automatic</string>
  <key>teamID</key><string>$TEAM</string>
</dict></plist>
EOF
if [[ -n ${BW_DEVELOPER_ID_PROFILE:-} ]]; then
  /usr/libexec/PlistBuddy -c 'Set :signingStyle manual' "$OUT/ExportOptions.plist"
  /usr/libexec/PlistBuddy -c 'Add :signingCertificate string Developer ID Application' "$OUT/ExportOptions.plist"
  /usr/libexec/PlistBuddy -c 'Add :provisioningProfiles dict' "$OUT/ExportOptions.plist"
  /usr/libexec/PlistBuddy -c "Add :provisioningProfiles:xyz.kuvshynov.Keywarden string $BW_DEVELOPER_ID_PROFILE" \
    "$OUT/ExportOptions.plist"
fi
print "Signing with Developer ID…"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$OUT/export" \
  -exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates "${xcauth[@]}" >>"$LOG" 2>&1 \
  || fail "Export failed (a Developer ID Application certificate is needed: Xcode › Settings › Accounts › Manage Certificates)"

for code in "$APP" "$APP/Contents/Helpers/keywarden-native-host"; do
  codesign --verify --strict "$code"
  codesign -d --entitlements - "$code" 2>/dev/null | grep -q get-task-allow && { print -u2 "$code is debuggable"; exit 1; }
done

if (( NOTARIZE )); then
  print "Notarizing…"
  ditto -c -k --keepParent "$APP" "$OUT/upload.zip"
  xcrun notarytool submit "$OUT/upload.zip" "${notary[@]}" --wait
  xcrun stapler staple "$APP"
  spctl --assess --type execute "$APP"
fi
ditto -c -k --keepParent "$APP" "$ZIP"
print "Built $ZIP — $VERSION build $BUILD"
