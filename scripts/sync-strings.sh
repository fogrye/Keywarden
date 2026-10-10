#!/bin/zsh
# Adds new UI strings to Sources/Keywarden/Localizable.xcstrings and marks removed ones stale, as
# Xcode does on build. Command-line builds don't update the catalog, so run this after changing text.
# Then translate the new entries for every language (LocalizationTests fails until they are).
set -euo pipefail
cd "${0:A:h}/.."

derived=$(mktemp -d)
trap 'rm -rf "$derived"' EXIT
xcodebuild -project Keywarden.xcodeproj -scheme Keywarden -configuration Debug -derivedDataPath "$derived" \
  build -quiet
args=()
for file in "$derived"/Build/Intermediates.noindex/Keywarden.build/Debug/Keywarden.build/**/*.stringsdata; do
  args+=(--stringsdata "$file")
done
xcrun xcstringstool sync Sources/Keywarden/Localizable.xcstrings "${args[@]}"
