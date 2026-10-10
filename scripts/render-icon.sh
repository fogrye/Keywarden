#!/bin/zsh
# Renders the icons in Branding/ into the app's asset catalog. Needs rsvg-convert (brew install librsvg).
set -euo pipefail
cd "${0:A:h}/.."

ASSETS=Sources/Keywarden/Assets.xcassets

ICONSET=$ASSETS/AppIcon.appiconset
for size in 16 32 128 256 512; do
  for scale in 1 2; do
    rsvg-convert -w $((size * scale)) -h $((size * scale)) Branding/AppIcon.svg \
      -o "$ICONSET/icon_${size}x${size}@${scale}x.png"
  done
done

# The locked shield is generated as plain paths: a custom SF Symbol (Settings toolbar tabs draw only
# symbols) and Branding/MenuBarLocked.svg.
python3 Branding/make-symbol.py $ASSETS/ShieldKey.symbolset/shield-key.svg Branding/MenuBarLocked.svg

# The shield icons (menu bar, lock screen, settings) are 18 pt vector template images: they stay
# sharp at any size, and macOS tints them for light and dark appearances.
for state in Locked Unlocked; do
  IMAGESET=$ASSETS/MenuBar$state.imageset
  rm -rf "$IMAGESET"
  mkdir -p "$IMAGESET"
  rsvg-convert -f pdf --dpi-x 72 --dpi-y 72 -w 18 -h 18 Branding/MenuBar$state.svg -o "$IMAGESET/menubar-${state:l}.pdf"
  cat > "$IMAGESET/Contents.json" <<JSON
{
  "images" : [
    { "filename" : "menubar-${state:l}.pdf", "idiom" : "universal" }
  ],
  "info" : { "author" : "xcode", "version" : 1 },
  "properties" : {
    "preserves-vector-representation" : true,
    "template-rendering-intent" : "template"
  }
}
JSON
done
print "Rendered $ASSETS"
