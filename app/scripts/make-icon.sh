#!/bin/bash
# Renders assets/icon.svg into the AppIcon set. Replace the placeholder SVG with
# the app's own icon, then run this. The PNGs are committed.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
svg="${1:-$here/assets/icon.svg}"
set_dir="$here/SecureApp/Resources/Assets.xcassets/AppIcon.appiconset"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Quick Look renders SVG with WebKit, so text in the icon uses the same fonts as Safari would.
qlmanage -t -s 1024 -o "$work" "$svg" >/dev/null 2>&1
master="$work/$(basename "$svg").png"
[ -f "$master" ] || { echo "make-icon: Quick Look did not render $svg" >&2; exit 1; }

mkdir -p "$set_dir"
images=""
for size in 16 32 128 256 512; do
  for scale in 1 2; do
    px=$((size * scale))
    name="icon_${size}x${size}@${scale}x.png"
    sips -z "$px" "$px" "$master" --out "$set_dir/$name" >/dev/null
    images="$images{\"idiom\":\"mac\",\"size\":\"${size}x${size}\",\"scale\":\"${scale}x\",\"filename\":\"$name\"},"
  done
done
printf '{"images":[%s],"info":{"author":"xcode","version":1}}\n' "${images%,}" > "$set_dir/Contents.json"
printf '{"info":{"author":"xcode","version":1}}\n' > "$set_dir/../Contents.json"
echo "make-icon: wrote $set_dir"
