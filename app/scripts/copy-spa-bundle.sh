#!/bin/bash
# Copies the web bundle into the app.
#
#   copy-spa-bundle.sh                 from an Xcode Run Script phase (uses Xcode's build settings)
#   copy-spa-bundle.sh <Resources dir> from scripts/build.sh
#
# The bundle is built by `npm run build:web` at the repo root into
# app/Resources/WebApp (gitignored). A missing or half-built bundle fails the
# build: an app without its pages is never shipped.
#
# APP_SKIP_WEB_BUNDLE=1 skips the copy, for a compile check on a machine that
# has not built the web app. The app then opens on a "bundle_missing" screen.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
src="${APP_WEB_DIR:-$here/Resources/WebApp}"

if [ "${APP_SKIP_WEB_BUNDLE:-0}" = 1 ]; then
  echo "warning: APP_SKIP_WEB_BUNDLE=1, the web bundle is not copied. Do not ship this build."
  exit 0
fi

if [ $# -ge 1 ]; then
  dest_parent="$1"
else
  : "${TARGET_BUILD_DIR:?run from Xcode, or pass the Resources directory of the app}"
  dest_parent="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
fi

if [ ! -f "$src/index.html" ] || [ ! -d "$src/assets" ]; then
  echo "error: The web bundle is missing from $src." >&2
  echo "error: Build it first from the repo root: npm run build:web" >&2
  exit 1
fi
if ! grep -q 'http-equiv="Content-Security-Policy"' "$src/index.html"; then
  echo "error: $src/index.html has no Content-Security-Policy meta tag; rebuild it with npm run build:web." >&2
  exit 1
fi

mkdir -p "$dest_parent"
rm -rf "$dest_parent/WebApp"
cp -R "$src" "$dest_parent/WebApp"
echo "copy-spa-bundle: $(find "$dest_parent/WebApp" -type f | wc -l | tr -d ' ') files into $dest_parent/WebApp"
