#!/bin/bash
# Builds Secure App for Mac: the web bundle, the unit tests, then the app.
#
#   app/scripts/build.sh                 web bundle, tests, unsigned app (ad-hoc signed) in app/build/
#   app/scripts/build.sh --skip-tests    no unit tests
#   app/scripts/build.sh --skip-spa      reuse the web bundle already built
#   app/scripts/build.sh --sign "Apple Development: ..." --profile path/to.provisionprofile
#                                                   signed with hardened runtime, the App Attest entitlement and
#                                                   the profile made for com.example.secureapp
#   app/scripts/build.sh --xcode         build and test with xcodebuild and the Xcode project instead
#   app/scripts/build.sh --build-number N  CFBundleVersion N (App Store Connect refuses a repeat)
#
# The unsigned app compiles and runs, but App Attest and the Keychain need the
# real signature and profile, so only a signed build can enrol and sign requests.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "$here/.." && pwd)"
out="$here/build"
config=release
skip_spa=0
skip_tests=0
use_xcode=0
identity=""
profile=""
build_number=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-spa) skip_spa=1 ;;
    --skip-tests) skip_tests=1 ;;
    --debug) config=debug ;;
    --xcode) use_xcode=1 ;;
    --sign) identity="$2"; shift ;;
    --profile) profile="$2"; shift ;;
    --build-number) build_number="$2"; shift ;;
    *) echo "build.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$skip_spa" = 0 ]; then
  echo "==> web bundle (npm run build:web)"
  (cd "$repo" && npm run build:web)
fi

if [ "$use_xcode" = 1 ]; then
  echo "==> xcodebuild test and build"
  (cd "$here" && xcodegen generate --quiet)
  args=(-project "$here/SecureApp.xcodeproj" -scheme SecureApp -derivedDataPath "$out/DerivedData")
  [ -z "$identity" ] && args+=(CODE_SIGNING_ALLOWED=NO)
  [ "$skip_tests" = 0 ] && xcodebuild "${args[@]}" test
  xcodebuild "${args[@]}" -configuration "$( [ "$config" = debug ] && echo Debug || echo Release )" build
  exit 0
fi

if [ "$skip_tests" = 0 ]; then
  echo "==> unit tests (swift test)"
  (cd "$here" && swift test --scratch-path "$out/spm")
fi

echo "==> app ($config)"
(cd "$here" && swift build -c "$config" --product SecureApp --scratch-path "$out/spm")
bin="$(cd "$here" && swift build -c "$config" --product SecureApp --scratch-path "$out/spm" --show-bin-path)/SecureApp"

app="$out/Secure App.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/Secure App"
printf 'APPL????' > "$app/Contents/PkgInfo"

# Info.plist: the same file and settings the Xcode project uses (Config/Shared.xcconfig).
"$here/scripts/render-info-plist.sh" "$here/SecureApp/Info.plist" "$here/Config/Shared.xcconfig" "$app/Contents/Info.plist"

# The icon, compiled from the asset catalog.
xcrun actool "$here/SecureApp/Resources/Assets.xcassets" --compile "$app/Contents/Resources" \
  --platform macosx --minimum-deployment-target 27.0 --app-icon AppIcon \
  --output-partial-info-plist "$out/assets-info.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleIconName string AppIcon" "$app/Contents/Info.plist"
if [ -n "$build_number" ]; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $build_number" "$app/Contents/Info.plist"
fi

"$here/scripts/copy-spa-bundle.sh" "$app/Contents/Resources"
# Everything readable by everyone: a checkout made with a tight umask leaves
# files owner-only, and an installed app is owned by root, so App Store
# Connect refuses the package (error 90255).
chmod -R a+rX "$app"

if [ -n "$identity" ]; then
  # A signed build is one that gets used: refuse the template's placeholders.
  if grep -qE 'REPLACE_ME|//localhost' "$app/Contents/Info.plist"; then
    echo "build.sh: Config/Shared.xcconfig still has the placeholder API base or client id (REPLACE_ME, localhost)" >&2
    exit 2
  fi
  [ -n "$profile" ] || { echo "build.sh: --sign needs --profile (the App Attest entitlement requires one)" >&2; exit 2; }
  cp "$profile" "$app/Contents/embedded.provisionprofile"
  # A profile from Downloads carries com.apple.quarantine, which App Store
  # Connect refuses (error 91109). Nothing in a signed app keeps its xattrs.
  xattr -cr "$app"
  entitlements="$out/entitlements.plist"
  src_ent="$here/SecureApp/SecureApp.entitlements"
  [ "$config" = debug ] && src_ent="$here/SecureApp/SecureApp.Debug.entitlements"
  # shellcheck disable=SC2016 # a literal $(AppIdentifierPrefix), as Xcode writes it
  sed 's/\$(AppIdentifierPrefix)/TEAMID1234./' "$src_ent" > "$entitlements"
  codesign --force --options runtime --timestamp --entitlements "$entitlements" --sign "$identity" "$app"
  echo "==> signed with $identity"
else
  # Ad-hoc, no entitlements: launches, but cannot attest or use the Keychain.
  codesign --force --sign - "$app"
  echo "==> ad-hoc signed (not enrolable)"
fi
codesign --verify --strict "$app"
echo "==> $app"
