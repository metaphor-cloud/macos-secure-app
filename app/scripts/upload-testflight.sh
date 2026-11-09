#!/bin/bash
# Builds Secure App for Mac signed for App Store Connect and uploads it. The
# build goes to TestFlight, and can ship as a Custom App through Apple Business
# Manager, private to your organisation and never listed publicly.
#
#   app/scripts/upload-testflight.sh path/to/App_Store_Connect.provisionprofile
#
# Needs, on this Mac:
#   - the "3rd Party Mac Developer Application" and "3rd Party Mac Developer
#     Installer" identities for your team, named in APP_MAC_IDENTITY and
#     APP_MAC_INSTALLER_IDENTITY, for example
#     APP_MAC_IDENTITY="3rd Party Mac Developer Application: Acme Ltd (TEAMID1234)"
#   - an App Store Connect API key in ~/.appstoreconnect/private_keys/ (altool
#     finds it there), with its ids in ASC_KEY_ID and ASC_ISSUER_ID
#
# The build number is the UTC time to the minute, so every upload is newer than the last.
set -euo pipefail

profile="${1:?usage: upload-testflight.sh path/to/App_Store_Connect.provisionprofile}"
here="$(cd "$(dirname "$0")/.." && pwd)"
app_identity="${APP_MAC_IDENTITY:?set APP_MAC_IDENTITY to the 3rd Party Mac Developer Application identity}"
installer_identity="${APP_MAC_INSTALLER_IDENTITY:?set APP_MAC_INSTALLER_IDENTITY to the 3rd Party Mac Developer Installer identity}"
key_id="${ASC_KEY_ID:?set ASC_KEY_ID to the App Store Connect API key id}"
issuer_id="${ASC_ISSUER_ID:?set ASC_ISSUER_ID to the App Store Connect issuer id}"
build_number="$(date -u +%Y%m%d%H%M)"

"$here/scripts/build.sh" --sign "$app_identity" --profile "$profile" --build-number "$build_number"

pkg="$here/build/SecureApp-$build_number.pkg"
productbuild --component "$here/build/Secure App.app" /Applications --sign "$installer_identity" "$pkg"
echo "==> packaged $pkg"

xcrun altool --upload-app -f "$pkg" -t macos --apiKey "$key_id" --apiIssuer "$issuer_id"
echo "==> uploaded build $build_number; it appears in TestFlight once Apple has processed it"
