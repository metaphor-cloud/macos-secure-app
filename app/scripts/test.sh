#!/bin/bash
# Runs the Secure App for Mac unit tests (SecureAppKitTests) on their own, without
# building the web bundle or the app. build.sh runs the same tests as part of a
# build; this is the one CI and a quick local check call.
#
#   app/scripts/test.sh
#
# Needs macOS and Swift 6. ContractDriftTests and GoldenVectorTests read
# ../shared, so run it from a full checkout.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
swift test --scratch-path "$here/build/spm"
