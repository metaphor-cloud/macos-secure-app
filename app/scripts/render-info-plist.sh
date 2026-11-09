#!/bin/bash
# Expands the $(VAR) build settings in Info.plist for the command-line build,
# from Config/Shared.xcconfig plus the target's own settings in project.yml.
#   render-info-plist.sh <Info.plist> <Shared.xcconfig> <out>
set -euo pipefail
src="$1"
xcconfig="$2"
dest="$3"

declare -a names=(EXECUTABLE_NAME PRODUCT_NAME PRODUCT_BUNDLE_IDENTIFIER DEVELOPMENT_TEAM MARKETING_VERSION CURRENT_PROJECT_VERSION MACOSX_DEPLOYMENT_TARGET)
declare -a values=("Secure App" "Secure App" "com.example.secureapp" "TEAMID1234" "1.0" "1" "27.0")

# KEY = value lines; $() is xcconfig's way of keeping // from starting a comment.
while IFS= read -r line; do
  case "$line" in ''|//*) continue ;; esac
  key="$(echo "${line%%=*}" | tr -d '[:space:]')"
  value="$(echo "${line#*=}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\$()//g')"
  names+=("$key")
  values+=("$value")
done < "$xcconfig"

expand() {
  local s="$1" i
  for _ in 1 2 3; do
    for i in "${!names[@]}"; do
      s="${s//\$(${names[$i]})/${values[$i]}}"
    done
  done
  printf '%s' "$s"
}

expand "$(cat "$src")" > "$dest"
if grep -q '\$(' "$dest"; then
  echo "render-info-plist: unexpanded settings left in $dest:" >&2
  grep -o '\$([A-Z_]*)' "$dest" >&2
  exit 1
fi
plutil -lint "$dest" >/dev/null
