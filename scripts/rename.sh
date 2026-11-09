#!/bin/bash
# Renames the template to a new app: every identity token in docs/CONTRACT.md's
# placeholder table, in file contents and in file and directory names, across
# the whole repo. Then regenerates the golden vectors (their hashes cover the
# renamed strings) and the Xcode project.
#
#   scripts/rename.sh --name "Acme Ops" --module AcmeOps --bundle-id nz.acme.ops \
#                     --team XXXXXXXXXX --scheme acmeops [--worker acme-ops]
#
#   --name       product name, shown to people          (template: Secure App)
#   --module     Swift module prefix, UpperCamelCase     (SecureApp, SecureAppKit)
#   --bundle-id  bundle id, also the log subsystem and keychain service
#                                                        (com.example.secureapp)
#   --team       Apple Team ID, 10 characters            (TEAMID1234)
#   --scheme     lower-case URL scheme prefix: <scheme>://, <scheme>-native://,
#                <scheme>-mac://                         (secureapp)
#   --worker     Worker name, D1 database, npm scope and the clientData version
#                prefix, kebab-case. Default: --name, lower-cased with hyphens (secure-app)
#
# The bridge handler and receiver names follow --module: secureApp / __secureAppNative
# become acmeOps / __acmeOpsNative.
#
# Run it once, on a clean checkout, before anything else. It is safe to run twice
# with the same arguments (nothing is left to replace). Review the result with git diff.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
self="scripts/rename.sh"

# The template's values (docs/CONTRACT.md). Keep this table and that one the same.
T_NAME="Secure App"
T_MODULE="SecureApp"
T_HANDLER="secureApp"
T_BUNDLE="com.example.secureapp"
T_TEAM="TEAMID1234"
T_SCHEME="secureapp"
T_WORKER="secure-app"

name="" module="" bundle="" team="" scheme="" worker=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) name="${2:?--name needs a value}"; shift ;;
    --module) module="${2:?--module needs a value}"; shift ;;
    --bundle-id) bundle="${2:?--bundle-id needs a value}"; shift ;;
    --team) team="${2:?--team needs a value}"; shift ;;
    --scheme) scheme="${2:?--scheme needs a value}"; shift ;;
    --worker) worker="${2:?--worker needs a value}"; shift ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "rename.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "rename.sh: $1" >&2; exit 2; }
[ -n "$name" ] || die "--name is required"
[ -n "$module" ] || die "--module is required"
[ -n "$bundle" ] || die "--bundle-id is required"
[ -n "$team" ] || die "--team is required"
[ -n "$scheme" ] || die "--scheme is required"

if [ -z "$worker" ]; then
  worker="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | tr -s ' ' '-')"
fi
handler="$(printf '%s' "${module:0:1}" | tr '[:upper:]' '[:lower:]')${module:1}"

[[ "$name" =~ ^[A-Za-z0-9]([A-Za-z0-9\ ]*[A-Za-z0-9])?$ ]] || die "--name takes letters, digits and single spaces"
[[ "$module" =~ ^[A-Z][A-Za-z0-9]*$ ]] || die "--module must be UpperCamelCase letters and digits, like AcmeOps"
[[ "$bundle" =~ ^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+$ ]] || die "--bundle-id must look like nz.acme.ops"
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || die "--team must be the 10 character Apple Team ID"
[[ "$scheme" =~ ^[a-z][a-z0-9]*$ ]] || die "--scheme must be lower-case letters and digits, like acmeops"
[[ "$worker" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ ]] || die "--worker must be kebab-case, like acme-ops"
# The scheme prefixes -native and -mac, and the template's own tokens must not collide with the new ones.
[ "$bundle" != "$T_BUNDLE" ] || die "--bundle-id is still the template's"

# Longest and most specific first, so a token is never half-replaced by a shorter one.
# Each pair is old, then new. The bridge receiver is a case-sensitive token of its own.
OLD=("$T_BUNDLE" "__${T_HANDLER}Native" "$T_MODULE" "$T_HANDLER" "$T_NAME" "$T_WORKER" "$T_SCHEME" "$T_TEAM")
NEW=("$bundle" "__${handler}Native" "$module" "$handler" "$name" "$worker" "$scheme" "$team")

# Names of paths: the same table, minus the ones that cannot appear in a file name.
OLD_PATH=("$T_MODULE" "$T_HANDLER" "$T_NAME" "$T_WORKER" "$T_SCHEME")
NEW_PATH=("$module" "$handler" "$name" "$worker" "$scheme")

prune=(-name .git -o -name node_modules -o -name build -o -name .build -o -name dist -o -name DerivedData -o -name .wrangler)

cd "$root"

echo "==> file contents"
export R_COUNT="${#OLD[@]}"
i=0
for old in "${OLD[@]}"; do
  export "R_OLD_$i=$old" "R_NEW_$i=${NEW[$i]}"
  i=$((i + 1))
done
# Text files that hold any template token. -I skips binaries (the icon PNGs).
pattern_args=()
for old in "${OLD[@]}"; do pattern_args+=(-e "$old"); done
changed=0
while IFS= read -r -d '' file; do
  [ "$file" = "./$self" ] && continue
  perl -pi -e '
    BEGIN { @p = map { [ $ENV{"R_OLD_$_"}, $ENV{"R_NEW_$_"} ] } 0 .. $ENV{R_COUNT} - 1 }
    for my $p (@p) { my ($o, $n) = @$p; s/\Q$o\E/$n/g }
  ' "$file"
  changed=$((changed + 1))
done < <(find . \( "${prune[@]}" \) -prune -o -type f -print0 | xargs -0 grep -IlF --null "${pattern_args[@]}" 2>/dev/null || true)
echo "    $changed files"

echo "==> file and directory names"
renamed=0
# Children before parents (find -depth), so a directory is renamed after what is in it.
while IFS= read -r -d '' path; do
  base="$(basename "$path")"
  new_base="$base"
  i=0
  for old in "${OLD_PATH[@]}"; do
    new_base="${new_base//"$old"/${NEW_PATH[$i]}}"
    i=$((i + 1))
  done
  if [ "$new_base" != "$base" ]; then
    mv "$path" "$(dirname "$path")/$new_base"
    renamed=$((renamed + 1))
  fi
done < <(find . -mindepth 1 -depth -print0 | grep -zvE '(^|/)(\.git|node_modules|build|\.build|dist|DerivedData|\.wrangler)(/|$)' || true)
echo "    $renamed paths"

if [ -f shared/scripts/generate-vectors.ts ]; then
  echo "==> golden vectors"
  # Their hashes cover the strings that just changed. Node 22.18 and later runs TypeScript directly.
  node shared/scripts/generate-vectors.ts
fi

if [ -f app/project.yml ]; then
  echo "==> xcodegen"
  command -v xcodegen >/dev/null || die "xcodegen is not installed (brew install xcodegen), then run: cd app && xcodegen generate"
  (cd app && xcodegen generate --quiet)
fi

echo "==> done: $name ($module, $bundle, team $team, scheme $scheme, worker $worker)"
echo "    Next: set APP_OIDC_CLIENT_ID and APP_API_BASE in app/Config/Shared.xcconfig, then see docs/NEW-APP.md."
