# Starting a new app

For a private business macOS app that only works from an App Attest-enrolled Mac. The names the Mac app, the SPA and the Worker share are in `CONTRACT.md`.

## 1. Rename

```sh
scripts/rename.sh --name "Acme Ops" --module AcmeOps --bundle-id nz.acme.ops \
                  --team XXXXXXXXXX --scheme acmeops
```

It rewrites every identity token in `CONTRACT.md`'s placeholder table, in file contents and in file and directory names. Then it regenerates `shared/vectors/request.json` and the Xcode project. Run it once, on a clean checkout, then read `git diff`.

- `--worker` sets the Worker, D1 database and npm scope. It defaults to the name in kebab-case.
- Run `npm install` afterwards, because the workspace links are renamed.
- Check it with `app/scripts/test.sh`, and `cd app && APP_SKIP_WEB_BUNDLE=1 xcodebuild -project <Module>.xcodeproj -scheme <Module> CODE_SIGNING_ALLOWED=NO build`.

## 2. Apple Developer

1. Create the App ID `<team>.<bundle id>` with App Attest and Push Notifications.
2. Make the macOS provisioning profiles for it: Mac App Development (lists the Mac's Provisioning UDID, not its Hardware UUID) and Mac App Store Connect.
3. Create an APNs key (Keys, Apple Push Notifications service). Apple lets you download the `.p8` once. Note the Key ID.
4. Create the app in App Store Connect.

Things that catch people out:

- A Developer ID build cannot attest. Developer ID profiles carry no App Attest. Ship through TestFlight, or as a Custom App through Apple Business Manager, private to your organisation.
- App Attest on a Mac needs Full Security in Startup Security Utility. In Reduced Security, attestation fails with `invalidKey` and the app shows its "Turn on Full Security" screen.
- Debug builds get development App Attest keys, which only a Worker with `ENVIRONMENT=development` accepts. Release builds get production keys.
- If the first real enrolment is refused with `rp_id_mismatch`, Apple's RP ID for the signing identifier differs from `ATTEST_APP_ID`. Change both to what Apple used.

## 3. Metaphor ID

1. Create a client for the app. Public client, authorisation code with PKCE.
2. Register the redirect URI `<scheme>-mac://auth`.
3. Put the client id in `app/Config/Shared.xcconfig` (`APP_OIDC_CLIENT_ID`) and in the Worker's `OIDC_CLIENT_ID`.
4. Put the people who may use the app in a group. The Worker's `ACCESS_GROUP` is `org:group`, as the `groups` claim writes it.
5. Enrolment needs SSO with MFA (`ATTEST_MFA=required`): an ID token with `acr = urn:acr:mfa` and `mfa` and `fed` in `amr`. The organisation's connection needs the MFA authentication context set, or nobody can enrol. A passkey or emailed code does not count.

## 4. Worker

Set these in `worker/wrangler.jsonc`:

| Var | Value |
|---|---|
| `ATTEST_APP_ID` | `<team>.<bundle id>`, as `rename.sh` wrote it |
| `ATTEST_MFA` | `required`, or exactly `off` |
| `ATTEST_MFA_ACR`, `ATTEST_REQUIRE_EXTENSIONS`, `ATTEST_MIN_BUNDLE_VERSION` | optional, see the comments in the file |
| `OIDC_ISSUER` | `https://metaphor.id` |
| `OIDC_CLIENT_ID` | the client id from step 3 |
| `ACCESS_GROUP` | `org:group` |

Secrets, from `worker/`:

```sh
npx wrangler secret put APNS_KEY_P8     # the whole .p8 file
npx wrangler secret put APNS_KEY_ID
npx wrangler secret put APNS_TEAM_ID
```

Until all three are set, push is off and the Worker logs `apns_not_configured`.

Create the data stores, and put their ids in `wrangler.jsonc`:

```sh
cd worker
npx wrangler d1 create <worker name>
npx wrangler kv namespace create KV
npm run migrate          # remote; npm run migrate:local for wrangler dev
npm run deploy
```

Point `APP_API_BASE` in `app/Config/Shared.xcconfig` at the deployed Worker. `app/scripts/build.sh --sign` refuses to sign while it is still `localhost` or the client id is still `REPLACE_ME`.

## 5. Build and first enrolment

```sh
npm run build:web                                   # the SPA, into app/Resources/WebApp
app/scripts/build.sh                                # SPA, tests, ad-hoc signed app in app/build/
app/scripts/build.sh --xcode                        # the same through xcodebuild
app/scripts/build.sh --sign "<identity>" --profile <file>.provisionprofile
app/scripts/upload-testflight.sh <App_Store_Connect>.provisionprofile
```

The ad-hoc build runs but cannot enrol: App Attest and the Keychain need the real signature, entitlements and profile. Run a signed Debug build from Xcode (automatic signing) against a local `wrangler dev` Worker first.

First enrolment, on a Mac with macOS 27 or later and Full Security:

1. Open the app and sign in with your work account (SSO, not a passkey).
2. Name the Mac and choose **Add this Mac**. The Mac makes a key, Apple confirms it, and the Worker records it against you.
3. The app opens on the SPA, and the Mac appears in the Worker's device list (`GET /api/devices`).

Logs are in Console, subsystem `<bundle id>`. Tokens, assertions, attestations and keys are never logged, and keys show as their first 12 characters.

## 6. Where to add business features

Replace the notes example. Nothing under `/api/` needs gate code.

- **Worker route.** Add a path constant to `shared/src/request.ts`, a handler under `worker/src/handlers/`, and a row in `routes` in `worker/src/routes.ts`. Every route under `/api/` already goes through the gate. Add a D1 migration in `worker/migrations/` if it needs a table. Log through `worker/src/log.ts`, and never log tokens or request bodies.
- **SPA screen.** Add a screen under `web/src/` at a hash route and call the API through the bridge, never `fetch`. The page reports where it is with the `page` message (route, title, badge and nav groups), and the Mac's sidebar and window title follow it.
- **MCP tool (optional).** Add an entry to `app/<Module>Kit/MCP/AppMCPTools.swift`. A read-only tool builds a request and needs no confirmation. A tool that changes data sets `confirmation`, so the person is asked on screen first. Add a case to `app/<Module>KitTests/AppMCPTests.swift`.
- **Push deep links.** The Worker's push `path` is a hash route. The Mac opens that page when the notification is tapped.
- **Bridge or request contract.** Change `shared/src/bridge.ts` or `shared/src/request.ts` and the Swift mirror in the same commit. `ContractDriftTests` fails if they differ. After touching the request, run `npm run generate:vectors`.
