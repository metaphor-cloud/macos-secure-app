# Runbook: the App Attest gate

Code: `worker/src/gate.ts` (the gate, enrolment, session challenge),
`worker/src/lib/appIntegrity/appAttest.ts` (the verifier), `worker/src/handlers/devices.ts`
(device list and revoke), `shared/src/request.ts` (the signed request contract). Names and paths:
`docs/CONTRACT.md`. The commands below say `secure-app` for the Worker and database; use your app's
names.

## What it does

Every path under `/api/` goes through one gate, before any route. It is always on: there is no
setting to turn it off. A request is admitted only with:

1. `Authorization: Bearer <access token>` for the app's OIDC client, from someone with a verified
   email who is in `ACCESS_GROUP`, and
2. an App Attest assertion, in the `X-App-*` headers, from a key that the same person (`sub`)
   enrolled and nobody has revoked.

Anything else from the app gets the same `403 {"error":"This needs the app on an enrolled device."}`
and a log line with the real reason. Anything without the app's headers gets a plain 404, so nothing
outside the app learns the API is here. There is no cookie session and no browser sign-in. Route
handlers get the identity from the gate's result and never check credentials themselves
(`worker/test/coverage.test.ts` fails if one does).

There is no break-glass, no bypass header, no IP or user allow-list and no read-only path. The
fallback is direct database access (below).

## Configuration

All in `worker/wrangler.jsonc` `vars`, except secrets. Changing any of them is a reviewed deploy.

| Var | Default | Meaning |
|---|---|---|
| `ATTEST_APP_ID` | `TEAMID1234.com.example.secureapp` | Team ID, a period, and the app's signing identifier. Empty refuses every key. The APNs topic is the part after the first period. |
| `ATTEST_MFA` | `required` | `required`, or exactly `off`. Anything else is `required`. See "SSO with MFA". |
| `ATTEST_MFA_ACR` | unset | The `acr` values enrolment accepts, comma-separated. Unset is `urn:acr:mfa` only. `urn:acr:1fa` is always dropped, and a list left empty accepts nobody. |
| `ATTEST_REQUIRE_EXTENSIONS` | unset | `true` refuses keys without Apple's validation category and bundle version extensions. macOS 27.0 sends none, so leave unset while any Mac is on it. |
| `ATTEST_MIN_BUNDLE_VERSION` | unset | Lowest `apple_bundle_version_01` accepted, dotted numbers. |
| `OIDC_ISSUER` | `https://metaphor.id` | The identity provider. Discovery, keys and userinfo come from it. |
| `OIDC_CLIENT_ID` | placeholder | The app's public client (authorisation code + PKCE, no secret, no DPoP, no resource indicator). Empty refuses every token. |
| `ACCESS_GROUP` | placeholder | The `org:group` entry an account's `groups` claim must contain. Empty refuses everyone. |
| `APNS_KEY_P8`, `APNS_KEY_ID`, `APNS_TEAM_ID` | unset | Secrets, set with `wrangler secret put`. Unset turns push off. |

`ENVIRONMENT` is not in `wrangler.jsonc` and must not be. Unset is production. `development` (in
`.dev.vars` for local work) and `test` relax rate limits and also take development App Attest keys
and validation category 3. `worker/test/config.test.ts` fails if `wrangler.jsonc` sets a mode,
a test trust root or an `ENVIRONMENT`.

Fixed in code, not configurable: production takes production AAGUID keys only and validation
categories 2 (TestFlight) and 4 (App Store, which is what a Custom App through Apple Business
Manager signs as). Developer ID carries no App Attest. Change `PRODUCTION_CATEGORIES` in
`appAttest.ts` if you ship another way. A key must carry Apple's macOS access policy (the aclBlob),
which means System Integrity Protection and Full Security are on.

### The test trust root

Tests attest against a CA they generate, passed in with `setAppAttestRootForTests`
(`worker/src/lib/trustRoot.ts`). It is a module variable set from test code only, and it is honoured
only when `ENVIRONMENT` is exactly `test`. Anywhere else Apple's pinned App Attest root is used and
the attempt is logged (`test_root_outside_test`). No request, header or deployed var can set it.

## Reading refusals

Logs are structured objects (`worker/src/log.ts`, `shared/src/logger.ts`): `level`, `message`,
`worker`, `data`. Refusals are `message = "request refused"` with `data.reason`, `data.path`,
`data.method`, `data.keyRef` (the first 12 characters of the key) and `data.sub` when known.
Enrolment refusals are `message = "enrolment refused"`. Tokens, attestations, assertions and receipts
are never logged.

| Reason | Meaning | Fix |
|---|---|---|
| `bearer_missing` | No bearer token: a browser, or a build that doesn't send one | Use the app |
| `attestation_missing` | A bearer token without App Attest headers: a build without signing | Update the app |
| `headers_malformed` | A signing header is missing or the wrong shape | App bug |
| `challenge_malformed` | A challenge that is not 43 base64url characters, or `bootstrap` off the session path | App bug |
| `app_id_not_allowed` | The App ID header is not `ATTEST_APP_ID` | Check the app's identity and the Worker var match |
| `app_id_mismatch` | The key was enrolled for a different App ID | Enrol again |
| `key_unknown` | The key is not enrolled (reinstall, new Mac) | The app enrols again |
| `key_revoked` | Revoked key | Enrol again, if they should have access |
| `key_owner_mismatch` | One person's key with another's token | Investigate |
| `challenge_invalid` | Stale or unknown session challenge | The app asks `/api/attest/session` again |
| `request_stale` | Clock more than 120 s out | Fix the Mac's clock |
| `counter_not_increasing` | Replay, or two requests signed out of order | App bug if frequent; investigate if not |
| `signature_invalid` | Request changed in transit, or a signing bug | Investigate |
| `rp_id_mismatch` | The assertion is for another App ID | Check the signing identifier matches `ATTEST_APP_ID` |
| `assertion_malformed` | The assertion is not base64 CBOR | App bug |
| `validation_category_not_allowed` | A build signed some way the Worker does not take (Developer ID, ad hoc) | Ship as TestFlight or App Store, or change the list |
| `bundle_version_too_old` | Below `ATTEST_MIN_BUNDLE_VERSION` | Update the app |
| `bearer_invalid` | Token expired, revoked, wrong client, or not in the group any more | Sign in again. The `bearer refused` line before it has the reason |
| `verify_error` | The gate itself failed (D1 down, say). Refused, fail closed, answered 503 | Check D1 |
| `attest_path_unknown` | A path under `/api/attest/` that is not an enrolment path | App bug |

`bearer refused` lines (reason in `data.reason`) say why a token failed: `wrong_client`,
`wrong_audience`, `wrong_issuer`, `expired`, `bad_signature`, `kid_unknown`, `not_access_token`,
`dpop_bound`, `userinfo_failed`, `not_in_access_group`, `email_unverified`, and the configuration
faults `app_client_unset`, `issuer_unset`, `access_group_unset` (logged as errors: everyone is locked
out until they are set). `jwks_unavailable` and `userinfo_unavailable` mean the provider could not
be reached.

Enrolment refusals (`data.reason`): `challenge_unknown`, `challenge_expired`, `challenge_rate_limited`,
`register_rate_limited`, `register_body_malformed`, `id_token_*`, `mfa_missing`, `sso_missing`,
`app_id_not_allowed`, `attestation_malformed`, `acl_blob_missing`, `acl_blob_mismatch`,
`extensions_missing`, `chain_invalid`, `chain_expired`, `nonce_mismatch`, `key_id_mismatch`,
`counter_not_zero`, `aaguid_not_allowed`, `key_already_registered`, `attestation_error`.
`acl_blob_mismatch` is a Mac in Reduced Security: the response carries `device: "full_security"` and
the app says to turn on Full Security. The log line carries the blob that was sent.

Enrolments, refused enrolments, revocations and counter races are also rows in `attest_events`:

```sh
npx wrangler d1 execute secure-app --remote --command \
  "SELECT at, event, sub, actor, key_ref, reason FROM attest_events ORDER BY id DESC LIMIT 50"
```

## SSO with MFA at enrolment

With `ATTEST_MFA = required`, `/api/attest/register` needs `idToken`: the ID token from the same
sign-in as the bearer token. It must be a real ID token for the app (`typ: JWT`, no `scope`, `aud`
the app's client, signed by the provider, not expired, same `sub`) with `acr = urn:acr:mfa` **and**
`"mfa"` and `"fed"` in `amr`: multi-factor, through the organisation's SSO. A passkey or emailed code
at the provider skips the organisation's own sign-in policy, so it does not count. Missing, malformed
or disagreeing claims are `mfa_missing`; MFA without SSO is `sso_missing`. Both answer
`403 {sso: "required"}`. For Metaphor ID the values are:

| Sign-in | `amr` | `acr` | Enrols |
|---|---|---|---|
| Emailed code | `otp` | `urn:acr:1fa` | No |
| Federated or SAML (Google, Microsoft, Apple, org SSO) | `fed` | `urn:acr:1fa` | No |
| Org connection with an MFA authentication context | `fed`, `mfa` | `urn:acr:mfa` | Yes |
| Federated, then TOTP or a recovery code | `fed`, `otp`, `mfa` | `urn:acr:mfa` | Yes |
| Passkey, with or without user verification | `hwk` or `swk` (plus `user`, `mfa` with UV) | either | No |
| Emailed code or passkey, then TOTP | first factor plus `otp`, `mfa` | `urn:acr:mfa` | No |
| Session from before the provider recorded `amr` | none | none | No |

The app sends no `acr_values` (it can steer the provider to a passkey). The organisation's SSO
connection needs the MFA authentication context set, or nobody can enrol. If your provider does not
issue `amr` and `acr` like this, set `ATTEST_MFA` to `off` on purpose, or adapt the check in
`registerKey` to what it does issue. Do not leave a half-working check in place.

Each key row records `mfa_required`, `mfa_acr`, `mfa_amr` and `mfa_auth_time`, so keys enrolled while
it was off can be found and re-enrolled:

```sh
npx wrangler d1 execute secure-app --remote --command \
  "SELECT key_id, email, device_label, enrolled_at FROM app_keys WHERE revoked_at IS NULL AND mfa_required = 0"
```

## Enrolling a Mac

You need macOS 27 or later (App Attest on a Mac), Full Security, and an account in `ACCESS_GROUP` that
signs in through the organisation's SSO.

1. Install the app from TestFlight or as a Custom App through Apple Business Manager. A Developer ID
   download can't attest. Open it.
2. Sign in through the organisation's SSO, not a passkey.
3. Name the Mac (it defaults to the Mac's own name) and choose **Add this Mac**. The Mac makes a key,
   Apple confirms it, and the Worker records it against you.
4. The app opens. Your Mac is listed under Devices, marked "This Mac".

What the app might show instead:

| Screen | What to do |
|---|---|
| This Mac can't run the app | Older than macOS 27, or Apple cannot vouch for it (SIP or Full Security off). Use another Mac. |
| Sign in with your work account | Passkey, emailed code, or SSO without MFA. Sign in again through the organisation's SSO. |
| Apple can't confirm this Mac right now | Apple's attestation service is down. Try again later; Macs already added keep working. |
| This Mac isn't set up any more | The key was revoked, or the app was reinstalled. Choose **Add this Mac again**. If it was revoked on purpose, ask why first. |
| This Mac's clock is out | Turn on automatic date and time. Signed requests must be within 2 minutes of the Worker's clock. |
| Too many tries | 5 enrolments a day per person, 10 challenges an hour. Wait. |

## Revoking a device

From an enrolled device: `POST /api/devices/revoke` with `{"keyId": "...", "reason": "..."}`. The
web app's Devices page does it. Anyone in the group may revoke any key. The key is refused on its
next request, its live socket is closed (code 4403), its push token is removed, and the revoke is in
`attest_events`. `GET /api/devices` lists every device (owner, label, environment, enrolled, last
used, revoked).

### Offboarding someone

Do both, in this order, the day they leave:

1. Remove them from the provider's group. Every device they hold stops within a minute (the userinfo
   cache), revoked or not, because the bearer token no longer passes.
2. Revoke each of their keys from the device list, reason "offboarded". This is the record, and it
   stops the keys if they are ever put back in the group by mistake.

Check nothing is left:

```sh
npx wrangler d1 execute secure-app --remote --command \
  "SELECT key_id, device_label, last_used_at FROM app_keys WHERE email = '<their email>' AND revoked_at IS NULL"
```

Their sessions with the provider end on the provider's side; nothing here holds them.

### A lost or stolen Mac

1. Revoke that Mac's key now, from any other enrolled device, reason "lost" or "stolen". It is
   refused on its next request and its live socket closes. No other device of theirs is affected.
2. If they have no other enrolled device, someone else in the group revokes it for them. Failing
   that, use the database (below).
3. If the Mac may be unlocked in someone else's hands, also end their sessions at the provider, so
   its refresh token stops working too.
4. They enrol the replacement as normal: sign in through SSO with MFA and choose **Add this Mac**.

The key never leaves the Mac's Secure Enclave, so a backup or a copied disk cannot sign requests.

### A reinstall, a restore, or a new Mac

App Attest keys don't survive a reinstall, a restore from backup, or migrating to a new Mac. The new
install has no key, or Apple no longer has the one it remembers.

- The app finds out on its own: either Apple refuses the old key, or the Worker refuses it after the
  usual recovery (session, then token). It shows "This Mac isn't set up any more". Sign out, sign in
  again through SSO, and it is added again. The new key is a new row.
- The old key stays in the list, unused. Revoke it, reason "reinstalled", so the list matches what
  people hold. Its "last used" date shows which one is dead.
- A reinstall counts towards the 5 enrolments a day per person.

## Recovering with direct database access

There is deliberately no HTTP back door and no grant script. Losing every device is not a lock-out:
anyone in the group can enrol a new device by signing in through SSO. Direct database access, by
someone with the Cloudflare account, is for when that does not work or a key has to go now.

All commands run by a human with their own wrangler login:

```sh
# Who has which device
npx wrangler d1 execute secure-app --remote --command \
  "SELECT key_id, email, device_label, enrolled_at, last_used_at, revoked_at FROM app_keys ORDER BY enrolled_at DESC"

# Revoke one key now
npx wrangler d1 execute secure-app --remote --command \
  "UPDATE app_keys SET revoked_at = datetime('now'), revoked_by = 'db:<your email>', revoked_reason = '<why>' WHERE key_id = '<key id>'"

# Revoke everything someone holds
npx wrangler d1 execute secure-app --remote --command \
  "UPDATE app_keys SET revoked_at = datetime('now'), revoked_by = 'db:<your email>', revoked_reason = 'offboarded' WHERE sub = '<provider sub>' AND revoked_at IS NULL"

# Undo a mistaken revoke
npx wrangler d1 execute secure-app --remote --command \
  "UPDATE app_keys SET revoked_at = NULL, revoked_by = NULL, revoked_reason = NULL WHERE key_id = '<key id>'"
```

A direct revoke closes no live socket and removes no push token; the gate refuses the key on its next
request, and the socket's next message is the last it gets. To clear a revoked key's push token:
`DELETE FROM push_tokens WHERE key_id = '<key id>'`.

You cannot make a key by hand: a key row needs the Mac's Secure Enclave public key, which only an
attestation gives. If enrolment itself is broken (the provider down, a gate bug), the way back is a
reviewed code change and deploy to the gate itself, and the urgent work is done in the database
meanwhile.

If D1 is lost, restore it with Time Travel (`wrangler d1 time-travel restore secure-app
--timestamp <time>`). If the keys table is gone for good, everyone enrols again; nothing else
depends on it.

## When Apple is down

Assertions are checked on the Worker against the stored key, with no call to Apple. Enrolled Macs
keep working. Only new enrolments wait, because the Mac has to reach Apple to attest. Nothing to do
on the server. If Apple's APNs is down, pushes fail with `push not delivered` warnings and the
live socket and API are unaffected.

## When the Worker's own checks fail

A `503` with `Retry-After: 30` and `reason = verify_error` means the gate could not verify, usually
because D1 is down. The app keeps its key and waits; it never enrols again over a 503. A 5xx from
`/api/attest/challenge` or `/register` is the same. The provider being down shows as `jwks_unavailable`
or `userinfo_unavailable` and refuses requests with the 403 until it is back.

## Push notifications (APNs)

The Worker sends to APNs directly (`worker/src/lib/apns.ts`) with a token-based auth key. Until the
three secrets below are set, push is off: each push that skips a Mac logs `push apns off` with reason
`apns_not_configured`, and nothing else is affected. Lock-screen text should name no one and carry
no business data: a push is a hint to open the app.

What a person has to do, once:

1. **Apple Developer, Keys:** create a key with Apple Push Notifications service (APNs) enabled.
   Download the `.p8` (Apple lets you download it once) and note its Key ID. One key covers both the
   sandbox and production hosts.
2. **Apple Developer, Identifiers:** on the App ID, turn on Push Notifications. Then regenerate the
   macOS development and App Store Connect profiles so they carry `com.apple.developer.aps-environment`,
   and install them (or let Xcode's automatic signing pick them up). The entitlements ask for
   `development` in Debug and `production` in Release. A build whose profile lacks it gets no token.
3. **Worker secrets:**

   ```sh
   cd worker
   npx wrangler secret put APNS_KEY_P8 < AuthKey_XXXXXXXXXX.p8   # the whole PEM, header lines included
   npx wrangler secret put APNS_KEY_ID                           # the 10-character Key ID
   npx wrangler secret put APNS_TEAM_ID                          # your Team ID
   ```

   Delete the downloaded `.p8` from your machine once it is stored somewhere safe. The Worker never
   logs it.
4. **Check delivery:** sign in to the Mac app and allow notifications when asked. Then send a signed
   test from the web inspector of a Debug build (`webView.isInspectable`):

   ```js
   window.webkit.messageHandlers.secureApp.postMessage({ kind: "fetch", method: "POST", path: "/api/push/test" })
   ```

   `200` means Apple accepted it and a banner should show. `503` means the secrets are not all set.
   `409` means this Mac has not registered a token (notifications not allowed, or the profile has no
   push entitlement). `410` means Apple said the token is dead; it was removed, and reopening the app
   registers a new one. `502` means Apple refused it for another reason: the `push not delivered`
   log line has Apple's `reason`.

Notes:

- Debug builds register sandbox tokens and the Worker sends them to `api.sandbox.push.apple.com`;
  Release builds use `api.push.apple.com`. The environment is stored with the token
  (`push_tokens.apns_environment`).
- A token Apple answers with 410, `BadDeviceToken` or `DeviceTokenNotForTopic` is deleted. Sign-out
  deletes this Mac's token; revoking the device's key deletes it too.
- The topic is the bundle id, taken from `ATTEST_APP_ID`.
- The provider JWT is cached for 50 minutes per Worker isolate and re-signed early if Apple says it
  expired.

## For app developers: the contract

`shared/src/request.ts` is the source of truth, and `shared/vectors/request.json` holds golden
vectors the Swift tests check against.

1. Sign in with the provider (the app's client), keeping the access token and the ID token.
2. `POST /api/attest/challenge` with the bearer token: `{challenge}` (32 bytes, base64url, 5 minutes,
   single use, bound to you).
3. `DCAppAttestService.attestKey(keyId, clientDataHash: SHA256(challenge))`.
4. `POST /api/attest/register` with the bearer token and
   `{challenge, keyId, attestation (base64), appId, deviceLabel (1 to 64 chars), idToken}`.
   `201 {ok, environment, sessionChallenge, sessionChallengeExpiresAt}`.
   `403 {sso: "required"}` means sign in again through the organisation's SSO. `403 {device:
   "full_security"}` means the Mac is in Reduced Security. `409` means the key is already enrolled.
   `429` rate limited (10 challenges an hour, 5 registrations a day, per person).
5. Every API request carries the bearer token and `X-App-Id`, `-Key`, `-Time` (ms), `-Nonce` (16 to
   64 of `[A-Za-z0-9_-]`), `-Challenge` (the session challenge), and `-Assertion` (base64) over
   `SHA256(clientData(...))`. One request at a time per key: the counter has to rise.
6. Session challenges last 10 minutes; the previous one keeps working. Refresh with a signed
   `GET /api/attest/session` (its challenge may be `bootstrap`, after a restart).
7. Every refusal is the same 403, by design. On a 403: refresh the session challenge and retry once;
   then refresh the token and retry once; then enrol again (a reinstall loses the key). A `401
   {reauth: true}` from enrolment means sign in again.
8. A `503` with `Retry-After` means the Worker couldn't check the request (its database failed), not
   that the key was refused. Keep the key and show the error; never enrol again over it.
9. Sign and send the path exactly as the Worker will parse it: `url.pathname + url.search` after URL
   normalisation (`canonicalRequestTarget` in the shared module). `encodeURIComponent` leaves `'`
   raw, the URL parser makes it `%27`, and a mismatch fails the signature.

## Adding your own API

Add a handler in `worker/src/handlers/` and a row in `worker/src/routes.ts`. Anything under `/api/`
is already behind the gate; there is nothing to register. Log every refusal, early return and
fallback in the handler with a `reason` code (see `handlers/notes.ts`), use `identity` from the
route context for who is asking, and call `notifyTablesChanged(env, ["table"])` after a write so open
apps refetch. `worker/test/coverage.test.ts` sweeps the route table, so a new route is checked for
the gate without a new test. Replace the example `notes` table and routes when you have your own.
