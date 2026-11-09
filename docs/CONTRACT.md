# Contract

The names and shapes the Mac app, the bundled SPA and the Worker share. `shared/src/request.ts` and
`shared/src/bridge.ts` are the source of truth; the Swift side mirrors them and
`app/SecureAppKitTests` checks itself against `shared/vectors/*.json`. Change both sides together.

## Identity placeholders

`scripts/rename.sh` rewrites these for a new app.

| Token | Template value |
|---|---|
| Product name | `Secure App` |
| Swift app / kit modules | `SecureApp` / `SecureAppKit` |
| Bundle id | `com.example.secureapp` |
| Apple Team ID | `TEAMID1234` |
| App ID (Worker `ATTEST_APP_ID`) | `TEAMID1234.com.example.secureapp` |
| Bundled SPA scheme | `secureapp://app/` |
| Native fetch scheme | `secureapp-native:///api/...` |
| OIDC redirect | `secureapp-mac://auth` |
| Bridge handler / receiver | `secureApp` / `__secureAppNative` |
| Log subsystem | `com.example.secureapp` |
| Worker name / D1 database | `secure-app` / `secure-app` |

## Signed request

Headers on every gated request, plus `Authorization: Bearer <access token>`:

| Header | Value |
|---|---|
| `X-App-Id` | App ID: Team ID, a period, the signing identifier |
| `X-App-Key` | App Attest key id, base64 |
| `X-App-Time` | ms since epoch, within 120 s of the Worker |
| `X-App-Nonce` | 16 to 64 of `[A-Za-z0-9_-]` |
| `X-App-Challenge` | current session challenge, or `bootstrap` on the session path |
| `X-App-Assertion` | base64 CBOR assertion over `SHA256(clientData)` |

`clientData` is these lines joined with `\n`: `secure-app-v1`, appId, keyId, METHOD, canonical path
and query, hex SHA-256 of body, hex SHA-256 of bearer token, time, nonce, challenge.

## Paths

| Path | Auth | Purpose |
|---|---|---|
| `POST /api/attest/challenge` | bearer | enrolment challenge |
| `POST /api/attest/register` | bearer + idToken | enrol a key, returns first session challenge |
| `GET /api/attest/session` | signed | fresh session challenge |
| `GET /api/me` | signed | who is signed in |
| `GET /api/devices`, `POST /api/devices/revoke` | signed | device list and revoke |
| `POST /api/push/token`, `DELETE /api/push/token`, `POST /api/push/test` | signed | APNs |
| `GET /api/live` | signed, WebSocket upgrade | live events (Durable Object hub) |
| `GET/POST /api/notes`, `GET /api/notes/:id/export` | signed | example business endpoints |

Everything under `/api/` goes through the gate. Refusals are one `403 {"error":"This needs the app on an enrolled device."}`; requests without the app headers get a plain 404.

## Worker configuration

`ATTEST_APP_ID`, `ATTEST_MFA` (`required` | `off`), `ATTEST_MFA_ACR`, `ATTEST_REQUIRE_EXTENSIONS`,
`ATTEST_MIN_BUNDLE_VERSION`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `ACCESS_GROUP` (the `org:group` an
account must be in), secrets `APNS_KEY_P8`, `APNS_KEY_ID`, `APNS_TEAM_ID`.

## Server details the app depends on

Added by the Worker build. The app mirrors these.

- `ENVIRONMENT` (Worker var, outside `wrangler.jsonc`): unset is production; `development` and `test`
  also take development App Attest keys and validation category 3. A development build only enrols
  against a Worker with `ENVIRONMENT=development`.
- Bindings: D1 `DB`, KV `KV` (userinfo cache, rate limits), Durable Object `LIVE_HUB`.
- `ATTEST_MFA_ACR` is a comma-separated list; unset is `urn:acr:mfa`. `urn:acr:1fa` is never accepted.
- Enrolment needs `amr` to include both `mfa` and `fed` when `ATTEST_MFA` is `required`.
- `GET /api/attest/session` only (no POST). `/api/attest/*` has no other paths.
- `POST /api/attest/register` replies `201 {ok, environment, sessionChallenge, sessionChallengeExpiresAt}`.
  There is no `platform` field: the Worker takes macOS keys only (Apple's macOS aclBlob is required).
  Refusals are `403 {error, sso: "required"}` (sign in through SSO with MFA), `403 {error, device:
  "full_security"}` (Reduced Security), `401 {error, reauth: true}`, `409`, `429`.
- `GET /api/attest/session` replies `{challenge, expiresAt}`. `POST /api/attest/challenge` replies `{challenge}`.
- `GET /api/me` replies `{sub, email, name, keyId}`.
- `GET /api/devices` replies `{keys: [{keyId, sub, email, appId, deviceLabel, environment,
  validationCategory, bundleVersion, mfaRequired, mfaAcr, enrolledAt, lastUsedAt, active, revokedAt,
  revokedBy, revokedReason}]}`. `POST /api/devices/revoke` takes `{keyId, reason}`.
- `POST /api/push/token` takes `{token, environment}`: the hex APNs device token and `production` or
  `development`. `DELETE /api/push/token` removes it. The APNs topic is the bundle id, the `ATTEST_APP_ID`
  part after the first period. The alert payload carries `path` (a hash route, e.g. `#/notes`) when
  there is one, and no badge.
- `GET /api/live` (WebSocket upgrade, signed like any request) sends `{"type":"changed","tables":[...]}`
  and answers any client message with `{"type":"pong"}`. Revoking the key closes the socket with code 4403.
- `GET /api/notes/:id/export` answers `text/markdown; charset=utf-8` with
  `Content-Disposition: attachment; filename="note-<id>.md"`.
- Bridge (`shared/src/bridge.ts`): the `page` message carries `badge` (not `unread`) and `nav` as
  `NavGroup[]` (`{title, items: [{title, path}]}`). `isBridgedApiPath(path)` is the page's path rule:
  `/api/` paths only, never `/api/attest/*` or `/api/live`, no `..`, `//`, `%2e` or `%2f`. Native
  code does the enrolment, session and live-socket calls itself.
- Golden vectors: `shared/vectors/request.json` holds `sha256`, `clientData` and
  `canonicalRequestTarget` cases. Regenerate with `npm run generate:vectors`.
