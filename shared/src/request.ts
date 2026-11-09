/**
 * The signed request the Mac app sends and the Worker checks. Both sides
 * import this module (the Swift app mirrors it and checks itself against
 * shared/vectors/request.json), so they cannot disagree about what was signed.
 *
 * Every API request carries an access token and an App Attest assertion over
 * clientDataHash = SHA-256(clientData), where clientData binds the request to:
 *
 *   - the App ID and key id, so neither can be swapped
 *   - the method, the path with its query, and the SHA-256 of the body, so
 *     nothing in the request can change in transit
 *   - the SHA-256 of the bearer token sent alongside, so a stolen assertion
 *     cannot be paired with another token, or a stolen token with another
 *     person's device
 *   - a millisecond timestamp and a random nonce
 *   - the server's current session challenge, which rotates
 */

export const APP_HEADER = {
  /** The App ID the key was attested for: Team ID, a period, and the signing identifier. */
  app: "X-App-Id",
  /** App Attest key id, base64 (SHA-256 of the public key). */
  key: "X-App-Key",
  /** Milliseconds since the epoch. */
  time: "X-App-Time",
  /** 16 to 64 characters of [A-Za-z0-9_-], random per request. */
  nonce: "X-App-Nonce",
  /** The current session challenge, or SESSION_BOOTSTRAP on the session path. */
  challenge: "X-App-Challenge",
  /** Base64 CBOR App Attest assertion. */
  assertion: "X-App-Assertion",
} as const;

export const CLIENT_DATA_VERSION = "secure-app-v1";

/** How far a request's timestamp may sit from the Worker's clock. */
export const REQUEST_MAX_SKEW_MS = 120 * 1000;

/** Enrolment: a challenge, then the attestation over it. Bearer token only, no assertion. */
export const ATTEST_CHALLENGE_PATH = "/api/attest/challenge";
export const ATTEST_REGISTER_PATH = "/api/attest/register";
/** A signed request that returns a fresh session challenge. */
export const ATTEST_SESSION_PATH = "/api/attest/session";

/** Everything under /api/ goes through the gate. */
export const API_PREFIX = "/api";

export const ME_PATH = "/api/me";
export const DEVICES_PATH = "/api/devices";
export const DEVICES_REVOKE_PATH = "/api/devices/revoke";
export const PUSH_TOKEN_PATH = "/api/push/token";
export const PUSH_TEST_PATH = "/api/push/test";
export const LIVE_PATH = "/api/live";
export const NOTES_PATH = "/api/notes";

/**
 * The challenge a key with no current session challenge signs over: after
 * enrolment, after a restart, or after the last one expired. Accepted on
 * ATTEST_SESSION_PATH only.
 */
export const SESSION_BOOTSTRAP = "bootstrap";

export const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

/** A session or enrolment challenge: 32 random bytes, base64url without padding. */
export const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** What a device is called in the device list. */
export const DEVICE_LABEL_MAX = 64;

export interface RequestParts {
  appId: string;
  keyId: string;
  method: string;
  /** Path and query exactly as sent, e.g. /api/notes?q=x. */
  pathAndQuery: string;
  /** Lower-case hex SHA-256 of the body bytes; of the empty string when none. */
  bodySha256: string;
  /** Lower-case hex SHA-256 of the bearer token's UTF-8 bytes, exactly as sent after "Bearer ". */
  tokenSha256: string;
  time: number;
  nonce: string;
  challenge: string;
}

export function clientData(p: RequestParts): string {
  return [
    CLIENT_DATA_VERSION,
    p.appId,
    p.keyId,
    p.method.toUpperCase(),
    p.pathAndQuery,
    p.bodySha256,
    p.tokenSha256,
    String(p.time),
    p.nonce,
    p.challenge,
  ].join("\n");
}

/**
 * A path and query as the Worker will see it in url.pathname + url.search,
 * which is what it hashes into clientData. The URL parser rewrites some
 * targets: a quote in the query becomes %27, an empty "?" goes. Signing the
 * text as written would fail the signature, so the app signs and sends this.
 */
export function canonicalRequestTarget(pathAndQuery: string): string {
  const url = new URL(pathAndQuery, "https://secure-app.invalid");
  return url.pathname + url.search;
}
