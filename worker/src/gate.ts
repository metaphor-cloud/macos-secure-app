/**
 * The App Attest gate in front of every /api/ path. Design and operation:
 * docs/runbook.md.
 *
 * A request is admitted only with both:
 *
 * 1. `Authorization: Bearer <access token>` that verifyBearer accepts (issuer,
 *    app client, expiry, verified email, ACCESS_GROUP);
 * 2. the X-App-* headers carrying an App Attest assertion, over the shared
 *    clientData (@secure-app/shared/request), from an enrolled, unrevoked key
 *    whose sub is the token's sub. The assertion's counter must rise, and is
 *    stored with a conditional UPDATE so two copies racing each other cannot
 *    both pass.
 *
 * It owns /api by prefix, not by a list of routes, so a route added later is
 * covered without anyone remembering. Enrolment and session endpoints
 * (/api/attest/*) are answered here and nowhere else.
 *
 * Always enforced, with no setting to turn it off. A refused request from the
 * app (it carries the signing headers) gets the same 403, whatever the
 * reason, which the app recovers from. The one exception is verification
 * itself failing (D1 down): that is a 503, so the app waits it out instead of
 * giving up a good key. Any other refused request gets the ordinary 404, so
 * nothing outside the app learns the API is here. Each refusal logs a line
 * with a reason code. Handlers get the identity from the gate's result, so no
 * handler, today's or a future one, sees someone it did not check.
 *
 * Fail closed: any error while verifying is a refusal. Assertions are checked
 * offline against the stored key; nothing here calls Apple, so an Apple
 * outage can only hold up enrolment, which needs the device to reach Apple.
 *
 * Never logged: tokens, attestations, assertions, receipts. Key ids are cut to
 * their first 12 characters.
 */
import {
  API_PREFIX,
  APP_HEADER,
  ATTEST_CHALLENGE_PATH,
  ATTEST_REGISTER_PATH,
  ATTEST_SESSION_PATH,
  CHALLENGE_PATTERN,
  DEVICE_LABEL_MAX,
  NONCE_PATTERN,
  REQUEST_MAX_SKEW_MS,
  SESSION_BOOTSTRAP,
  clientData,
} from "@secure-app/shared/request";
import { DEVELOPMENT_CATEGORY, PRODUCTION_CATEGORIES, verifyMacAssertion, verifyMacAttestation, type AttestPolicy } from "./lib/appIntegrity/appAttest";
import { AppAttestError } from "./lib/appIntegrity/appleAppAttest";
import { bytesEqual, fromBase64, sha256, toBase64, toBase64Url, toHex } from "./lib/appIntegrity/bytes";
import { bearerToken, verifyBearer, verifyIdToken, type BearerSession } from "./lib/bearer";
import { isDevEnvironment } from "./lib/environment";
import { overLimit, rateLimitIpKey } from "./lib/rateLimit";
import { attestRoot } from "./lib/trustRoot";
import { log, serializeError } from "./log";
import type { Bindings } from "./types";

// ---- Configuration ----------------------------------------------------------

/** The acr an ID token carries for a multi-factor sign-in. */
export const ACR_MFA = "urn:acr:mfa";
/** The acr for a single-factor sign-in. Never accepted, whatever the config says. */
export const ACR_SINGLE_FACTOR = "urn:acr:1fa";
/** The amr value for more than one factor. */
export const AMR_MFA = "mfa";
/**
 * The amr value for a sign-in through an upstream identity provider, the
 * organisation's SSO. A passkey or emailed code at the provider skips the
 * organisation's own sign-in policy, so enrolment needs this as well as mfa.
 */
export const AMR_FEDERATED = "fed";

/**
 * The acr values enrolment accepts. Unset or empty is urn:acr:mfa alone.
 * Otherwise the comma-separated list, minus urn:acr:1fa, so config can never
 * admit a single-factor sign-in. A list that keeps nothing accepts nothing: a
 * typo fails closed.
 */
export function mfaAcrs(env: Bindings): ReadonlySet<string> {
  const raw = (env.ATTEST_MFA_ACR ?? "").trim();
  if (raw === "") return new Set([ACR_MFA]);
  return new Set(raw.split(",").map((v) => v.trim()).filter((v) => v !== "" && v !== ACR_SINGLE_FACTOR));
}

/** Required unless set to exactly "off": relaxing it has to be on purpose. */
export function mfaRequired(env: Bindings): boolean {
  return (env.ATTEST_MFA ?? "").trim() !== "off";
}

/** The App ID, or null when unset, which refuses every key. */
export function appId(env: Bindings): string | null {
  return (env.ATTEST_APP_ID ?? "").trim() || null;
}

export function attestPolicy(id: string, env: Bindings): AttestPolicy {
  const dev = isDevEnvironment(env);
  return {
    appId: id,
    // A production Worker takes production keys only (the AAGUID).
    allowedEnvironments: dev ? ["production", "development"] : ["production"],
    allowedCategories: dev ? [...PRODUCTION_CATEGORIES, DEVELOPMENT_CATEGORY] : PRODUCTION_CATEGORIES,
    requireExtensions: (env.ATTEST_REQUIRE_EXTENSIONS ?? "").trim() === "true",
    minBundleVersion: (env.ATTEST_MIN_BUNDLE_VERSION ?? "").trim() || null,
  };
}

// ---- Paths ------------------------------------------------------------------

/** Whether the gate owns this path: /api, or anything under it. */
export function isGatedPath(pathname: string): boolean {
  return pathname === API_PREFIX || pathname.startsWith(`${API_PREFIX}/`);
}

// ---- Identity ---------------------------------------------------------------

export interface Identity extends BearerSession {
  keyId: string;
  appId: string;
}

export type GateResult =
  /** Not an /api path: the Worker's own 404. */
  | { kind: "outside" }
  /** The gate answered (enrolment, session challenge or a refusal). */
  | { kind: "response"; response: Response }
  /** Admitted: hand the request to the routes with this identity. */
  | { kind: "admitted"; identity: Identity };

// ---- Responses --------------------------------------------------------------

export const REFUSAL_MESSAGE = "This needs the app on an enrolled device.";

/** The one answer to every refused request from the app, so the reason is never disclosed. */
export function refusal(): Response {
  return Response.json({ error: REFUSAL_MESSAGE }, { status: 403, headers: { "Cache-Control": "no-store" } });
}

/**
 * The answer to the app when verifying broke rather than refused. It says
 * nothing about the request; it keeps the app from treating a Worker fault as
 * a revoked key and setting the device up again.
 */
export function unavailable(): Response {
  return Response.json(
    { error: "Couldn't check this request. Try again in a minute." },
    { status: 503, headers: { "Cache-Control": "no-store", "Retry-After": "30" } },
  );
}

/** What an app's refused request gets. */
function appRefusal(reason: string): Response {
  return reason === "verify_error" ? unavailable() : refusal();
}

/** The Worker's answer to a path it doesn't have, given to anything outside the app. */
export function notFound(): Response {
  return Response.json({ error: "Not found" }, { status: 404 });
}

/** Whether a request carries any of the app's signing headers. */
function fromApp(request: Request): boolean {
  return [APP_HEADER.app, APP_HEADER.key, APP_HEADER.assertion].some((name) => request.headers.has(name));
}

function enrolRefusal(reason: string, data: Record<string, unknown>, status: number, body: Record<string, unknown>): Response {
  log("warn", "enrolment refused", { reason, ...data });
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

// ---- Audit ------------------------------------------------------------------

export async function recordAttestEvent(
  env: Bindings,
  event: string,
  fields: { sub?: string | null; actor?: string | null; keyId?: string | null; reason?: string | null; path?: string | null },
): Promise<void> {
  try {
    await env.DB.prepare("INSERT INTO attest_events (event, sub, actor, key_ref, reason, path) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(event, fields.sub ?? null, fields.actor ?? null, fields.keyId ? fields.keyId.slice(0, 12) : null, fields.reason ?? null, fields.path ?? null)
      .run();
  } catch (error) {
    // The audit row is a record, not a control: losing it must not let a
    // refused request through or refuse a good one. The log line still lands.
    log("error", "attest event not recorded", { event, reason: "audit_write_failed", error: serializeError(error) });
  }
}

// ---- The gate ---------------------------------------------------------------

/**
 * Runs ahead of every route. Answers the enrolment and session endpoints
 * itself; for any other /api path returns the identity it admitted, or a
 * refusal. Paths outside /api are not its business.
 */
export async function gate(request: Request, url: URL, env: Bindings): Promise<GateResult> {
  const path = url.pathname;
  if (!isGatedPath(path)) return { kind: "outside" };
  if (path === ATTEST_CHALLENGE_PATH) return respond(await issueEnrolmentChallenge(request, env));
  if (path === ATTEST_REGISTER_PATH) return respond(await registerKey(request, env));
  if (path === ATTEST_SESSION_PATH) return respond(await issueSessionChallenge(request, url, env));
  // Nothing else lives under the attest prefix.
  if (path === "/api/attest" || path.startsWith("/api/attest/")) {
    log("warn", "request refused", { reason: "attest_path_unknown", path, method: request.method });
    return respond(notFound());
  }

  const outcome = await verifyRequest(request, url, env, { session: false });
  if (outcome.ok) return { kind: "admitted", identity: outcome.identity };
  return respond(refuse(request, path, outcome));
}

function respond(response: Response): GateResult {
  return { kind: "response", response };
}

type Outcome = { ok: true; identity: Identity } | { ok: false; reason: string; data: Record<string, unknown> };

function no(reason: string, data: Record<string, unknown> = {}): Outcome {
  return { ok: false, reason, data };
}

/** Logs why, and answers the app with the one 403 (or the 503) and anyone else with a 404. */
function refuse(request: Request, path: string, outcome: Extract<Outcome, { ok: false }>): Response {
  const app = fromApp(request);
  log("warn", "request refused", { reason: outcome.reason, path, method: request.method, app, ...outcome.data });
  return app ? appRefusal(outcome.reason) : notFound();
}

const KEY_ID_SHAPE = /^[A-Za-z0-9+/=_-]{1,128}$/;
const MAX_ASSERTION_LENGTH = 8192;

interface KeyRow {
  sub: string;
  app_id: string;
  public_key: string;
  counter: number;
  revoked_at: string | null;
  session_challenge: string | null;
  session_challenge_expires_at: number | null;
  previous_session_challenge: string | null;
  previous_session_challenge_expires_at: number | null;
}

function sameString(a: string, b: string): boolean {
  const enc = new TextEncoder();
  return bytesEqual(enc.encode(a), enc.encode(b));
}

/** Whether `challenge` is this key's current or previous session challenge, unexpired. */
function sessionChallengeMatches(row: KeyRow, challenge: string, now: number): boolean {
  const current = row.session_challenge !== null && (row.session_challenge_expires_at ?? 0) > now && sameString(row.session_challenge, challenge);
  const previous =
    row.previous_session_challenge !== null &&
    (row.previous_session_challenge_expires_at ?? 0) > now &&
    sameString(row.previous_session_challenge, challenge);
  return current || previous;
}

/** Verify a signed request end to end. Never throws: an error is a refusal. */
async function verifyRequest(request: Request, url: URL, env: Bindings, opts: { session: boolean }): Promise<Outcome> {
  try {
    return await verifyRequestInner(request, url, env, opts);
  } catch (error) {
    return no("verify_error", { error: serializeError(error) });
  }
}

async function verifyRequestInner(request: Request, url: URL, env: Bindings, opts: { session: boolean }): Promise<Outcome> {
  const h = request.headers;
  const token = bearerToken(request);
  if (!token) return no("bearer_missing");

  const claimedAppId = h.get(APP_HEADER.app) ?? "";
  const keyId = h.get(APP_HEADER.key) ?? "";
  const timeRaw = h.get(APP_HEADER.time) ?? "";
  const nonce = h.get(APP_HEADER.nonce) ?? "";
  const challenge = h.get(APP_HEADER.challenge) ?? "";
  const assertionText = h.get(APP_HEADER.assertion) ?? "";
  if (!claimedAppId && !keyId && !assertionText) return no("attestation_missing");
  if (!KEY_ID_SHAPE.test(keyId)) return no("headers_malformed");
  const keyRef = keyId.slice(0, 12);

  if (claimedAppId !== appId(env)) return no("app_id_not_allowed", { keyRef });
  const time = /^\d{10,16}$/.test(timeRaw) ? Number(timeRaw) : NaN;
  if (!Number.isFinite(time) || !NONCE_PATTERN.test(nonce)) return no("headers_malformed", { keyRef });
  const bootstrap = challenge === SESSION_BOOTSTRAP;
  if (bootstrap ? !opts.session : !CHALLENGE_PATTERN.test(challenge)) return no("challenge_malformed", { keyRef });
  if (!assertionText || assertionText.length > MAX_ASSERTION_LENGTH) return no("headers_malformed", { keyRef });
  const now = Date.now();
  if (Math.abs(now - time) > REQUEST_MAX_SKEW_MS) return no("request_stale", { keyRef, skewMs: now - time });

  const row = await env.DB.prepare(
    `SELECT sub, app_id, public_key, counter, revoked_at, session_challenge, session_challenge_expires_at,
            previous_session_challenge, previous_session_challenge_expires_at
       FROM app_keys WHERE key_id = ?`,
  ).bind(keyId).first<KeyRow>();
  if (!row) return no("key_unknown", { keyRef });
  if (row.revoked_at !== null) return no("key_revoked", { keyRef, sub: row.sub });
  if (row.app_id !== claimedAppId) return no("app_id_mismatch", { keyRef, sub: row.sub });

  const session = await verifyBearer(token, env);
  if (!session) return no("bearer_invalid", { keyRef, sub: row.sub });
  if (session.sub !== row.sub) return no("key_owner_mismatch", { keyRef, sub: session.sub });

  if (!bootstrap && !sessionChallengeMatches(row, challenge, now)) return no("challenge_invalid", { keyRef, sub: row.sub });

  const body = new Uint8Array(await request.clone().arrayBuffer());
  const signed = clientData({
    appId: claimedAppId,
    keyId,
    method: request.method,
    pathAndQuery: url.pathname + url.search,
    bodySha256: toHex(await sha256(body)),
    tokenSha256: toHex(await sha256(token)),
    time,
    nonce,
    challenge,
  });

  let assertion: Uint8Array;
  try {
    assertion = fromBase64(assertionText);
  } catch {
    return no("assertion_malformed", { keyRef, sub: row.sub });
  }
  let counter: number;
  try {
    ({ counter } = await verifyMacAssertion({
      assertion,
      clientData: signed,
      publicKeySpki: fromBase64(row.public_key),
      storedCounter: Number(row.counter),
      policy: attestPolicy(claimedAppId, env),
    }));
  } catch (error) {
    if (error instanceof AppAttestError) return no(error.reason, { keyRef, sub: row.sub, storedCounter: Number(row.counter) });
    throw error;
  }

  // Guarded on the counter still being lower and the key still unrevoked, so
  // two copies of one assertion racing each other advance it once, and a
  // revoke landing between the read and here wins.
  const update = await env.DB.prepare(
    "UPDATE app_keys SET counter = ?1, last_used_at = datetime('now') WHERE key_id = ?2 AND revoked_at IS NULL AND counter < ?1",
  ).bind(counter, keyId).run();
  if (update.meta.changes !== 1) {
    await recordAttestEvent(env, "counter_race", { sub: row.sub, keyId, reason: "counter_not_increasing", path: url.pathname });
    return no("counter_not_increasing", { keyRef, sub: row.sub, counter, race: true });
  }

  return { ok: true, identity: { ...session, keyId, appId: claimedAppId } };
}

// ---- Session challenge ------------------------------------------------------

/** How long a session challenge stays usable. The previous one is kept too, so a rotation never strands a request in flight. */
const SESSION_CHALLENGE_TTL_MS = 10 * 60 * 1000;

function newChallenge(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * GET /api/attest/session: a signed request whose challenge is the current
 * one, the previous one, or "bootstrap". Answers with a fresh challenge for
 * the requests that follow, and keeps the one before it.
 */
async function issueSessionChallenge(request: Request, url: URL, env: Bindings): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed(request, url.pathname);
  const outcome = await verifyRequest(request, url, env, { session: true });
  if (!outcome.ok) return refuse(request, url.pathname, outcome);
  const challenge = newChallenge();
  const expiresAt = Date.now() + SESSION_CHALLENGE_TTL_MS;
  await env.DB.prepare(
    `UPDATE app_keys
        SET previous_session_challenge = session_challenge,
            previous_session_challenge_expires_at = session_challenge_expires_at,
            session_challenge = ?, session_challenge_expires_at = ?
      WHERE key_id = ? AND revoked_at IS NULL`,
  ).bind(challenge, expiresAt, outcome.identity.keyId).run();
  return Response.json({ challenge, expiresAt }, { headers: { "Cache-Control": "no-store" } });
}

function methodNotAllowed(request: Request, path: string): Response {
  log("warn", "request refused", { reason: "method_not_allowed", path, method: request.method });
  return Response.json({ error: "Method not allowed" }, { status: 405 });
}

// ---- Enrolment --------------------------------------------------------------

const ENROL_CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** Enrolment challenges per address per hour, and per person per hour. */
const CHALLENGES_PER_IP_HOUR = 20;
const CHALLENGES_PER_SUB_HOUR = 10;
/** Enrolment attempts per person per day. */
const REGISTRATIONS_PER_SUB_DAY = 5;
const MAX_ATTESTATION_LENGTH = 64 * 1024;

async function bearerSession(request: Request, env: Bindings): Promise<BearerSession | null> {
  const token = bearerToken(request);
  if (!token) return null;
  return verifyBearer(token, env);
}

function reauth(path: string): Response {
  return enrolRefusal("bearer_invalid", { path }, 401, { error: "Sign in again.", reauth: true });
}

/** POST /api/attest/challenge: a bearer token in, a single-use challenge bound to its owner out. */
async function issueEnrolmentChallenge(request: Request, env: Bindings): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(request, ATTEST_CHALLENGE_PATH);
  const session = await bearerSession(request, env);
  if (!session) return reauth(ATTEST_CHALLENGE_PATH);
  if (
    (await overLimit(env, "attest_challenge_ip", rateLimitIpKey(request), CHALLENGES_PER_IP_HOUR, 1)) ||
    (await overLimit(env, "attest_challenge_sub", session.sub, CHALLENGES_PER_SUB_HOUR, 1))
  ) {
    return enrolRefusal("challenge_rate_limited", { sub: session.sub }, 429, { error: "Too many attempts. Try again later." });
  }
  const now = Date.now();
  const challenge = newChallenge();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM attest_challenges WHERE expires_at < ?").bind(now),
    env.DB.prepare("INSERT INTO attest_challenges (challenge, sub, expires_at) VALUES (?, ?, ?)").bind(challenge, session.sub, now + ENROL_CHALLENGE_TTL_MS),
  ]);
  return Response.json({ challenge }, { headers: { "Cache-Control": "no-store" } });
}

/** A device label as shown in the device list: trimmed, no control characters, 1 to 64 characters. */
export function cleanLabel(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  // eslint-disable-next-line no-control-regex
  const label = raw.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return label.length >= 1 && label.length <= DEVICE_LABEL_MAX ? label : null;
}

/**
 * POST /api/attest/register: {challenge, keyId, attestation, appId,
 * deviceLabel, idToken}. Enrols the key for the person the bearer token
 * belongs to, active at once. With MFA required (the default), the ID token
 * from the same sign-in must say acr = urn:acr:mfa (or another value mfaAcrs
 * accepts) and amr includes "mfa" and "fed": multi-factor, through the
 * organisation's SSO. acr and amr both, so a token that disagrees with itself
 * fails.
 */
async function registerKey(request: Request, env: Bindings): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(request, ATTEST_REGISTER_PATH);
  const session = await bearerSession(request, env);
  if (!session) return reauth(ATTEST_REGISTER_PATH);
  const sub = session.sub;
  if (await overLimit(env, "attest_register", sub, REGISTRATIONS_PER_SUB_DAY, 24)) {
    return enrolRefusal("register_rate_limited", { sub }, 429, { error: "Too many attempts. Try again later." });
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    body = parsed as Record<string, unknown>;
  } catch {
    return enrolRefusal("register_body_malformed", { sub }, 400, { error: "Bad request" });
  }
  const { challenge, keyId, attestation, appId: claimedAppId, idToken } = body;
  const deviceLabel = cleanLabel(body.deviceLabel);
  if (
    typeof challenge !== "string" ||
    typeof keyId !== "string" ||
    !KEY_ID_SHAPE.test(keyId) ||
    typeof attestation !== "string" ||
    attestation.length > MAX_ATTESTATION_LENGTH ||
    typeof claimedAppId !== "string" ||
    (idToken !== undefined && typeof idToken !== "string") ||
    !deviceLabel
  ) {
    return enrolRefusal("register_body_malformed", { sub }, 400, { error: "Bad request" });
  }
  const keyRef = keyId.slice(0, 12);
  const refused = async (reason: string, status: number, extra: Record<string, unknown> = {}, detail: Record<string, unknown> = {}) => {
    await recordAttestEvent(env, "enrol_refused", { sub, actor: session.email, keyId, reason, path: ATTEST_REGISTER_PATH });
    return enrolRefusal(reason, { sub, keyRef, ...detail }, status, { error: "This device could not be added.", ...extra });
  };

  // Spent by any attempt, good or bad, so a challenge is never tried twice,
  // and only by the person it was issued to.
  const spent = await env.DB.prepare("DELETE FROM attest_challenges WHERE challenge = ? AND sub = ? RETURNING expires_at")
    .bind(challenge, sub)
    .first<{ expires_at: number }>();
  if (!spent) return refused("challenge_unknown", 403);
  if (spent.expires_at < Date.now()) return refused("challenge_expired", 403);

  // MFA evidence from the ID token. Recorded whenever one verifies; demanded
  // only when ATTEST_MFA is required.
  const required = mfaRequired(env);
  let mfa: { acr: string | null; amr: string[] | null; authTime: number | null } = { acr: null, amr: null, authTime: null };
  if (typeof idToken === "string" && idToken) {
    const checked = await verifyIdToken(idToken, env, sub);
    if (checked.ok) mfa = { acr: checked.claims.acr, amr: checked.claims.amr, authTime: checked.claims.auth_time };
    else if (required) return refused(checked.reason, 403, { sso: "required" });
  }
  if (required) {
    if (!idToken) return refused("id_token_missing", 403, { sso: "required" });
    const amr = mfa.amr ?? [];
    if (!(mfa.acr !== null && mfaAcrs(env).has(mfa.acr) && amr.includes(AMR_MFA))) {
      return refused("mfa_missing", 403, { sso: "required" }, { amr: amr.join(" ") });
    }
    if (!amr.includes(AMR_FEDERATED)) {
      return refused("sso_missing", 403, { sso: "required" }, { amr: amr.join(" ") });
    }
  }

  if (claimedAppId !== appId(env)) return refused("app_id_not_allowed", 403);

  let attestationBytes: Uint8Array;
  try {
    attestationBytes = fromBase64(attestation);
  } catch {
    return refused("attestation_malformed", 400);
  }
  let key;
  try {
    key = await verifyMacAttestation({
      attestation: attestationBytes,
      keyId,
      challenge,
      root: attestRoot(env),
      policy: attestPolicy(claimedAppId, env),
    });
  } catch (error) {
    // A key policy other than Apple's macOS one is a Mac in Reduced
    // Security: the app says to turn on Full Security rather than update.
    if (error instanceof AppAttestError) return refused(error.reason, 403, error.reason === "acl_blob_mismatch" ? { device: "full_security" } : {}, error.detail);
    log("error", "enrolment failed", { reason: "attestation_error", sub, keyRef, error: serializeError(error) });
    return refused("attestation_error", 403);
  }

  const sessionChallenge = newChallenge();
  const sessionExpiresAt = Date.now() + SESSION_CHALLENGE_TTL_MS;
  const inserted = await env.DB.prepare(
    `INSERT INTO app_keys (key_id, sub, email, app_id, device_label, public_key, counter, environment,
                           validation_category, bundle_version, receipt, mfa_required, mfa_acr, mfa_amr, mfa_auth_time,
                           session_challenge, session_challenge_expires_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (key_id) DO NOTHING`,
  ).bind(
    keyId,
    sub,
    session.email,
    claimedAppId,
    deviceLabel,
    toBase64(key.publicKeySpki),
    key.environment,
    key.validationCategory,
    key.bundleVersion,
    key.receipt ? toBase64(key.receipt) : null,
    required ? 1 : 0,
    mfa.acr,
    mfa.amr ? JSON.stringify(mfa.amr) : null,
    mfa.authTime,
    sessionChallenge,
    sessionExpiresAt,
  ).run();
  if (inserted.meta.changes !== 1) return refused("key_already_registered", 409);

  await recordAttestEvent(env, "enrol", { sub, actor: session.email, keyId, path: ATTEST_REGISTER_PATH });
  log("info", "device enrolled", { sub, keyRef, environment: key.environment, validationCategory: key.validationCategory, mfaRequired: required });
  return Response.json(
    { ok: true, environment: key.environment, sessionChallenge, sessionChallengeExpiresAt: sessionExpiresAt },
    { status: 201, headers: { "Cache-Control": "no-store" } },
  );
}
