/**
 * Access tokens from the OIDC provider as the app's credential.
 *
 * The Mac app is a native public client: it signs in with authorisation code
 * + PKCE itself and sends `Authorization: Bearer <access_token>`. The token is
 * accepted only if:
 *
 * 1. It is an RS256 JWT signed by a key in the provider's JWKS, with
 *    `typ: at+jwt` (RFC 9068). The same key may sign ID tokens, so the
 *    signature alone does not make it an access token.
 * 2. `iss` is the configured issuer, `client_id` and `aud` are the app's
 *    client, and it has not expired. A token minted for any other client is
 *    refused.
 * 3. Userinfo, called with the token, passes `checkUserinfo`: a verified
 *    email and membership of ACCESS_GROUP. Userinfo is also the provider
 *    confirming the token is still good, and its answer is cached for at most
 *    a minute, so removing someone from the group takes effect within that
 *    minute.
 *
 * No session is created: the token is the session, and the provider's access
 * and refresh token lifetimes are its idle and absolute limits.
 */

import type { Bindings } from "../types";
import { log, serializeError } from "../log";
import { checkUserinfo, discoverOidc, type Userinfo } from "./oidc";

export interface BearerSession {
  sub: string;
  email: string;
  name: string;
  /** When the token was issued, in milliseconds. */
  issuedAt: number;
}

/** A token is a few hundred bytes; anything far past that is not one of ours. */
const MAX_TOKEN_LENGTH = 8192;

/** Allowance for clock difference on `iat`/`nbf`. None on `exp`: an expired token is expired. */
const CLOCK_SKEW_SECONDS = 60;

/** How long a userinfo answer stands in for asking again. Also KV's minimum TTL. */
const USERINFO_CACHE_SECONDS = 60;

/** How long fetched signing keys are trusted before they are fetched again. */
const JWKS_TTL_MS = 10 * 60 * 1000;

/** An unknown `kid` refetches the keys (rotation), but no more often than this. */
const JWKS_REFETCH_MIN_INTERVAL_MS = 60 * 1000;

const IDP_TIMEOUT_MS = 5000;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

interface JwksCache {
  issuer: string;
  keys: Map<string, CryptoKey>;
  userinfoEndpoint: string;
  fetchedAt: number;
}

let jwksCache: JwksCache | null = null;

/** Tests only: forget the fetched keys, so a test can serve its own. */
export function resetBearerKeysForTests(): void {
  jwksCache = null;
}

/**
 * The token in an `Authorization: Bearer` header, or null when the request
 * does not use that scheme. An empty token comes back as "" so the caller
 * refuses it rather than falling through to the cookie.
 */
export function bearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization");
  if (!header) return null;
  const match = header.match(/^\s*bearer(?:\s+(.*))?$/i);
  if (!match) return null;
  return (match[1] ?? "").trim();
}

function refuse(reason: string, data: Record<string, unknown> = {}, level: "warn" | "error" = "warn"): null {
  log(level, "bearer refused", { reason, ...data });
  return null;
}

function base64urlDecode(part: string): Uint8Array {
  const padded = part.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (part.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJson(part: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(new TextDecoder().decode(base64urlDecode(part)));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchKeys(issuer: string): Promise<JwksCache> {
  const oidc = await discoverOidc(issuer);
  // Discovery is trusted for where the keys live only if it is the configured issuer's own.
  if (oidc.issuer !== issuer) throw new Error(`discovery issuer mismatch: ${oidc.issuer}`);
  const res = await fetch(oidc.jwks_uri, { signal: AbortSignal.timeout(IDP_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys?: unknown };
  const keys = new Map<string, CryptoKey>();
  for (const jwk of Array.isArray(body.keys) ? body.keys : []) {
    const k = jwk as JsonWebKey & { kid?: unknown; use?: unknown };
    if (k.kty !== "RSA" || typeof k.kid !== "string") continue;
    if (k.use !== undefined && k.use !== "sig") continue;
    if (k.alg !== undefined && k.alg !== "RS256") continue;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: k.n, e: k.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    keys.set(k.kid, key);
  }
  return { issuer, keys, userinfoEndpoint: oidc.userinfo_endpoint, fetchedAt: Date.now() };
}

/** The key for `kid`, fetching the keyset when it is stale or does not know it. */
async function signingKey(issuer: string, kid: string): Promise<{ key: CryptoKey | null; userinfoEndpoint: string }> {
  const now = Date.now();
  const cached = jwksCache;
  const stale = !cached || cached.issuer !== issuer || now - cached.fetchedAt > JWKS_TTL_MS;
  const unknownKid = cached && !cached.keys.has(kid) && now - cached.fetchedAt > JWKS_REFETCH_MIN_INTERVAL_MS;
  if (stale || unknownKid) jwksCache = await fetchKeys(issuer);
  return { key: jwksCache!.keys.get(kid) ?? null, userinfoEndpoint: jwksCache!.userinfoEndpoint };
}

/**
 * The person this access token belongs to, or null (logged with a reason) when
 * it is not one the provider issued to the app for a current member of ACCESS_GROUP.
 */
export async function verifyBearer(token: string, env: Bindings): Promise<BearerSession | null> {
  const clientId = env.OIDC_CLIENT_ID;
  const issuer = env.OIDC_ISSUER;
  if (!clientId) return refuse("app_client_unset", {}, "error");
  if (!issuer) return refuse("issuer_unset", {}, "error");
  if (!token) return refuse("token_empty");
  if (token.length > MAX_TOKEN_LENGTH) return refuse("token_too_large", { length: token.length });

  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => BASE64URL.test(p))) return refuse("token_malformed");
  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (!header || !payload) return refuse("token_malformed");

  // Header checks come before any key lookup, so junk never fetches keys.
  if (header.alg !== "RS256") return refuse("alg_not_allowed", { alg: String(header.alg).slice(0, 20) });
  if (header.typ !== "at+jwt") return refuse("not_access_token", { typ: String(header.typ).slice(0, 20) });
  if (header.crit !== undefined) return refuse("crit_header_unsupported");
  if (typeof header.kid !== "string" || !header.kid) return refuse("kid_missing");

  let key: CryptoKey | null;
  let userinfoEndpoint: string;
  try {
    ({ key, userinfoEndpoint } = await signingKey(issuer, header.kid));
  } catch (error) {
    return refuse("jwks_unavailable", { error: serializeError(error) }, "error");
  }
  if (!key) return refuse("kid_unknown", { kid: header.kid.slice(0, 64) });

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlDecode(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) return refuse("bad_signature", { kid: header.kid.slice(0, 64) });

  // Signed by the provider from here on, so the claims are safe to log.
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  const jti = typeof payload.jti === "string" ? payload.jti : undefined;
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer) return refuse("wrong_issuer", { sub, iss: String(payload.iss).slice(0, 100) });
  // client_id names who the token was issued to; aud is the client too unless
  // the grant named an RFC 8707 resource, which the app does not.
  if (payload.client_id !== clientId) {
    return refuse("wrong_client", { sub, clientId: String(payload.client_id).slice(0, 64) });
  }
  const aud = payload.aud;
  if (!(aud === clientId || (Array.isArray(aud) && aud.length === 1 && aud[0] === clientId))) {
    return refuse("wrong_audience", { sub });
  }
  if (typeof payload.exp !== "number" || now >= payload.exp) {
    return refuse("expired", { sub, jti, exp: payload.exp });
  }
  if (typeof payload.iat !== "number" || payload.iat > now + CLOCK_SKEW_SECONDS) {
    return refuse("iat_invalid", { sub, jti });
  }
  if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || payload.nbf > now + CLOCK_SKEW_SECONDS)) {
    return refuse("not_yet_valid", { sub, jti });
  }
  // A DPoP-bound token is only valid with a proof this route does not check,
  // so taking it as a plain bearer would strip the binding.
  if (payload.cnf !== undefined) return refuse("dpop_bound", { sub, jti });
  if (!sub) return refuse("sub_missing", { jti });

  // The access check, from userinfo, cached by the token's hash.
  const cacheKey = `bearer:${await sha256Hex(token)}`;
  const cached = await env.KV.get(cacheKey);
  let identity: { sub: string; email: string; name: string };
  if (cached) {
    identity = JSON.parse(cached) as typeof identity;
  } else {
    let res: Response;
    try {
      res = await fetch(userinfoEndpoint, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(IDP_TIMEOUT_MS),
      });
    } catch (error) {
      return refuse("userinfo_unavailable", { sub, jti, error: serializeError(error) }, "error");
    }
    if (!res.ok) {
      // 401 is the provider saying the token is no good (revoked, say); anything
      // else is the provider failing.
      return refuse("userinfo_failed", { sub, jti, status: res.status }, res.status === 401 ? "warn" : "error");
    }
    const userinfo = (await res.json()) as Userinfo;
    if (userinfo.sub !== sub) return refuse("userinfo_sub_mismatch", { sub, jti });
    const gate = checkUserinfo(userinfo, env);
    if (!gate.ok) return refuse(gate.reason, { ...gate.data, jti }, gate.level);
    identity = gate.identity;
    // Only while the token itself has that long left; KV refuses shorter TTLs.
    if (payload.exp - now >= USERINFO_CACHE_SECONDS) {
      await env.KV.put(cacheKey, JSON.stringify(identity), { expirationTtl: USERINFO_CACHE_SECONDS });
    }
  }

  return { ...identity, issuedAt: payload.iat * 1000 };
}

/** What an ID token says about how its holder signed in:
 *  acr urn:acr:mfa or urn:acr:1fa, amr RFC 8176 values (otp, hwk, swk, user, fed, mfa). */
export interface IdTokenClaims {
  sub: string;
  acr: string | null;
  amr: string[] | null;
  auth_time: number | null;
}

export type IdTokenResult = { ok: true; claims: IdTokenClaims } | { ok: false; reason: string };

/**
 * An ID token issued to the app for `expectedSub`, for its acr and amr at
 * device enrolment. Checked as an ID token, not an access token: `typ: JWT`
 * and no `scope`, which is how the provider tells the two apart, so an access
 * token cannot be passed off as one. `aud` is the app's client, as OIDC Core
 * defines it for ID tokens. Signed by the same JWKS as the access tokens above.
 *
 * Never logs: the caller logs the reason.
 */
export async function verifyIdToken(token: string, env: Bindings, expectedSub: string): Promise<IdTokenResult> {
  const no = (reason: string): IdTokenResult => ({ ok: false, reason });
  const clientId = env.OIDC_CLIENT_ID;
  const issuer = env.OIDC_ISSUER;
  if (!clientId || !issuer) return no("app_client_unset");
  if (!token) return no("id_token_missing");
  if (token.length > MAX_TOKEN_LENGTH) return no("id_token_too_large");
  const parts = token.split(".");
  if (parts.length !== 3 || !parts.every((p) => BASE64URL.test(p))) return no("id_token_malformed");
  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (!header || !payload) return no("id_token_malformed");
  if (header.alg !== "RS256") return no("id_token_alg_not_allowed");
  if (header.typ !== "JWT") return no("id_token_wrong_type");
  if (header.crit !== undefined) return no("id_token_crit_unsupported");
  if (typeof header.kid !== "string" || !header.kid) return no("id_token_kid_missing");

  let key: CryptoKey | null;
  try {
    ({ key } = await signingKey(issuer, header.kid));
  } catch {
    return no("jwks_unavailable");
  }
  if (!key) return no("id_token_kid_unknown");
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlDecode(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) return no("id_token_bad_signature");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer) return no("id_token_wrong_issuer");
  const aud = payload.aud;
  if (!(aud === clientId || (Array.isArray(aud) && aud.length === 1 && aud[0] === clientId))) return no("id_token_wrong_audience");
  if (payload.scope !== undefined) return no("id_token_wrong_type");
  if (typeof payload.exp !== "number" || now >= payload.exp) return no("id_token_expired");
  if (typeof payload.iat !== "number" || payload.iat > now + CLOCK_SKEW_SECONDS) return no("id_token_iat_invalid");
  if (payload.sub !== expectedSub) return no("id_token_sub_mismatch");

  const amr = Array.isArray(payload.amr) && payload.amr.every((v) => typeof v === "string") ? (payload.amr as string[]) : null;
  return {
    ok: true,
    claims: {
      sub: expectedSub,
      acr: typeof payload.acr === "string" ? payload.acr : null,
      amr,
      auth_time: typeof payload.auth_time === "number" ? payload.auth_time : null,
    },
  };
}
