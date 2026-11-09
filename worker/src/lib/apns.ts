import type { Bindings } from "../types";

/**
 * Apple Push Notification service, direct: the Worker talks to APNs itself
 * with a token-based provider key, an ES256 JWT signed with the .p8 auth key
 * and reused for 50 minutes (Apple wants a new one between 20 and 60 minutes).
 *
 * Neither the device token nor the key is ever logged. This module does not
 * log at all: it returns an outcome and the caller logs it.
 */

/** The topic is the app's bundle id: the App ID without its Team ID prefix. */
export function apnsTopic(appId: string): string {
  return appId.slice(appId.indexOf(".") + 1);
}

export type ApnsEnvironment = "production" | "development";
export const APNS_HOSTS: Record<ApnsEnvironment, string> = {
  production: "https://api.push.apple.com",
  development: "https://api.sandbox.push.apple.com",
};
/** How long a provider token is reused. */
export const APNS_JWT_TTL_MS = 50 * 60 * 1000;
/** How long Apple keeps trying a device that is offline. */
export const APNS_EXPIRATION_SECONDS = 24 * 60 * 60;
const APNS_TIMEOUT_MS = 10_000;

/** A device token as the Mac sends it: hex, 32 bytes today, up to 100 allowed for. */
const APNS_DEVICE_TOKEN = /^(?:[0-9a-f]{2}){32,100}$/;

export function isApnsDeviceToken(value: unknown): value is string {
  return typeof value === "string" && APNS_DEVICE_TOKEN.test(value);
}

export function isApnsEnvironment(value: unknown): value is ApnsEnvironment {
  return value === "production" || value === "development";
}

export interface ApnsConfig {
  keyP8: string;
  keyId: string;
  teamId: string;
}

/** The provider key, or null when any part of it is unset: Mac push is off. */
export function apnsConfig(env: Bindings): ApnsConfig | null {
  const keyP8 = env.APNS_KEY_P8?.trim();
  const keyId = env.APNS_KEY_ID?.trim();
  const teamId = env.APNS_TEAM_ID?.trim();
  return keyP8 && keyId && teamId ? { keyP8, keyId, teamId } : null;
}

export interface ApnsAlert {
  title: string;
  body: string;
  /** The Dock badge, or null to leave it as it is. */
  badge: number | null;
  /** Groups notifications in Notification Centre. */
  threadId: string;
  /** Where a tap takes the app: a hash route in the SPA, e.g. #/notes. */
  path: string | null;
}

export type ApnsOutcome =
  | { kind: "sent" }
  /** Apple says the token is dead or not ours: delete it. */
  | { kind: "drop"; status: number; reason: string }
  | { kind: "failed"; status: number | null; reason: string };

/** The JSON Apple gets for one alert. */
export function apnsPayload(alert: ApnsAlert): Record<string, unknown> {
  return {
    aps: {
      alert: { title: alert.title, body: alert.body },
      ...(alert.badge === null ? {} : { badge: alert.badge }),
      sound: "default",
      "thread-id": alert.threadId,
    },
    ...(alert.path ? { path: alert.path } : {}),
  };
}

/** Sends one alert to one device. Never throws. */
export async function sendApns(
  config: ApnsConfig,
  topic: string,
  token: string,
  environment: ApnsEnvironment,
  alert: ApnsAlert,
  now = Date.now(),
): Promise<ApnsOutcome> {
  let jwt: string;
  try {
    jwt = await providerToken(config, now);
  } catch {
    // A key that will not import or sign. The message could quote the key, so it stays out.
    return { kind: "failed", status: null, reason: "bad_provider_key" };
  }
  let res: Response;
  try {
    res = await fetch(`${APNS_HOSTS[environment]}/3/device/${token}`, {
      method: "POST",
      headers: {
        authorization: `bearer ${jwt}`,
        "apns-topic": topic,
        "apns-push-type": "alert",
        "apns-priority": "10",
        "apns-expiration": String(Math.floor(now / 1000) + APNS_EXPIRATION_SECONDS),
        "content-type": "application/json",
      },
      body: JSON.stringify(apnsPayload(alert)),
      signal: AbortSignal.timeout(APNS_TIMEOUT_MS),
    });
  } catch {
    return { kind: "failed", status: null, reason: "apns_unreachable" };
  }
  if (res.status === 200) return { kind: "sent" };
  const reason = ((await res.json().catch(() => null)) as { reason?: unknown } | null)?.reason;
  const why = typeof reason === "string" ? reason : `http_${res.status}`;
  if (res.status === 410 || (res.status === 400 && (why === "BadDeviceToken" || why === "DeviceTokenNotForTopic"))) {
    return { kind: "drop", status: res.status, reason: why };
  }
  // Apple refused the JWT: sign a new one next time rather than reuse it for the rest of the hour.
  if (res.status === 403 && (why === "ExpiredProviderToken" || why === "InvalidProviderToken")) jwtCache.delete(cacheKey(config));
  return { kind: "failed", status: res.status, reason: why };
}

// ---- Provider token ------------------------------------------------------------

const jwtCache = new Map<string, { jwt: string; issuedAt: number }>();

const cacheKey = (config: ApnsConfig) => `${config.teamId}:${config.keyId}`;

/** Forgets cached provider tokens, so a test signs afresh. */
export function resetApnsTokenCacheForTests(): void {
  jwtCache.clear();
}

/** The ES256 provider token for `config`, reused until it is APNS_JWT_TTL_MS old. */
export async function providerToken(config: ApnsConfig, now = Date.now()): Promise<string> {
  const key = cacheKey(config);
  const cached = jwtCache.get(key);
  if (cached && now - cached.issuedAt >= 0 && now - cached.issuedAt < APNS_JWT_TTL_MS) return cached.jwt;
  const signingKey = await crypto.subtle.importKey("pkcs8", pemToDer(config.keyP8), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: config.keyId })));
  const claims = base64url(new TextEncoder().encode(JSON.stringify({ iss: config.teamId, iat: Math.floor(now / 1000) })));
  const input = `${header}.${claims}`;
  // WebCrypto's ECDSA signature is r || s, 64 bytes, which is what JWS ES256 wants.
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKey, new TextEncoder().encode(input));
  const jwt = `${input}.${base64url(new Uint8Array(signature))}`;
  jwtCache.set(key, { jwt, issuedAt: now });
  return jwt;
}

/** The DER inside a PKCS#8 PEM. Tolerates a secret pasted with literal \n for newlines. */
function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/\\n/g, "\n")
    .replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return bytes.buffer;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
