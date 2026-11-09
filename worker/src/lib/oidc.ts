/**
 * The OIDC provider access comes from. One access check, used for the bearer
 * token on every request (bearer.ts), so there is nowhere for two sign-in
 * paths to drift apart.
 */

import type { Bindings } from "../types";

export interface OidcConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  /** RP-initiated logout (OIDC session management). Not every provider has it. */
  end_session_endpoint?: string;
}

export async function discoverOidc(issuer: string): Promise<OidcConfig> {
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  return res.json() as Promise<OidcConfig>;
}

/** The userinfo response, as untrusted JSON. */
export interface Userinfo {
  sub?: unknown;
  email?: unknown;
  email_verified?: unknown;
  name?: unknown;
  groups?: unknown;
}

export interface Identity {
  sub: string;
  email: string;
  name: string;
}

export type AccessResult =
  | { ok: true; identity: Identity }
  | { ok: false; reason: string; level: "warn" | "error"; data: Record<string, unknown> };

/**
 * Whether this userinfo belongs to someone allowed in: a verified email and
 * membership of ACCESS_GROUP. The groups claim carries `{org_id}:{group_id}`
 * entries, so ACCESS_GROUP is matched exactly: a group id cannot be renamed
 * into this string, and a role entry never equals it.
 */
export function checkUserinfo(userinfo: Userinfo, env: Bindings): AccessResult {
  const sub = typeof userinfo.sub === "string" ? userinfo.sub : "";
  const email = typeof userinfo.email === "string" ? userinfo.email.trim() : "";

  // The email is the actor on every audit row, so it has to be one the
  // provider says the person proved they own.
  if (!sub || !email) {
    return { ok: false, reason: "identity_incomplete", level: "warn", data: { hasSub: !!sub, hasEmail: !!email } };
  }
  if (userinfo.email_verified !== true) {
    return { ok: false, reason: userinfo.email_verified === undefined ? "email_verified_missing" : "email_unverified", level: "warn", data: { sub } };
  }

  const group = (env.ACCESS_GROUP ?? "").trim();
  if (!group) return { ok: false, reason: "access_group_unset", level: "error", data: { sub } };
  const groups = Array.isArray(userinfo.groups) ? userinfo.groups : [];
  if (!groups.includes(group)) {
    return { ok: false, reason: Array.isArray(userinfo.groups) ? "not_in_access_group" : "groups_claim_missing", level: "warn", data: { sub } };
  }

  return { ok: true, identity: { sub, email, name: typeof userinfo.name === "string" ? userinfo.name : "" } };
}
