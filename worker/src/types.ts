import type { LiveHub } from "./lib/hub";

/** The Worker's bindings: wrangler.jsonc vars and secrets (docs/CONTRACT.md). */
export interface Bindings {
  DB: D1Database;
  /** Userinfo cache and rate limits. */
  KV: KVNamespace;
  LIVE_HUB: DurableObjectNamespace<LiveHub>;

  /** Unset or any other value is production. "development" and "test" relax rate limits and take development keys. Never put it in wrangler.jsonc. */
  ENVIRONMENT?: string;

  /** Team ID, a period, and the signing identifier. Empty refuses every key. */
  ATTEST_APP_ID?: string;
  /** "off" turns the MFA and SSO check off at enrolment; anything else is "required". */
  ATTEST_MFA?: string;
  /** Comma-separated acr values enrolment accepts. Unset is urn:acr:mfa. */
  ATTEST_MFA_ACR?: string;
  /** "true" refuses keys without Apple's validation category and bundle version. */
  ATTEST_REQUIRE_EXTENSIONS?: string;
  /** Lowest apple_bundle_version_01 accepted, dotted numbers. */
  ATTEST_MIN_BUNDLE_VERSION?: string;

  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  /** The org:group an account must be in, as the groups claim writes it. */
  ACCESS_GROUP?: string;

  APNS_KEY_P8?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
}
