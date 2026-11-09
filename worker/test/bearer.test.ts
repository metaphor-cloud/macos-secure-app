import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import { setupDatabase, cleanDatabase } from "./setup";
import { verifyBearer } from "../src/lib/bearer";
import { ALICE, IdentityStub, ISSUER, APP_CLIENT, appEnv, captureLogs, logged } from "./helpers/attestKit";
import type { Bindings } from "../src/types";

// The access token check: what makes a token the app's credential.

let id: IdentityStub;

beforeAll(async () => {
  await setupDatabase();
  id = await new IdentityStub().init();
});

beforeEach(async () => {
  await cleanDatabase();
  id.install();
});

afterEach(() => vi.restoreAllMocks());

const env = appEnv();
const now = () => Math.floor(Date.now() / 1000);

/** The reason a token is refused, from the log, or null when it was accepted. */
async function refusedFor(token: string, runEnv: Bindings = env): Promise<{ session: unknown; reasons: string[] }> {
  const warn = vi.spyOn(console, "warn");
  const error = vi.spyOn(console, "error");
  const session = await verifyBearer(token, runEnv);
  const reasons = [...logged(warn, "bearer refused"), ...logged(error, "bearer refused")].map((d) => String(d.reason));
  warn.mockRestore();
  error.mockRestore();
  return { session, reasons };
}

describe("verifyBearer", () => {
  it("accepts a token for the app's client from a member of the access group", async () => {
    const token = await id.accessToken(ALICE);
    const { session, reasons } = await refusedFor(token);
    expect(session).toMatchObject({ sub: ALICE.sub, email: ALICE.email });
    expect(reasons).toEqual([]);
  });

  it("refuses a token that is not the app's, with the reason", async () => {
    const cases: [string, () => Promise<string>, string][] = [
      ["another client", () => id.accessToken(ALICE, env, {}, { client_id: "other", aud: "other" }), "wrong_client"],
      ["another audience", () => id.accessToken(ALICE, env, {}, { aud: "other" }), "wrong_audience"],
      ["another issuer", () => id.accessToken(ALICE, env, {}, { iss: "https://evil.example" }), "wrong_issuer"],
      ["an expired token", () => id.accessToken(ALICE, env, {}, { exp: now() - 1 }), "expired"],
      ["a token from the future", () => id.accessToken(ALICE, env, {}, { iat: now() + 3600 }), "iat_invalid"],
      ["a token not valid yet", () => id.accessToken(ALICE, env, {}, { nbf: now() + 3600 }), "not_yet_valid"],
      ["a DPoP-bound token", () => id.accessToken(ALICE, env, {}, { cnf: { jkt: "x" } }), "dpop_bound"],
      ["no subject", () => id.accessToken(ALICE, env, {}, { sub: "" }), "sub_missing"],
      ["an ID token", () => id.idToken(ALICE), "not_access_token"],
      ["a forged signature", async () => (await id.accessToken(ALICE)).replace(/\.[^.]+$/, ".AAAA"), "bad_signature"],
      ["an unknown key id", () => id.sign({ typ: "at+jwt", kid: "other" }, { iss: ISSUER, sub: ALICE.sub, aud: APP_CLIENT, client_id: APP_CLIENT, iat: now(), exp: now() + 60 }), "kid_unknown"],
      ["a token signed with another algorithm", () => id.sign({ typ: "at+jwt", alg: "HS256" }, {}), "alg_not_allowed"],
      ["a critical header", () => id.sign({ typ: "at+jwt", crit: ["x"] }, {}), "crit_header_unsupported"],
      ["junk", async () => "not.a.token!", "token_malformed"],
      ["two parts", async () => "a.b", "token_malformed"],
      ["nothing", async () => "", "token_empty"],
      ["a huge token", async () => "a".repeat(9000), "token_too_large"],
    ];
    for (const [what, make, reason] of cases) {
      const { session, reasons } = await refusedFor(await make());
      expect(session, what).toBeNull();
      expect(reasons, what).toEqual([reason]);
    }
  });

  it("refuses someone the provider says is not allowed in", async () => {
    const cases: [string, Record<string, unknown>, string][] = [
      ["outside the group", { groups: ["org-1:other"] }, "not_in_access_group"],
      ["no groups claim", { groups: undefined }, "groups_claim_missing"],
      ["an unverified email", { email_verified: false }, "email_unverified"],
      ["no email_verified claim", { email_verified: undefined }, "email_verified_missing"],
      ["no email", { email: "" }, "identity_incomplete"],
      ["another subject in userinfo", { sub: "someone-else" }, "userinfo_sub_mismatch"],
    ];
    for (const [what, userinfo, reason] of cases) {
      const { session, reasons } = await refusedFor(await id.accessToken(ALICE, env, userinfo));
      expect(session, what).toBeNull();
      expect(reasons, what).toEqual([reason]);
    }
  });

  it("refuses everyone, loudly, when the access group or the client is not configured", async () => {
    const token = await id.accessToken(ALICE);
    const error = vi.spyOn(console, "error");
    expect(await verifyBearer(token, appEnv({ ACCESS_GROUP: "" }))).toBeNull();
    expect(await verifyBearer(token, appEnv({ OIDC_CLIENT_ID: "" }))).toBeNull();
    expect(await verifyBearer(token, appEnv({ OIDC_ISSUER: "" }))).toBeNull();
    expect(logged(error, "bearer refused").map((d) => d.reason)).toEqual(["access_group_unset", "app_client_unset", "issuer_unset"]);
  });

  it("refuses when the provider cannot be reached, and says so as an error", async () => {
    const token = await id.accessToken(ALICE);
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("network down"));
    const { session, reasons } = await refusedFor(token);
    expect(session).toBeNull();
    expect(reasons).toEqual(["jwks_unavailable"]);
  });

  it("asks userinfo once for a token inside the cache window, and again for another token", async () => {
    const token = await id.accessToken(ALICE);
    expect(await verifyBearer(token, env)).not.toBeNull();
    expect(await verifyBearer(token, env)).not.toBeNull();
    expect(id.userinfoCalls).toBe(1);
    expect(await verifyBearer(await id.accessToken(ALICE), env)).not.toBeNull();
    expect(id.userinfoCalls).toBe(2);
  });

  it("refuses a token userinfo no longer knows (revoked), as a warning", async () => {
    const token = await id.accessToken(ALICE);
    id.install();
    const { session, reasons } = await refusedFor(token);
    expect(session).toBeNull();
    expect(reasons).toEqual(["userinfo_failed"]);
  });

  it("never logs the token", async () => {
    const lines = captureLogs();
    const token = await id.accessToken(ALICE, env, { groups: [] });
    await verifyBearer(token, env);
    await verifyBearer(token.replace(/\.[^.]+$/, ".AAAA"), env);
    expect(lines.join("\n")).toContain("bearer refused");
    expect(lines.join("\n")).not.toContain(token.split(".")[1]);
  });
});
