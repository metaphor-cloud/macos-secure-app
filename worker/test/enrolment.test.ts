import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { ATTEST_CHALLENGE_PATH } from "@secure-app/shared/request";
import { setupDatabase, cleanDatabase } from "./setup";
import { setAppAttestRootForTests } from "../src/lib/trustRoot";
import { mfaAcrs } from "../src/gate";
import { attest, makeTestCa, type TestCa } from "./helpers/appAttestFixture";
import {
  ACR_1FA,
  ACR_MFA,
  ALICE,
  APP_ID,
  BOB,
  MACOS_ACL_BLOB,
  IdentityStub,
  ORIGIN,
  appEnv,
  appleExtensions,
  bearer,
  call,
  enrol,
  enrolmentChallenge,
  logged,
  register,
} from "./helpers/attestKit";
import type { Bindings } from "../src/types";

// Enrolling a Mac: an access token, a single-use challenge bound to that
// person, an App Attest attestation over it, and (by default) an MFA ID token
// from the same sign-in through the organisation's SSO.

let ca: TestCa;
let id: IdentityStub;

beforeAll(async () => {
  await setupDatabase();
  ca = await makeTestCa();
  id = await new IdentityStub().init();
});

beforeEach(async () => {
  await cleanDatabase();
  setAppAttestRootForTests(ca.root.der);
  id.install();
});

afterEach(() => vi.restoreAllMocks());
afterAll(() => setAppAttestRootForTests(null));

const env = appEnv();

async function keyRow(keyId: string) {
  return env.DB.prepare("SELECT * FROM app_keys WHERE key_id = ?").bind(keyId).first<Record<string, unknown>>();
}

async function events() {
  return (await env.DB.prepare("SELECT event, sub, reason, key_ref FROM attest_events ORDER BY id").all<Record<string, unknown>>()).results;
}

const MAC = { aclBlob: MACOS_ACL_BLOB, extensions: appleExtensions(4) };

async function attempt(opts: { idToken?: string | null; appId?: string; label?: unknown; attestOpts?: Parameters<typeof attest>[2]; env?: Bindings } = {}) {
  const runEnv = opts.env ?? env;
  const token = await id.accessToken(ALICE, runEnv);
  const challenge = await enrolmentChallenge(token, runEnv);
  const appId = opts.appId ?? APP_ID;
  const device = await attest(ca, challenge, { appId, ...MAC, ...opts.attestOpts });
  const idToken = opts.idToken === undefined ? await id.idToken(ALICE) : opts.idToken;
  const res = await register(
    token,
    {
      challenge,
      keyId: device.keyId,
      attestation: device.attestation,
      appId,
      deviceLabel: opts.label ?? "Alice's Mac",
      ...(idToken === null ? {} : { idToken }),
    },
    runEnv,
  );
  return { res, device, token, challenge };
}

describe("enrolment challenge", () => {
  it("needs a bearer token from someone in the access group", async () => {
    const none = await call(new Request(`${ORIGIN}${ATTEST_CHALLENGE_PATH}`, { method: "POST" }));
    expect(none.status).toBe(401);
    expect(await none.json()).toMatchObject({ reauth: true });
    const outsider = await id.accessToken(ALICE, env, { groups: [] });
    expect((await call(new Request(`${ORIGIN}${ATTEST_CHALLENGE_PATH}`, { method: "POST", headers: bearer(outsider) }))).status).toBe(401);
    expect((await call(new Request(`${ORIGIN}${ATTEST_CHALLENGE_PATH}`, { method: "GET", headers: bearer(outsider) }))).status).toBe(405);
  });

  it("is 32 random bytes, stored against the person who asked, for five minutes", async () => {
    const before = Date.now();
    const challenge = await enrolmentChallenge(await id.accessToken(ALICE));
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const row = await env.DB.prepare("SELECT sub, expires_at FROM attest_challenges WHERE challenge = ?").bind(challenge).first<{ sub: string; expires_at: number }>();
    expect(row!.sub).toBe(ALICE.sub);
    expect(row!.expires_at - before).toBeGreaterThanOrEqual(5 * 60 * 1000 - 50);
    expect(row!.expires_at - before).toBeLessThanOrEqual(5 * 60 * 1000 + 5000);
  });

  it("is rate limited per person outside development, and says why in the log", async () => {
    const prod = appEnv({ ENVIRONMENT: "production" });
    const token = await id.accessToken(BOB, prod);
    const ask = () => call(new Request(`${ORIGIN}${ATTEST_CHALLENGE_PATH}`, { method: "POST", headers: { ...bearer(token), "CF-Connecting-IP": "203.0.113.9" } }), prod);
    for (let i = 0; i < 10; i++) expect((await ask()).status).toBe(200);
    const warn = vi.spyOn(console, "warn");
    expect((await ask()).status).toBe(429);
    expect(logged(warn, "enrolment refused")).toEqual([expect.objectContaining({ reason: "challenge_rate_limited", sub: BOB.sub })]);
  });
});

describe("registration", () => {
  it("enrols an active key bound to the person's sub, with the MFA evidence", async () => {
    const { res, device } = await attempt();
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, environment: "production" });
    expect(body.sessionChallenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(body.sessionChallengeExpiresAt).toBeGreaterThan(Date.now());
    expect(await keyRow(device.keyId)).toMatchObject({
      sub: ALICE.sub,
      email: ALICE.email,
      app_id: APP_ID,
      device_label: "Alice's Mac",
      counter: 0,
      environment: "production",
      validation_category: 4,
      bundle_version: "1.0",
      mfa_required: 1,
      mfa_acr: ACR_MFA,
      mfa_amr: JSON.stringify(["fed", "mfa"]),
      revoked_at: null,
      session_challenge: body.sessionChallenge,
    });
    expect(await events()).toEqual([expect.objectContaining({ event: "enrol", sub: ALICE.sub, key_ref: device.keyId.slice(0, 12) })]);
  });

  it("lets one person hold several Macs", async () => {
    await enrol(ca, id, ALICE);
    await enrol(ca, id, ALICE, { label: "Alice's other Mac" });
    const rows = await env.DB.prepare("SELECT device_label FROM app_keys WHERE sub = ? ORDER BY device_label").bind(ALICE.sub).all<{ device_label: string }>();
    expect(rows.results.map((r) => r.device_label)).toEqual(["Alice's other Mac", "Test Mac"]);
  });

  it("spends the challenge on any attempt, so it cannot be used twice", async () => {
    const { token, challenge } = await attempt();
    const again = await attest(ca, challenge, { appId: APP_ID, ...MAC });
    const res = await register(token, { challenge, keyId: again.keyId, attestation: again.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(ALICE) });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ event: "enrol_refused", reason: "challenge_unknown" });
  });

  it("refuses a challenge issued to someone else", async () => {
    const bobChallenge = await enrolmentChallenge(await id.accessToken(BOB));
    const token = await id.accessToken(ALICE);
    const device = await attest(ca, bobChallenge, { appId: APP_ID, ...MAC });
    const res = await register(token, { challenge: bobChallenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(ALICE) });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "challenge_unknown", sub: ALICE.sub });
  });

  it("refuses an expired challenge", async () => {
    const token = await id.accessToken(ALICE);
    const challenge = await enrolmentChallenge(token);
    await env.DB.prepare("UPDATE attest_challenges SET expires_at = ? WHERE challenge = ?").bind(Date.now() - 1, challenge).run();
    const device = await attest(ca, challenge, { appId: APP_ID, ...MAC });
    const res = await register(token, { challenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(ALICE) });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "challenge_expired" });
  });

  it("never lets a key belong to two people", async () => {
    const device = await enrol(ca, id, ALICE);
    const bob = await id.accessToken(BOB);
    const challenge = await enrolmentChallenge(bob);
    // The same attestation cannot be re-presented (the nonce covers the
    // challenge), so this is the strongest replay: Alice's key, a fresh
    // challenge, Bob's token. It fails before it can be stored.
    const res = await register(bob, { challenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(BOB) });
    expect(res.status).toBe(403);
    expect((await keyRow(device.keyId))!.sub).toBe(ALICE.sub);
  });

  it("refuses a key id that is already enrolled, to the owner or to anyone else", async () => {
    const device = await enrol(ca, id, ALICE);
    for (const person of [ALICE, BOB]) {
      const token = await id.accessToken(person);
      const challenge = await enrolmentChallenge(token);
      const again = await attest(ca, challenge, { appId: APP_ID, ...MAC, keys: device.keys });
      expect(again.keyId).toBe(device.keyId);
      const res = await register(token, { challenge, keyId: again.keyId, attestation: again.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(person) });
      expect(res.status).toBe(409);
      expect((await events()).at(-1)).toMatchObject({ event: "enrol_refused", reason: "key_already_registered" });
    }
    expect((await keyRow(device.keyId))!.sub).toBe(ALICE.sub);
  });

  it("refuses without a bearer token, or for someone outside the access group", async () => {
    expect((await register("", { challenge: "x" })).status).toBe(401);
    const outsider = await id.accessToken(ALICE, env, { groups: ["other:group"] });
    expect((await register(outsider, { challenge: "x" })).status).toBe(401);
  });

  it("refuses a malformed body", async () => {
    const token = await id.accessToken(ALICE);
    const res = await call(new Request(`${ORIGIN}/api/attest/register`, { method: "POST", headers: { ...bearer(token), "Content-Type": "application/json" }, body: "[]" }), env);
    expect(res.status).toBe(400);
    expect((await register(token, { challenge: "c" })).status).toBe(400);
  });

  it("refuses an App ID that is not configured, and every key while none is set", async () => {
    const { res } = await attempt({ appId: "TEAMID1234.com.example.other" });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "app_id_not_allowed" });

    const unset = appEnv({ ATTEST_APP_ID: "" });
    const token = await id.accessToken(ALICE, unset);
    const challenge = await enrolmentChallenge(token, unset);
    const device = await attest(ca, challenge, { appId: APP_ID, ...MAC });
    const none = await register(token, { challenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(ALICE) }, unset);
    expect(none.status).toBe(403);
  });

  it("refuses a key that is not a Mac's, or is a Mac without Full Security", async () => {
    const notMac = await attempt({ attestOpts: { aclBlob: undefined } });
    expect(notMac.res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "acl_blob_missing" });

    const altered = MACOS_ACL_BLOB.slice();
    altered[0] ^= 1;
    const { res } = await attempt({ attestOpts: { aclBlob: altered } });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ device: "full_security" });
    expect((await events()).at(-1)).toMatchObject({ reason: "acl_blob_mismatch" });
  });

  it("enrols a Mac attestation without the extensions, as macOS 27.0 sends", async () => {
    const { res, device } = await attempt({ attestOpts: { extensions: undefined } });
    expect(res.status).toBe(201);
    expect(await keyRow(device.keyId)).toMatchObject({ validation_category: null, bundle_version: null });
  });

  it("refuses a key without the extensions when ATTEST_REQUIRE_EXTENSIONS is true", async () => {
    const strict = appEnv({ ATTEST_REQUIRE_EXTENSIONS: "true" });
    const { res } = await attempt({ env: strict, attestOpts: { extensions: undefined } });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "extensions_missing" });
  });

  it("refuses a build older than ATTEST_MIN_BUNDLE_VERSION", async () => {
    const strict = appEnv({ ATTEST_MIN_BUNDLE_VERSION: "2.0" });
    const old = await attempt({ env: strict, attestOpts: { extensions: appleExtensions(4, "1.9") } });
    expect(old.res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "bundle_version_too_old" });
    expect((await attempt({ env: strict, attestOpts: { extensions: appleExtensions(4, "2.0") } })).res.status).toBe(201);
  });

  it("refuses a development key on a production Worker, and ignores the test root there", async () => {
    const prod = appEnv({ ENVIRONMENT: "production" });
    // Production also ignores the test root, so the chain fails first; the
    // AAGUID rule itself is covered in the verifier suite.
    const token = await id.accessToken(ALICE, prod);
    const challenge = await enrolmentChallenge(token, prod);
    const device = await attest(ca, challenge, { appId: APP_ID, ...MAC });
    const error = vi.spyOn(console, "error");
    const res = await register(token, { challenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x", idToken: await id.idToken(ALICE) }, prod);
    expect(res.status).toBe(403);
    expect(logged(error, "app attest test root ignored")).toEqual([expect.objectContaining({ reason: "test_root_outside_test" })]);
  });

  it("refuses a missing or unusable device label", async () => {
    for (const label of ["", "   ", "x".repeat(65), 42]) {
      const { res } = await attempt({ label });
      expect(res.status).toBe(400);
    }
  });

  it("strips control characters from the device label", async () => {
    const { res, device } = await attempt({ label: "  Bob's work Mac\u0007 " });
    expect(res.status).toBe(201);
    expect((await keyRow(device.keyId))!.device_label).toBe("Bob's work Mac");
  });

  it("is rate limited per person outside development", async () => {
    const prod = appEnv({ ENVIRONMENT: "production" });
    const token = await id.accessToken(BOB, prod);
    const body = { challenge: "nope", keyId: "a", attestation: "", appId: APP_ID, deviceLabel: "x" };
    for (let i = 0; i < 5; i++) expect((await register(token, body, prod)).status).toBe(403);
    expect((await register(token, body, prod)).status).toBe(429);
  });
});

describe("SSO with MFA at enrolment", () => {
  it("is required by default: no ID token, no device", async () => {
    const warn = vi.spyOn(console, "warn");
    const { res, device } = await attempt({ idToken: null });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ sso: "required" });
    expect(await keyRow(device.keyId)).toBeNull();
    expect(logged(warn, "enrolment refused")).toEqual([expect.objectContaining({ reason: "id_token_missing" })]);
  });

  it.each([
    ["org SSO with the MFA context", ["fed", "mfa"]],
    ["a federated sign-in then TOTP", ["fed", "otp", "mfa"]],
  ])("enrols after %s (acr urn:acr:mfa), and records what the token said", async (_, amr) => {
    const { res, device } = await attempt({ idToken: await id.idToken(ALICE, { acr: ACR_MFA, amr }) });
    expect(res.status).toBe(201);
    expect(await keyRow(device.keyId)).toMatchObject({ mfa_required: 1, mfa_acr: "urn:acr:mfa", mfa_amr: JSON.stringify(amr) });
  });

  // MFA at the provider without the organisation's SSO skips the org's sign-in policy.
  it.each([
    ["a device-bound passkey with user verification", ["hwk", "user", "mfa"]],
    ["a synced passkey with user verification", ["swk", "user", "mfa"]],
    ["an emailed code then TOTP", ["otp", "mfa"]],
    ["a passkey without user verification then TOTP", ["hwk", "otp", "mfa"]],
  ])("refuses a multi-factor sign-in that skipped the org's SSO: %s", async (_, amr) => {
    const warn = vi.spyOn(console, "warn");
    const { res, device } = await attempt({ idToken: await id.idToken(ALICE, { acr: ACR_MFA, amr }) });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ sso: "required" });
    expect(await keyRow(device.keyId)).toBeNull();
    expect((await events()).at(-1)).toMatchObject({ reason: "sso_missing" });
    expect(logged(warn, "enrolment refused")).toEqual([expect.objectContaining({ reason: "sso_missing", amr: amr.join(" ") })]);
  });

  it.each([
    ["an emailed code", ["otp"]],
    ["a federated sign-in", ["fed"]],
    ["a passkey without user verification", ["hwk"]],
  ])("refuses a single-factor sign-in: %s (acr urn:acr:1fa)", async (_, amr) => {
    const { res, device } = await attempt({ idToken: await id.idToken(ALICE, { acr: ACR_1FA, amr }) });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ sso: "required" });
    expect(await keyRow(device.keyId)).toBeNull();
    expect((await events()).at(-1)).toMatchObject({ reason: "mfa_missing" });
  });

  it("refuses urn:acr:1fa even when amr claims mfa: both must agree", async () => {
    const { res } = await attempt({ idToken: await id.idToken(ALICE, { acr: ACR_1FA, amr: ["fed", "mfa"] }) });
    expect(res.status).toBe(403);
    expect((await events()).at(-1)).toMatchObject({ reason: "mfa_missing" });
  });

  it("refuses urn:acr:mfa when amr has no mfa", async () => {
    for (const amr of [["hwk", "user"], ["otp"], ["fed"], ["swk"], []]) {
      const { res } = await attempt({ idToken: await id.idToken(ALICE, { acr: ACR_MFA, amr }) });
      expect(res.status).toBe(403);
      expect((await events()).at(-1)).toMatchObject({ reason: "mfa_missing" });
    }
  });

  it("fails closed on missing or malformed claims", async () => {
    const cases: Record<string, unknown>[] = [
      { acr: undefined },
      { amr: undefined },
      { acr: undefined, amr: undefined },
      { acr: "" },
      { acr: "URN:ACR:MFA" },
      { acr: " urn:acr:mfa" },
      { acr: ["urn:acr:mfa"] },
      { amr: "mfa" },
      { amr: ["MFA"] },
      { amr: [1, "mfa"] },
    ];
    for (const claims of cases) {
      const { res, device } = await attempt({ idToken: await id.idToken(ALICE, claims) });
      expect(res.status, JSON.stringify(claims)).toBe(403);
      expect(await keyRow(device.keyId)).toBeNull();
    }
  });

  it("accepts another multi-factor acr only when ATTEST_MFA_ACR names it, and still needs amr mfa", async () => {
    const custom = appEnv({ ATTEST_MFA_ACR: "urn:acr:mfa, urn:example:strong" });
    const strong = await attempt({ env: custom, idToken: await id.idToken(ALICE, { acr: "urn:example:strong" }) });
    expect(strong.res.status).toBe(201);
    expect(await keyRow(strong.device.keyId)).toMatchObject({ mfa_required: 1, mfa_acr: "urn:example:strong" });
    expect((await attempt({ env: custom, idToken: await id.idToken(ALICE, { acr: ACR_MFA }) })).res.status).toBe(201);
    expect((await attempt({ env: custom, idToken: await id.idToken(ALICE, { acr: "urn:example:strong", amr: ["otp"] }) })).res.status).toBe(403);
    expect((await attempt({ env: custom, idToken: await id.idToken(ALICE, { acr: ACR_1FA }) })).res.status).toBe(403);
    // Not named, so not accepted.
    expect((await attempt({ idToken: await id.idToken(ALICE, { acr: "urn:example:strong" }) })).res.status).toBe(403);
  });

  it("cannot be configured to accept a single-factor acr", async () => {
    for (const configured of ["urn:acr:1fa", "urn:acr:1fa,urn:acr:mfa"]) {
      const widened = appEnv({ ATTEST_MFA_ACR: configured });
      const { res } = await attempt({ env: widened, idToken: await id.idToken(ALICE, { acr: ACR_1FA }) });
      expect(res.status, configured).toBe(403);
    }
  });

  it("refuses everyone when the configured list names nothing useful (a typo fails closed)", async () => {
    const typo = appEnv({ ATTEST_MFA_ACR: "urn:acr:mfaa" });
    expect((await attempt({ env: typo })).res.status).toBe(403);
  });

  it("refuses an ID token that is not one: someone else's, expired, an access token, or forged", async () => {
    const cases: [string, string][] = [
      [await id.idToken(BOB), "id_token_sub_mismatch"],
      [await id.idToken(ALICE, { exp: Math.floor(Date.now() / 1000) - 1 }), "id_token_expired"],
      [await id.idToken(ALICE, { aud: "another-client" }), "id_token_wrong_audience"],
      [await id.idToken(ALICE, { iss: "https://evil.example" }), "id_token_wrong_issuer"],
      [await id.idToken(ALICE, { scope: "openid" }), "id_token_wrong_type"],
      [await id.idToken(ALICE, {}, { typ: "at+jwt" }), "id_token_wrong_type"],
      [(await id.idToken(ALICE)).replace(/\.[^.]+$/, ".AAAA"), "id_token_bad_signature"],
    ];
    for (const [token, reason] of cases) {
      const { res } = await attempt({ idToken: token });
      expect(res.status).toBe(403);
      expect((await events()).at(-1)).toMatchObject({ reason });
    }
  });

  it("can be relaxed on purpose with ATTEST_MFA=off, and still records what the token said", async () => {
    const relaxed = appEnv({ ATTEST_MFA: "off" });
    const token = await id.accessToken(ALICE, relaxed);
    const challenge = await enrolmentChallenge(token, relaxed);
    const device = await attest(ca, challenge, { appId: APP_ID, ...MAC });
    const res = await register(token, { challenge, keyId: device.keyId, attestation: device.attestation, appId: APP_ID, deviceLabel: "x" }, relaxed);
    expect(res.status).toBe(201);
    expect(await keyRow(device.keyId)).toMatchObject({ mfa_required: 0, mfa_acr: null, mfa_amr: null });

    const oneFactor = await attempt({ env: relaxed, idToken: await id.idToken(ALICE, { acr: ACR_1FA, amr: ["otp"] }) });
    expect(oneFactor.res.status).toBe(201);
    expect(await keyRow(oneFactor.device.keyId)).toMatchObject({ mfa_required: 0, mfa_acr: ACR_1FA, mfa_amr: JSON.stringify(["otp"]) });
  });

  it("treats any other value as required", async () => {
    for (const value of ["", " ", "OFF", "false", "0", "no", "required", "of"]) {
      const { res } = await attempt({ env: appEnv({ ATTEST_MFA: value }), idToken: await id.idToken(ALICE, { acr: ACR_1FA, amr: ["otp"] }) });
      expect(res.status, JSON.stringify(value)).toBe(403);
    }
  });
});

describe("mfaAcrs", () => {
  it("is urn:acr:mfa unless configured", () => {
    expect([...mfaAcrs(appEnv())]).toEqual(["urn:acr:mfa"]);
    expect([...mfaAcrs(appEnv({ ATTEST_MFA_ACR: "" }))]).toEqual(["urn:acr:mfa"]);
    expect([...mfaAcrs(appEnv({ ATTEST_MFA_ACR: "  " }))]).toEqual(["urn:acr:mfa"]);
  });

  it("takes the configured list, never urn:acr:1fa", () => {
    expect([...mfaAcrs(appEnv({ ATTEST_MFA_ACR: "urn:acr:mfa,urn:example:strong" }))].sort()).toEqual(["urn:acr:mfa", "urn:example:strong"]);
    expect([...mfaAcrs(appEnv({ ATTEST_MFA_ACR: "urn:acr:1fa,urn:acr:mfa" }))]).toEqual(["urn:acr:mfa"]);
    expect([...mfaAcrs(appEnv({ ATTEST_MFA_ACR: "urn:acr:1fa" }))]).toEqual([]);
  });
});
