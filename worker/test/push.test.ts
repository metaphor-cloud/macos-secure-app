import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { PUSH_TEST_PATH, PUSH_TOKEN_PATH } from "@secure-app/shared/request";
import { setupDatabase, cleanDatabase, getEnv } from "./setup";
import { setAppAttestRootForTests } from "../src/lib/trustRoot";
import { makeTestCa, type TestCa } from "./helpers/appAttestFixture";
import { ALICE, BOB, IdentityStub, APP_ID, appEnv, call, captureLogs, enrol, logged, signed } from "./helpers/attestKit";
import {
  APNS_EXPIRATION_SECONDS,
  APNS_JWT_TTL_MS,
  apnsConfig,
  apnsTopic,
  isApnsDeviceToken,
  providerToken,
  resetApnsTokenCacheForTests,
  sendApns,
  type ApnsAlert,
  type ApnsConfig,
} from "../src/lib/apns";
import { sendPush } from "../src/lib/push";
import type { Bindings } from "../src/types";

// Push to the Mac, straight to APNs. Apple is faked with a fetch spy; the
// provider key is a P-256 key made here for the run.

let ca: TestCa;
let id: IdentityStub;
let keyPair: CryptoKeyPair;
let config: ApnsConfig;

const TOPIC = "com.example.secureapp";

function pem(der: ArrayBuffer): string {
  let binary = "";
  for (const b of new Uint8Array(der)) binary += String.fromCharCode(b);
  const lines = btoa(binary).match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----\n`;
}

beforeAll(async () => {
  await setupDatabase();
  ca = await makeTestCa();
  id = await new IdentityStub().init();
  keyPair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  config = { keyP8: pem((await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)) as ArrayBuffer), keyId: "ABC123DEFG", teamId: "TEAMID1234" };
});

beforeEach(async () => {
  await cleanDatabase();
  resetApnsTokenCacheForTests();
});

afterEach(() => vi.restoreAllMocks());
afterAll(() => setAppAttestRootForTests(null));

const withApns = (env: Bindings): Bindings => ({ ...env, APNS_KEY_P8: config.keyP8, APNS_KEY_ID: config.keyId, APNS_TEAM_ID: config.teamId }) as Bindings;
const macToken = (n: string) => n.repeat(64).slice(0, 64);
const alert: ApnsAlert = { title: "Secure App", body: "A note was added.", badge: 3, threadId: "#/notes", path: "#/notes" };

function b64urlJson(part: string): Record<string, unknown> {
  return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
}

function b64urlBytes(part: string): Uint8Array {
  const s = atob(part.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (part.length % 4)) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

interface ApnsRequest {
  url: string;
  headers: Headers;
  body: { aps: { alert: { title: string; body: string }; badge?: number; sound: string; "thread-id": string }; path?: string };
}

/**
 * Fakes APNs (any api*.push.apple.com URL). `apns` answers each request;
 * everything else goes to whatever fetch was before (the identity stub, or
 * the network guard). Returns what Apple received.
 */
function fakeApns(opts: { apns?: (r: ApnsRequest) => Response | Promise<Response> } = {}) {
  const apns: ApnsRequest[] = [];
  // Spying on fetch again returns the same spy, so a fake already installed
  // (the identity stub) is kept by its implementation, not by reference.
  const current = globalThis.fetch;
  const fallback = vi.isMockFunction(current) ? (current.getMockImplementation() as typeof fetch) : current;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (/^https:\/\/api(\.sandbox)?\.push\.apple\.com\//.test(url)) {
      const req = { url, headers: new Headers(init?.headers), body: JSON.parse(String(init?.body)) };
      apns.push(req);
      return opts.apns ? opts.apns(req) : new Response(null, { status: 200, headers: { "apns-id": crypto.randomUUID() } });
    }
    return fallback(input, init);
  });
  return apns;
}

/** An enrolled key row and its push token, straight into D1. */
async function device(env: Bindings, keyId: string, email: string, token: string | null, environment: "production" | "development" = "production", opts: { revoked?: boolean } = {}) {
  await env.DB.prepare(
    `INSERT INTO app_keys (key_id, sub, email, app_id, device_label, public_key, environment, mfa_required, revoked_at)
     VALUES (?, ?, ?, ?, 'Mac', 'pk', 'production', 1, ?)`,
  ).bind(keyId, `sub-${email}`, email, APP_ID, opts.revoked ? "2026-10-01 00:00:00" : null).run();
  if (token) {
    await env.DB.prepare("INSERT INTO push_tokens (key_id, token, sub, email, apns_environment) VALUES (?, ?, ?, ?, ?)").bind(keyId, token, `sub-${email}`, email, environment).run();
  }
}

async function tokens(env: Bindings) {
  return (await env.DB.prepare("SELECT key_id, token, apns_environment FROM push_tokens ORDER BY key_id").all<{ key_id: string; token: string; apns_environment: string }>()).results;
}

describe("the APNs provider token", () => {
  it("is an ES256 JWT with the key id and team, verifiable with the key's public half", async () => {
    const now = Date.UTC(2026, 10, 1, 0, 0, 0);
    const jwt = await providerToken(config, now);
    const [header, claims, signature] = jwt.split(".");
    expect(b64urlJson(header)).toEqual({ alg: "ES256", kid: "ABC123DEFG" });
    expect(b64urlJson(claims)).toEqual({ iss: "TEAMID1234", iat: now / 1000 });
    const sig = b64urlBytes(signature);
    expect(sig.length).toBe(64);
    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, keyPair.publicKey, sig, new TextEncoder().encode(`${header}.${claims}`));
    expect(valid).toBe(true);
  });

  it("is reused for 50 minutes, then signed again", async () => {
    const now = Date.UTC(2026, 10, 1);
    const first = await providerToken(config, now);
    expect(await providerToken(config, now + APNS_JWT_TTL_MS - 1)).toBe(first);
    const next = await providerToken(config, now + APNS_JWT_TTL_MS);
    expect(next).not.toBe(first);
    expect(b64urlJson(next.split(".")[1]).iat).toBe((now + APNS_JWT_TTL_MS) / 1000);
  });

  it("reads a key pasted with literal \\n for newlines", async () => {
    const jwt = await providerToken({ ...config, keyP8: config.keyP8.replace(/\n/g, "\\n") });
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("is off unless all three secrets are set", () => {
    expect(apnsConfig(getEnv())).toBeNull();
    expect(apnsConfig({ ...withApns(getEnv()), APNS_KEY_ID: "" } as Bindings)).toBeNull();
    expect(apnsConfig(withApns(getEnv()))).toEqual({ ...config, keyP8: config.keyP8.trim() });
  });

  it("knows an APNs device token, and the topic is the bundle id", () => {
    expect(isApnsDeviceToken("ab".repeat(32))).toBe(true);
    expect(isApnsDeviceToken("ab".repeat(80))).toBe(true);
    expect(isApnsDeviceToken("AB".repeat(32))).toBe(false);
    expect(isApnsDeviceToken("ab".repeat(31))).toBe(false);
    expect(isApnsDeviceToken(`${"ab".repeat(32)}a`)).toBe(false);
    expect(isApnsDeviceToken(42)).toBe(false);
    expect(apnsTopic(APP_ID)).toBe(TOPIC);
  });
});

describe("sendApns", () => {
  it("posts the alert to the production host with Apple's headers", async () => {
    const apns = fakeApns();
    const now = Date.UTC(2026, 10, 1);
    expect(await sendApns(config, TOPIC, macToken("a"), "production", alert, now)).toEqual({ kind: "sent" });
    expect(apns).toHaveLength(1);
    const [req] = apns;
    expect(req.url).toBe(`https://api.push.apple.com/3/device/${macToken("a")}`);
    expect(req.headers.get("authorization")).toBe(`bearer ${await providerToken(config, now)}`);
    expect(req.headers.get("apns-topic")).toBe(TOPIC);
    expect(req.headers.get("apns-push-type")).toBe("alert");
    expect(req.headers.get("apns-priority")).toBe("10");
    expect(req.headers.get("apns-expiration")).toBe(String(now / 1000 + APNS_EXPIRATION_SECONDS));
    expect(req.body).toEqual({
      aps: { alert: { title: "Secure App", body: "A note was added." }, badge: 3, sound: "default", "thread-id": "#/notes" },
      path: "#/notes",
    });
  });

  it("uses the sandbox host for a development token, and leaves the path and badge out when there are none", async () => {
    const apns = fakeApns();
    await sendApns(config, TOPIC, macToken("b"), "development", { ...alert, path: null, badge: null });
    expect(apns[0].url).toBe(`https://api.sandbox.push.apple.com/3/device/${macToken("b")}`);
    expect(apns[0].body).not.toHaveProperty("path");
    expect(apns[0].body.aps).not.toHaveProperty("badge");
  });

  it("says to drop the token on 410, BadDeviceToken, and DeviceTokenNotForTopic, and not on other refusals", async () => {
    const answers = [
      { status: 410, reason: "Unregistered" },
      { status: 400, reason: "BadDeviceToken" },
      { status: 400, reason: "DeviceTokenNotForTopic" },
      { status: 400, reason: "PayloadTooLarge" },
      { status: 429, reason: "TooManyRequests" },
    ];
    let i = 0;
    fakeApns({ apns: () => Response.json({ reason: answers[i].reason }, { status: answers[i++].status }) });
    const outcomes = [];
    for (let n = 0; n < answers.length; n++) outcomes.push(await sendApns(config, TOPIC, macToken("c"), "production", alert));
    expect(outcomes).toEqual([
      { kind: "drop", status: 410, reason: "Unregistered" },
      { kind: "drop", status: 400, reason: "BadDeviceToken" },
      { kind: "drop", status: 400, reason: "DeviceTokenNotForTopic" },
      { kind: "failed", status: 400, reason: "PayloadTooLarge" },
      { kind: "failed", status: 429, reason: "TooManyRequests" },
    ]);
  });

  it("signs a new provider token after Apple says the old one expired", async () => {
    const now = Date.UTC(2026, 10, 1);
    let first = true;
    const apns = fakeApns({
      apns: () => {
        if (!first) return new Response(null, { status: 200 });
        first = false;
        return Response.json({ reason: "ExpiredProviderToken" }, { status: 403 });
      },
    });
    expect(await sendApns(config, TOPIC, macToken("d"), "production", alert, now)).toEqual({ kind: "failed", status: 403, reason: "ExpiredProviderToken" });
    expect(await sendApns(config, TOPIC, macToken("d"), "production", alert, now + 1000)).toEqual({ kind: "sent" });
    expect(apns[0].headers.get("authorization")).not.toBe(apns[1].headers.get("authorization"));
  });

  it("reports an unreachable APNs and a bad key without throwing", async () => {
    fakeApns({ apns: () => Promise.reject(new TypeError("network down")) });
    expect(await sendApns(config, TOPIC, macToken("e"), "production", alert)).toEqual({ kind: "failed", status: null, reason: "apns_unreachable" });
    expect(await sendApns({ ...config, keyId: "OTHER", keyP8: "not a key" }, TOPIC, macToken("e"), "production", alert)).toEqual({
      kind: "failed",
      status: null,
      reason: "bad_provider_key",
    });
  });
});

describe("sendPush", () => {
  it("reaches every live device with the same text and path, sandbox tokens on the sandbox host", async () => {
    const env = withApns(appEnv());
    await device(env, "key-mac", "alice@example.test", macToken("a"));
    await device(env, "key-mac-dev", "bob@example.test", macToken("b"), "development");
    await device(env, "key-gone", "carol@example.test", macToken("g"), "production", { revoked: true });
    await device(env, "key-none", "dave@example.test", null);
    const apns = fakeApns();
    const lines = captureLogs();

    const outcome = await sendPush(env, { event: "note_created", body: "A note was added.", path: "#/notes" });

    expect(outcome).toEqual({ devices: 2, sent: 2, failed: 0, pruned: 0, skipped: 0 });
    const byUrl = Object.fromEntries(apns.map((r) => [r.url, r]));
    expect(byUrl[`https://api.push.apple.com/3/device/${macToken("a")}`].body).toEqual({
      aps: { alert: { title: "Secure App", body: "A note was added." }, sound: "default", "thread-id": "#/notes" },
      path: "#/notes",
    });
    expect(byUrl[`https://api.sandbox.push.apple.com/3/device/${macToken("b")}`]).toBeDefined();
    expect(apns.every((r) => r.headers.get("apns-topic") === TOPIC)).toBe(true);
    // Neither the device tokens nor the key reach the log.
    const logText = lines.join("\n");
    expect(logText).not.toContain(macToken("a"));
    expect(logText).not.toContain(config.keyP8.split("\n")[1]);
  });

  it("leaves out the device that caused it", async () => {
    const env = withApns(appEnv());
    await device(env, "key-a", "alice@example.test", macToken("a"));
    await device(env, "key-b", "bob@example.test", macToken("b"));
    const apns = fakeApns();
    const outcome = await sendPush(env, { event: "note_created", body: "x", path: null, exceptKeyId: "key-a" });
    expect(outcome).toMatchObject({ devices: 1, sent: 1 });
    expect(apns.map((r) => r.url)).toEqual([`https://api.push.apple.com/3/device/${macToken("b")}`]);
  });

  it("prunes a token Apple says is dead, and logs why", async () => {
    const env = withApns(appEnv());
    await device(env, "key-a", "alice@example.test", macToken("a"));
    await device(env, "key-b", "bob@example.test", macToken("b"));
    fakeApns({ apns: (r) => (r.url.includes(macToken("a")) ? Response.json({ reason: "Unregistered" }, { status: 410 }) : new Response(null, { status: 200 })) });
    const info = vi.spyOn(console, "log");
    const outcome = await sendPush(env, { event: "note_created", body: "x", path: null });
    expect(outcome).toEqual({ devices: 2, sent: 1, failed: 1, pruned: 1, skipped: 0 });
    expect((await tokens(env)).map((t) => t.key_id)).toEqual(["key-b"]);
    expect(logged(info, "push token pruned")).toEqual([expect.objectContaining({ reason: "apns_token_dead", apnsReason: "Unregistered" })]);
  });

  it("logs a refusal that is not a dead token, and keeps the token", async () => {
    const env = withApns(appEnv());
    await device(env, "key-a", "alice@example.test", macToken("a"));
    fakeApns({ apns: () => Response.json({ reason: "TooManyRequests" }, { status: 429 }) });
    const warn = vi.spyOn(console, "warn");
    const outcome = await sendPush(env, { event: "note_created", body: "x", path: null });
    expect(outcome).toMatchObject({ sent: 0, failed: 1, pruned: 0 });
    expect(logged(warn, "push not delivered")).toEqual([expect.objectContaining({ reason: "TooManyRequests", status: 429, keyRef: "key-a" })]);
    expect(await tokens(env)).toHaveLength(1);
  });

  it("never throws when Apple is down, and logs why", async () => {
    const env = withApns(appEnv());
    await device(env, "key-a", "alice@example.test", macToken("a"));
    fakeApns({ apns: () => Promise.reject(new TypeError("apns down")) });
    const warn = vi.spyOn(console, "warn");
    expect(await sendPush(env, { event: "note_created", body: "x", path: null })).toMatchObject({ sent: 0, failed: 1, pruned: 0 });
    expect(logged(warn, "push not delivered")).toEqual([expect.objectContaining({ reason: "apns_unreachable" })]);
    expect(await tokens(env)).toHaveLength(1);
  });

  it("skips devices when APNs is not configured, and says so", async () => {
    const env = getEnv();
    await device(env, "key-a", "alice@example.test", macToken("a"));
    await device(env, "key-b", "bob@example.test", macToken("b"));
    const apns = fakeApns();
    const info = vi.spyOn(console, "log");
    expect(await sendPush(env, { event: "note_created", body: "x", path: null })).toEqual({ devices: 2, sent: 0, failed: 0, pruned: 0, skipped: 2 });
    expect(apns).toHaveLength(0);
    expect(logged(info, "push apns off")).toEqual([expect.objectContaining({ reason: "apns_not_configured", devices: 2 })]);
    expect(await tokens(env)).toHaveLength(2);
  });

  it("does nothing, and asks Apple nothing, with no devices", async () => {
    const apns = fakeApns();
    expect(await sendPush(withApns(appEnv()), { event: "note_created", body: "x", path: null })).toEqual({ devices: 0, sent: 0, failed: 0, pruned: 0, skipped: 0 });
    expect(apns).toHaveLength(0);
  });

  it("never throws when the database fails, and logs it as an error", async () => {
    const broken = { ...withApns(appEnv()), DB: { prepare: () => { throw new Error("D1 down"); } } } as unknown as Bindings;
    const error = vi.spyOn(console, "error");
    expect(await sendPush(broken, { event: "note_created", body: "x", path: null })).toMatchObject({ sent: 0 });
    expect(logged(error, "push failed")).toEqual([expect.objectContaining({ reason: "push_error" })]);
  });
});

describe("the push token and test endpoints", () => {
  beforeEach(() => {
    setAppAttestRootForTests(ca.root.der);
    id.install();
  });

  const post = (body: unknown) => ({ method: "POST", path: PUSH_TOKEN_PATH, body: JSON.stringify(body) });
  const test = { method: "POST", path: PUSH_TEST_PATH };

  it("stores an APNs token with its environment against the signing key, and replaces it with a new one", async () => {
    const env = appEnv();
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    expect((await call(await signed(mac, token, post({ token: macToken("a"), environment: "development" })), env)).status).toBe(200);
    expect((await call(await signed(mac, token, post({ token: macToken("b"), environment: "production" })), env)).status).toBe(200);
    expect(await tokens(env)).toEqual([{ key_id: mac.keyId, token: macToken("b"), apns_environment: "production" }]);
  });

  it("moves a token that turns up on a new key", async () => {
    const env = appEnv();
    const old = await enrol(ca, id, ALICE);
    const fresh = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await call(await signed(old, token, post({ token: macToken("a"), environment: "production" })), env);
    await call(await signed(fresh, token, post({ token: macToken("a"), environment: "production" })), env);
    expect(await tokens(env)).toEqual([{ key_id: fresh.keyId, token: macToken("a"), apns_environment: "production" }]);
  });

  it("keeps the key from the signed request, never the body", async () => {
    const env = appEnv();
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await call(await signed(mac, token, post({ token: macToken("a"), environment: "production", keyId: "someone-else" })), env);
    expect((await tokens(env)).map((t) => t.key_id)).toEqual([mac.keyId]);
  });

  it("refuses a bad token, a missing environment, and bad JSON, and says why in the log", async () => {
    const env = appEnv();
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    const warn = vi.spyOn(console, "warn");
    for (const body of [{ token: "zz", environment: "production" }, { token: macToken("a") }, { token: macToken("a"), environment: "staging" }]) {
      expect((await call(await signed(mac, token, post(body)), env)).status).toBe(400);
    }
    expect((await call(await signed(mac, token, { method: "POST", path: PUSH_TOKEN_PATH, body: "not json" }), env)).status).toBe(400);
    expect(logged(warn, "push token refused").map((d) => d.reason)).toEqual(["bad_apns_token", "bad_apns_token", "bad_apns_token", "bad_json"]);
    expect(await tokens(env)).toEqual([]);
  });

  it("deletes the token on sign-out", async () => {
    const env = appEnv();
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await call(await signed(mac, token, post({ token: macToken("a"), environment: "production" })), env);
    expect((await call(await signed(mac, token, { method: "DELETE", path: PUSH_TOKEN_PATH }), env)).status).toBe(200);
    expect(await tokens(env)).toEqual([]);
  });

  it("deletes the token when the key is revoked", async () => {
    const env = appEnv();
    const alice = await enrol(ca, id, ALICE);
    const bob = await enrol(ca, id, BOB);
    const aliceToken = await id.accessToken(ALICE, env);
    const bobToken = await id.accessToken(BOB, env);
    await call(await signed(alice, aliceToken, post({ token: macToken("a"), environment: "production" })), env);
    await call(await signed(bob, bobToken, post({ token: macToken("b"), environment: "production" })), env);
    const body = JSON.stringify({ keyId: alice.keyId, reason: "Lost Mac" });
    expect((await call(await signed(bob, bobToken, { method: "POST", path: "/api/devices/revoke", body }), env)).status).toBe(200);
    expect((await tokens(env)).map((t) => t.token)).toEqual([macToken("b")]);
  });

  it("sends a test notification to the asking Mac only", async () => {
    const env = withApns(appEnv());
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await device(env, "key-other-mac", "bob@example.test", macToken("o"));
    await call(await signed(mac, token, post({ token: macToken("a"), environment: "development" })), env);
    const apns = fakeApns();

    const res = await call(await signed(mac, token, test), env);

    expect(res.status).toBe(200);
    expect(apns).toHaveLength(1);
    expect(apns[0].url).toBe(`https://api.sandbox.push.apple.com/3/device/${macToken("a")}`);
    expect(apns[0].body.aps.alert).toEqual({ title: "Secure App", body: "Test notification. Push is working on this device." });
  });

  it("refuses clearly when APNs is not configured, and sends nothing", async () => {
    const env = appEnv();
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await call(await signed(mac, token, post({ token: macToken("a"), environment: "production" })), env);
    const apns = fakeApns();
    const warn = vi.spyOn(console, "warn");
    const res = await call(await signed(mac, token, test), env);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toContain("APNS_KEY_P8");
    expect(apns).toHaveLength(0);
    expect(logged(warn, "push test refused")).toEqual([expect.objectContaining({ reason: "apns_not_configured" })]);
  });

  it("says when the device has no token, and when Apple drops it", async () => {
    const env = withApns(appEnv());
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    const warn = vi.spyOn(console, "warn");
    expect((await call(await signed(mac, token, test), env)).status).toBe(409);
    expect(logged(warn, "push test refused")).toEqual([expect.objectContaining({ reason: "no_token" })]);

    await call(await signed(mac, token, post({ token: macToken("a"), environment: "production" })), env);
    fakeApns({ apns: () => Response.json({ reason: "BadDeviceToken" }, { status: 400 }) });
    expect((await call(await signed(mac, token, test), env)).status).toBe(410);
    expect(await tokens(env)).toEqual([]);
  });

  it("answers 502 when Apple refuses for another reason", async () => {
    const env = withApns(appEnv());
    const mac = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await call(await signed(mac, token, post({ token: macToken("a"), environment: "production" })), env);
    fakeApns({ apns: () => Response.json({ reason: "TooManyRequests" }, { status: 429 }) });
    expect((await call(await signed(mac, token, test), env)).status).toBe(502);
    expect(await tokens(env)).toHaveLength(1);
  });
});
