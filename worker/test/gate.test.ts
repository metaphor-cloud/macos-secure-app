import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { ATTEST_SESSION_PATH, APP_HEADER, SESSION_BOOTSTRAP } from "@secure-app/shared/request";
import { setupDatabase, cleanDatabase } from "./setup";
import { setAppAttestRootForTests } from "../src/lib/trustRoot";
import { isGatedPath } from "../src/gate";
import { connectToHub, revokeHubKey } from "../src/lib/hub";
import { makeTestCa, type TestCa } from "./helpers/appAttestFixture";
import { ALICE, BOB, APP_ID, IdentityStub, ORIGIN, appEnv, bearer, call, captureLogs, enrol, logged, signed, type EnrolledDevice } from "./helpers/attestKit";
import type { Bindings } from "../src/types";

// The gate in front of every /api path, always on.

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

const REFUSAL = { error: "This needs the app on an enrolled device." };

async function counterOf(keyId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT counter FROM app_keys WHERE key_id = ?").bind(keyId).first<{ counter: number }>();
  return row!.counter;
}

async function isRefusal(res: Response): Promise<boolean> {
  return res.status === 403 && JSON.stringify(await res.clone().json().catch(() => null)) === JSON.stringify(REFUSAL);
}

/** The Worker's answer to a path it doesn't have: what anything outside the app gets. */
async function isNotFound(res: Response): Promise<boolean> {
  return res.status === 404 && JSON.stringify(await res.clone().json().catch(() => null)) === JSON.stringify({ error: "Not found" });
}

/** Runs `send` with console.warn watched; returns the gate's refusal reasons. */
async function refusedFor(send: () => Promise<Response>, message = "request refused"): Promise<{ res: Response; reasons: string[] }> {
  const warn = vi.spyOn(console, "warn");
  const res = await send();
  const reasons = logged(warn, message).map((d) => String(d.reason));
  warn.mockRestore();
  return { res, reasons };
}

describe("the paths it owns", () => {
  it("covers /api and everything under it, and nothing that merely starts the same", () => {
    for (const p of ["/api", "/api/", "/api/me", "/api/notes/abc/export", "/api/live", "/api/attest/session"]) expect(isGatedPath(p), p).toBe(true);
    for (const p of ["/", "/apix", "/api-docs", "/app/api", "/health"]) expect(isGatedPath(p), p).toBe(false);
  });

  it("can't be switched off: no setting in wrangler.jsonc turns it off, and ENVIRONMENT is not in it", async () => {
    const { default: wrangler } = await import("../wrangler.jsonc?raw");
    expect(wrangler).not.toMatch(/ATTEST_MODE|ATTEST_ENFORCE|ATTEST_DISABLED|BYPASS/i);
    expect(wrangler).not.toMatch(/"ENVIRONMENT"\s*:/);
  });
});

describe("the gate", () => {
  let device: EnrolledDevice;
  let token: string;

  beforeEach(async () => {
    device = await enrol(ca, id, ALICE);
    token = await id.accessToken(ALICE, env);
  });

  it("admits a signed request from the token's own enrolled device and advances the counter by one", async () => {
    const res = await call(await signed(device, token), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ email: ALICE.email, keyId: device.keyId });
    expect(await counterOf(device.keyId)).toBe(1);
    expect((await call(await signed(device, token, { counter: 5 }), env)).status).toBe(200);
    expect(await counterOf(device.keyId)).toBe(5);
  });

  it("refuses everything else: the app gets the same 403, anything without its headers a 404, and each says why in the log", async () => {
    const bobToken = await id.accessToken(BOB, env);
    const cases: [string, () => Promise<Request>, string][] = [
      ["no credentials", async () => new Request(`${ORIGIN}/api/me`), "bearer_missing"],
      ["a bearer token alone", async () => new Request(`${ORIGIN}/api/me`, { headers: bearer(token) }), "attestation_missing"],
      ["someone else's token with this key", async () => signed(device, bobToken), "key_owner_mismatch"],
      ["a token other than the one signed", async () => signed(device, token, { signedToken: bobToken }), "signature_invalid"],
      ["a stale timestamp", async () => signed(device, token, { time: Date.now() - 121_000 }), "request_stale"],
      ["a future timestamp", async () => signed(device, token, { time: Date.now() + 121_000 }), "request_stale"],
      ["an unknown key", async () => signed(device, token, { headers: { [APP_HEADER.key]: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } }), "key_unknown"],
      ["an App ID that is not configured", async () => signed(device, token, { headers: { [APP_HEADER.app]: "TEAMID1234.com.example.other" } }), "app_id_not_allowed"],
      ["a signature for another App ID", async () => signed(device, token, { rpAppId: "TEAMID1234.com.example.other" }), "rp_id_mismatch"],
      ["a challenge never issued", async () => signed(device, token, { challenge: "A".repeat(43) }), "challenge_invalid"],
      ["bootstrap outside the session path", async () => signed(device, token, { challenge: SESSION_BOOTSTRAP }), "challenge_malformed"],
      ["a malformed nonce", async () => signed(device, token, { nonce: "short" }), "headers_malformed"],
      ["no assertion", async () => signed(device, token, { headers: { [APP_HEADER.assertion]: null } }), "headers_malformed"],
      ["an assertion that is not base64", async () => signed(device, token, { headers: { [APP_HEADER.assertion]: "!!!" } }), "assertion_malformed"],
      ["a counter that does not rise", async () => signed(device, token, { counter: 0 }), "counter_not_increasing"],
    ];
    for (const [what, make, reason] of cases) {
      const request = await make();
      const unsigned = !request.headers.has(APP_HEADER.key);
      const { res, reasons } = await refusedFor(async () => call(request, env));
      expect(await (unsigned ? isNotFound(res) : isRefusal(res)), what).toBe(true);
      expect(reasons, what).toEqual([reason]);
    }
    expect(await counterOf(device.keyId)).toBe(0);
  });

  it("refuses a method, path or body other than the one signed", async () => {
    const changed: [string, Request][] = [];
    const post = await signed(device, token, { method: "POST", path: "/api/devices/revoke", body: '{"keyId":"x","reason":"a"}', sendBody: '{"keyId":"y","reason":"a"}' });
    changed.push(["body", post]);
    const moved = await signed(device, token, { path: "/api/me" });
    changed.push(["path", new Request(`${ORIGIN}/api/devices`, { headers: moved.headers })]);
    const query = await signed(device, token, { path: "/api/notes?q=a" });
    changed.push(["query", new Request(`${ORIGIN}/api/notes?q=b`, { headers: query.headers })]);
    const get = await signed(device, token, { path: "/api/devices" });
    changed.push(["method", new Request(`${ORIGIN}/api/devices`, { method: "DELETE", headers: get.headers })]);
    for (const [what, request] of changed) {
      const { res, reasons } = await refusedFor(() => call(request, env));
      expect(await isRefusal(res), what).toBe(true);
      expect(reasons, what).toEqual(["signature_invalid"]);
    }
  });

  it("admits a request once: the same one again is refused", async () => {
    const request = await signed(device, token);
    const copy = request.clone();
    expect((await call(request, env)).status).toBe(200);
    const { res, reasons } = await refusedFor(() => call(copy, env));
    expect(await isRefusal(res)).toBe(true);
    expect(reasons).toEqual(["counter_not_increasing"]);
  });

  it("lets exactly one of three concurrent copies through, and records the race", async () => {
    const request = await signed(device, token);
    const copies = [request, request.clone(), request.clone()];
    const results = await Promise.all(copies.map((r) => call(r, env)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 403)).toHaveLength(2);
    expect(await counterOf(device.keyId)).toBe(1);
  });

  it("refuses a revoked key, even with a request signed before the revoke", async () => {
    const early = await signed(device, token);
    await env.DB.prepare("UPDATE app_keys SET revoked_at = datetime('now') WHERE key_id = ?").bind(device.keyId).run();
    const { res, reasons } = await refusedFor(() => call(early, env));
    expect(await isRefusal(res)).toBe(true);
    expect(reasons).toEqual(["key_revoked"]);
  });

  it("refuses someone who has left the access group, whatever their device", async () => {
    const leaver = await id.accessToken(ALICE, env, { groups: [] });
    const { res, reasons } = await refusedFor(async () => call(await signed(device, leaver), env));
    expect(await isRefusal(res)).toBe(true);
    expect(reasons).toEqual(["bearer_invalid"]);
  });

  it("fails closed when verification itself breaks, with a 503 the app waits out instead of giving up its key", async () => {
    const broken = {
      ...env,
      DB: new Proxy(env.DB, {
        get(target, prop) {
          if (prop === "prepare") {
            return (sql: string) => {
              if (sql.includes("FROM app_keys WHERE key_id")) throw new Error("D1 unavailable");
              return target.prepare(sql);
            };
          }
          return Reflect.get(target, prop);
        },
      }),
    } as Bindings;
    const { res, reasons } = await refusedFor(async () => call(await signed(device, token), broken));
    expect(res.status).toBe(503);
    expect(res.headers.get("Retry-After")).toBe("30");
    expect(await isRefusal(res)).toBe(false);
    expect(reasons).toEqual(["verify_error"]);
    // Nothing outside the app learns any more than before.
    expect(await isNotFound(await call(new Request(`${ORIGIN}/api/notes`, { headers: bearer(token) }), broken))).toBe(true);
    // Nor does the session challenge give up the key.
    const session = await refusedFor(async () => call(await signed(device, token, { path: ATTEST_SESSION_PATH, challenge: device.sessionChallenge }), broken));
    expect(session.res.status).toBe(503);
    expect(session.reasons).toEqual(["verify_error"]);
  });

  it("asks nothing of Apple: the only outbound calls are the identity provider's", async () => {
    const fetchSpy = globalThis.fetch as unknown as { mock: { calls: unknown[][] } };
    const before = fetchSpy.mock.calls.length;
    expect((await call(await signed(device, token), env)).status).toBe(200);
    const urls = fetchSpy.mock.calls.slice(before).map((args) => String(args[0] instanceof Request ? args[0].url : args[0]));
    expect(urls.every((u) => u.startsWith("https://id.test/"))).toBe(true);
  });

  it("answers anything outside the app as a path it doesn't have, and logs why", async () => {
    const requests: [string, Request][] = [
      ["bearer only", new Request(`${ORIGIN}/api/me`, { headers: bearer(token) })],
      ["no credentials", new Request(`${ORIGIN}/api/notes`)],
      ["a write", new Request(`${ORIGIN}/api/notes`, { method: "POST", body: "{}" })],
      ["an unknown attest path", new Request(`${ORIGIN}/api/attest/anything`)],
      ["outside /api", new Request(`${ORIGIN}/admin`)],
      ["the root", new Request(`${ORIGIN}/`)],
    ];
    for (const [what, request] of requests) expect(await isNotFound(await call(request, env)), what).toBe(true);
    const { reasons } = await refusedFor(() => call(new Request(`${ORIGIN}/api/notes`), env));
    expect(reasons).toEqual(["bearer_missing"]);
  });

  it("opens the live socket for a signed upgrade, tagged with the key, and closes it on revoke", async () => {
    const upgrade = await signed(device, token, { path: "/api/live", headers: { Upgrade: "websocket" } });
    const res = await call(upgrade, env);
    expect(res.status).toBe(101);
    const socket = res.webSocket!;
    socket.accept();
    const closed = new Promise<number>((resolve) => socket.addEventListener("close", (e) => resolve((e as CloseEvent).code)));
    await revokeHubKey(env, device.keyId);
    expect(await closed).toBe(4403);
  });
});

describe("the live hub's key tag", () => {
  it("comes only from the gate, never from a header the client sent", async () => {
    const res = await connectToHub(new Request(`${ORIGIN}/api/live`, { headers: { Upgrade: "websocket", "X-Hub-Key": "someone-elses-key" } }), env);
    const socket = res.webSocket!;
    socket.accept();
    let closedCode: number | null = null;
    socket.addEventListener("close", (e) => (closedCode = (e as CloseEvent).code));
    await revokeHubKey(env, "someone-elses-key");
    await new Promise((r) => setTimeout(r, 50));
    expect(closedCode).toBeNull();
    socket.close();
  });
});

describe("the session challenge", () => {
  async function session(device: EnrolledDevice, token: string, challenge: string, sendEnv: Bindings = env) {
    return call(await signed(device, token, { path: ATTEST_SESSION_PATH, challenge }), sendEnv);
  }

  it("rotates on a signed request, keeping the previous challenge usable", async () => {
    const device = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    const first = device.sessionChallenge;
    const res = await session(device, token, SESSION_BOOTSTRAP);
    expect(res.status).toBe(200);
    const second = ((await res.json()) as { challenge: string }).challenge;
    expect(second).not.toBe(first);
    // Both the new one and the one before it work.
    expect((await call(await signed(device, token, { challenge: second }), env)).status).toBe(200);
    expect((await call(await signed(device, token, { challenge: first }), env)).status).toBe(200);
    // Two rotations on, the first is gone.
    const third = ((await (await session(device, token, second)).json()) as { challenge: string }).challenge;
    expect(third).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const { res: stale, reasons } = await refusedFor(async () => call(await signed(device, token, { challenge: first }), env));
    expect(await isRefusal(stale)).toBe(true);
    expect(reasons).toEqual(["challenge_invalid"]);
  });

  it("refuses an expired challenge", async () => {
    const device = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    await env.DB.prepare("UPDATE app_keys SET session_challenge_expires_at = ? WHERE key_id = ?").bind(Date.now() - 1, device.keyId).run();
    const { res, reasons } = await refusedFor(async () => call(await signed(device, token), env));
    expect(await isRefusal(res)).toBe(true);
    expect(reasons).toEqual(["challenge_invalid"]);
  });

  it("refuses an unsigned request, and any method but GET", async () => {
    const device = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    expect(await isNotFound(await call(new Request(`${ORIGIN}${ATTEST_SESSION_PATH}`, { headers: bearer(token) }), env))).toBe(true);
    const post = await signed(device, token, { method: "POST", path: ATTEST_SESSION_PATH, challenge: SESSION_BOOTSTRAP, body: "{}" });
    expect((await call(post, env)).status).toBe(405);
  });
});

describe("never logged", () => {
  it("keeps tokens, assertions and full key ids out of every log line", async () => {
    const device = await enrol(ca, id, ALICE);
    const token = await id.accessToken(ALICE, env);
    const lines = captureLogs();
    const good = await signed(device, token);
    const assertionHeader = good.headers.get(APP_HEADER.assertion)!;
    await call(good, env);
    await call(await signed(device, token, { counter: 0 }), env);
    await call(await signed(device, await id.accessToken(BOB, env)), env);
    await call(await signed(device, token, { time: 1 }), env);
    const all = lines.join("\n");
    expect(all).toContain("request refused");
    expect(all).not.toContain(token);
    expect(all).not.toContain(assertionHeader.slice(0, 40));
    expect(all).not.toContain(device.keyId);
    expect(all).toContain(device.keyId.slice(0, 12));
  });

  it("logs objects with level, message and worker at the top, never strings", async () => {
    const warn = vi.spyOn(console, "warn");
    await call(new Request(`${ORIGIN}/api/me`), env);
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ level: "warn", message: "request refused", worker: "secure-app", data: expect.objectContaining({ reason: "bearer_missing" }) }));
  });
});

describe("enrolment alongside the gate", () => {
  it("works with the token alone: it needs no assertion", async () => {
    const device = await enrol(ca, id, ALICE, { env });
    expect(device.keyId).toBeTruthy();
    expect(APP_ID).toBe(device.appId);
  });
});
