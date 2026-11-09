import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { setupDatabase, cleanDatabase } from "./setup";
import { setAppAttestRootForTests } from "../src/lib/trustRoot";
import { makeTestCa, type TestCa } from "./helpers/appAttestFixture";
import { ALICE, BOB, IdentityStub, appEnv, call, enrol, logged, signed, type EnrolledDevice } from "./helpers/attestKit";
import type { Bindings } from "../src/types";

// The example API behind the gate: who am I, notes, the device list and revoke, the live socket.

let ca: TestCa;
let id: IdentityStub;

beforeAll(async () => {
  await setupDatabase();
  ca = await makeTestCa();
  id = await new IdentityStub().init();
});

let alice: EnrolledDevice;
let bob: EnrolledDevice;
let aliceToken: string;
let bobToken: string;
const env = appEnv();

beforeEach(async () => {
  await cleanDatabase();
  setAppAttestRootForTests(ca.root.der);
  id.install();
  alice = await enrol(ca, id, ALICE, { label: "Alice's Mac" });
  bob = await enrol(ca, id, BOB, { label: "Bob's Mac" });
  aliceToken = await id.accessToken(ALICE, env);
  bobToken = await id.accessToken(BOB, env);
});

afterEach(() => vi.restoreAllMocks());
afterAll(() => setAppAttestRootForTests(null));

const json = (body: unknown) => JSON.stringify(body);

describe("GET /api/me", () => {
  it("says who is signed in and on which device", async () => {
    const res = await call(await signed(alice, aliceToken, { path: "/api/me" }), env);
    expect(await res.json()).toEqual({ sub: ALICE.sub, email: ALICE.email, name: ALICE.email, keyId: alice.keyId });
  });
});

describe("notes", () => {
  async function create(body: unknown, device = alice, token = aliceToken, context?: ExecutionContext) {
    return call(await signed(device, token, { method: "POST", path: "/api/notes", body: typeof body === "string" ? body : json(body) }), env, context);
  }

  it("creates a note for the signed-in person and lists it, newest first, to everyone", async () => {
    const res = await create({ title: "  First  ", body: "Hello" });
    expect(res.status).toBe(201);
    const { note } = (await res.json()) as { note: Record<string, string> };
    expect(note).toMatchObject({ title: "First", body: "Hello", authorEmail: ALICE.email });
    expect(res.headers.get("Location")).toBe(`/api/notes/${note.id}`);
    await env.DB.prepare("UPDATE notes SET created_at = '2020-01-01 00:00:00'").run();
    await create({ title: "Second" }, bob, bobToken);

    const list = await call(await signed(bob, bobToken, { path: "/api/notes" }), env);
    const { notes } = (await list.json()) as { notes: { title: string; body: string; authorEmail: string }[] };
    expect(notes.map((n) => n.title)).toEqual(["Second", "First"]);
    expect(notes[0]).toMatchObject({ body: "", authorEmail: BOB.email });
  });

  it("refuses a note that is not valid, and says why in the log", async () => {
    const warn = vi.spyOn(console, "warn");
    for (const body of [{ title: "" }, { title: "   " }, { title: "x".repeat(121) }, { title: "ok", body: 5 }, { title: "ok", body: "x".repeat(10_001) }, { body: "no title" }]) {
      expect((await create(body)).status, JSON.stringify(body).slice(0, 40)).toBe(400);
    }
    expect((await create("not json")).status).toBe(400);
    expect(logged(warn, "note refused").map((d) => d.reason)).toEqual([...Array(6).fill("invalid_note"), "bad_json"]);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM notes").first<{ n: number }>())!.n).toBe(0);
  });

  it("exports a note as a Markdown file download", async () => {
    const { note } = (await (await create({ title: "Plan", body: "Do the thing" })).json()) as { note: { id: string } };
    const res = await call(await signed(alice, aliceToken, { path: `/api/notes/${note.id}/export` }), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/markdown; charset=utf-8");
    expect(res.headers.get("Content-Disposition")).toBe(`attachment; filename="note-${note.id}.md"`);
    const text = await res.text();
    expect(text).toContain("# Plan");
    expect(text).toContain("Do the thing");
    expect(text).toContain(ALICE.email);
  });

  it("answers 404 for a note that is not there, and logs it", async () => {
    const warn = vi.spyOn(console, "warn");
    const res = await call(await signed(alice, aliceToken, { path: "/api/notes/nope/export" }), env);
    expect(res.status).toBe(404);
    expect(logged(warn, "note export refused")).toEqual([expect.objectContaining({ reason: "note_not_found", noteId: "nope" })]);
  });

  it("answers 405 for a method a path does not take, and 404 for a path with no route, once admitted", async () => {
    expect((await call(await signed(alice, aliceToken, { method: "DELETE", path: "/api/notes" }), env)).status).toBe(405);
    expect((await call(await signed(alice, aliceToken, { path: "/api/nothing-here" }), env)).status).toBe(404);
  });

  it("tells every open app to refetch, and pushes only to the other devices", async () => {
    const upgrade = await signed(bob, bobToken, { path: "/api/live", headers: { Upgrade: "websocket" } });
    const socket = (await call(upgrade, env)).webSocket!;
    socket.accept();
    const message = new Promise<string>((resolve) => socket.addEventListener("message", (e) => resolve(String((e as MessageEvent).data))));

    const pending: Promise<unknown>[] = [];
    const context = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;
    const configured = { ...env, APNS_KEY_ID: "ABC123DEFG", APNS_TEAM_ID: "TEAMID1234" } as Bindings;
    const debug = vi.spyOn(console, "debug");
    const res = await call(
      await signed(alice, aliceToken, { method: "POST", path: "/api/notes", body: json({ title: "Ping" }) }),
      configured,
      context,
    );
    expect(res.status).toBe(201);
    expect(JSON.parse(await message)).toEqual({ type: "changed", tables: ["notes"] });
    await Promise.all(pending);
    expect(pending).toHaveLength(1);
    // No device has a token yet, and the push says so rather than failing.
    expect(logged(debug, "push skipped")).toEqual([expect.objectContaining({ event: "note_created", reason: "no_devices" })]);
    socket.close();
  });
});

describe("devices", () => {
  it("lists every device, with no key material", async () => {
    const res = await call(await signed(bob, bobToken, { path: "/api/devices" }), env);
    expect(res.status).toBe(200);
    const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
    expect(keys.map((k) => k.deviceLabel).sort()).toEqual(["Alice's Mac", "Bob's Mac"]);
    expect(keys.find((k) => k.keyId === alice.keyId)).toMatchObject({ email: ALICE.email, active: true, mfaRequired: true, environment: "production", revokedAt: null });
    expect(keys.every((k) => !("publicKey" in k) && !("receipt" in k) && !("public_key" in k))).toBe(true);
  });

  it("lets another person revoke a device; the revoked key is refused next time, and its live socket closes", async () => {
    const upgrade = await signed(alice, aliceToken, { path: "/api/live", headers: { Upgrade: "websocket" } });
    const socket = (await call(upgrade, env)).webSocket!;
    socket.accept();
    const closed = new Promise<number>((resolve) => socket.addEventListener("close", (e) => resolve((e as CloseEvent).code)));

    const body = json({ keyId: alice.keyId, reason: "Lost Mac" });
    const revoke = await call(await signed(bob, bobToken, { method: "POST", path: "/api/devices/revoke", body }), env);
    expect(revoke.status).toBe(200);
    expect(await closed).toBe(4403);
    expect(await env.DB.prepare("SELECT revoked_by, revoked_reason FROM app_keys WHERE key_id = ?").bind(alice.keyId).first()).toEqual({ revoked_by: BOB.email, revoked_reason: "Lost Mac" });
    const events = await env.DB.prepare("SELECT event, actor, sub FROM attest_events WHERE event = 'revoke'").all();
    expect(events.results).toEqual([{ event: "revoke", actor: BOB.email, sub: ALICE.sub }]);

    const warn = vi.spyOn(console, "warn");
    const refused = await call(await signed(alice, aliceToken), env);
    expect(refused.status).toBe(403);
    expect(logged(warn, "request refused").map((d) => d.reason)).toEqual(["key_revoked"]);

    // Revoking it again finds nothing active.
    const again = await call(await signed(bob, bobToken, { method: "POST", path: "/api/devices/revoke", body }), env);
    expect(again.status).toBe(404);
    expect((await call(await signed(bob, bobToken, { path: "/api/devices" }), env)).status).toBe(200);
  });

  it("needs a key and a reason, and logs the refusal", async () => {
    const warn = vi.spyOn(console, "warn");
    const revoke = async (body: string) => (await call(await signed(bob, bobToken, { method: "POST", path: "/api/devices/revoke", body }), env)).status;
    expect(await revoke(json({ keyId: bob.keyId }))).toBe(400);
    expect(await revoke(json({ reason: "x" }))).toBe(400);
    expect(await revoke("not json")).toBe(400);
    expect(logged(warn, "revoke refused").map((d) => d.reason)).toEqual(["bad_request", "bad_request", "bad_json"]);
    expect((await env.DB.prepare("SELECT revoked_at FROM app_keys WHERE key_id = ?").bind(bob.keyId).first<{ revoked_at: string | null }>())!.revoked_at).toBeNull();
  });

  it("lets a device revoke itself", async () => {
    const body = json({ keyId: bob.keyId, reason: "Sold the Mac" });
    expect((await call(await signed(bob, bobToken, { method: "POST", path: "/api/devices/revoke", body }), env)).status).toBe(200);
    expect((await call(await signed(bob, bobToken), env)).status).toBe(403);
  });
});

describe("the live socket", () => {
  it("needs a WebSocket upgrade", async () => {
    const res = await call(await signed(alice, aliceToken, { path: "/api/live" }), env);
    expect(res.status).toBe(426);
  });
});
