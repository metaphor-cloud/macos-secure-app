import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from "vitest";
import { setupDatabase, cleanDatabase } from "./setup";
import { setAppAttestRootForTests } from "../src/lib/trustRoot";
import { routes } from "../src/routes";
import { makeTestCa, type TestCa } from "./helpers/appAttestFixture";
import { ALICE, BOB, IdentityStub, ORIGIN, appEnv, bearer, call, enrol, signed, type EnrolledDevice } from "./helpers/attestKit";
import type { Bindings } from "../src/types";

/**
 * Deny by default, proved over the route table and the source rather than a
 * hand list.
 *
 * 1. Route sweep. Every route in routes.ts becomes a concrete request, sent
 *    with (a) nothing, (b) a valid bearer token without an assertion, and
 *    (c) a valid token with an assertion from another person's key. Every one
 *    must be refused and must not reach a handler: the only D1 statement
 *    allowed is the gate's own key lookup.
 * 2. Who may judge credentials. Only gate.ts may call the verifiers, and
 *    index.ts must call the gate before the router.
 *
 * Self-tests feed the scanner a made-up caller and check it fails, so this
 * cannot pass by scanning nothing.
 */

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

/** The env with every D1 statement recorded. */
function watched(env: Bindings): { env: Bindings; sql: string[] } {
  const sql: string[] = [];
  const db = new Proxy(env.DB, {
    get(target, prop) {
      if (prop === "prepare") return (q: string) => (sql.push(q), target.prepare(q));
      if (prop === "batch") return (...args: unknown[]) => (sql.push("BATCH"), (target.batch as (...a: unknown[]) => unknown)(...args));
      const value = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { env: { ...env, DB: db } as Bindings, sql };
}

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const exampleOf = (pattern: string) => pattern.replace(/:[a-z]+/gi, "abc");
const GATE_LOOKUP = /FROM app_keys WHERE key_id/;

describe("every route", () => {
  it("is refused to anyone but an attested request from the token's own device, before any handler runs", async () => {
    const base = appEnv();
    const alicesDevice: EnrolledDevice = await enrol(ca, id, ALICE);
    const bobToken = await id.accessToken(BOB, base);
    const paths = [...new Set(routes.map((r) => exampleOf(r.pattern)))];
    expect(paths.length).toBeGreaterThanOrEqual(8);

    const failures: string[] = [];
    let sent = 0;
    for (const path of paths) {
      for (const method of METHODS) {
        const body = method === "GET" || method === "DELETE" ? undefined : "{}";
        const credentials: [string, () => Promise<Request>][] = [
          ["nothing", async () => new Request(`${ORIGIN}${path}`, { method, body })],
          ["bearer only", async () => new Request(`${ORIGIN}${path}`, { method, body, headers: bearer(bobToken) })],
        ];
        if (method === "GET" || method === "POST") credentials.push(["another person's key", () => signed(alicesDevice, bobToken, { method, path, body })]);
        for (const [what, make] of credentials) {
          const { env, sql } = watched(base);
          const res = await call(await make(), env);
          sent++;
          const text = await res.text();
          // A signed request is the app, which gets the gate's 403; anything
          // else gets the Worker's 404 for a path it doesn't have.
          const refused =
            what === "another person's key"
              ? res.status === 403 && text.includes("needs the app on an enrolled device")
              : res.status === 404 && text === JSON.stringify({ error: "Not found" });
          const handlerSql = sql.filter((q) => !GATE_LOOKUP.test(q));
          if (!refused || handlerSql.length) {
            failures.push(`${method} ${path} with ${what}: ${res.status}${handlerSql.length ? `, ran ${handlerSql[0].slice(0, 60)}` : ""}`);
          }
        }
      }
    }
    expect(failures).toEqual([]);
    expect(sent).toBe(paths.length * (METHODS.length * 2 + 2));
    // Bob's token with Alice's key moved no counter.
    const row = await base.DB.prepare("SELECT counter FROM app_keys WHERE key_id = ?").bind(alicesDevice.keyId).first<{ counter: number }>();
    expect(row!.counter).toBe(0);
  }, 120_000);
});

const sources = import.meta.glob(["../src/**/*.ts"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
const files: Record<string, string> = Object.fromEntries(Object.entries(sources).map(([k, v]) => [k.replace(/^\.\.\/src\//, ""), v]));

/** Files that call a credential verifier, outside the verifiers' own files. */
function verifierCallers(src: Record<string, string>): string[] {
  return Object.entries(src)
    .filter(([file]) => !["lib/bearer.ts", "lib/oidc.ts", "lib/appIntegrity/appAttest.ts", "lib/appIntegrity/appleAppAttest.ts"].includes(file))
    .filter(([, text]) => /\b(verifyBearer|verifyIdToken|verifyMacAssertion|verifyMacAttestation|checkUserinfo)\s*\(/.test(text))
    .map(([file]) => file)
    .sort();
}

/** Files that call the router, other than its own. */
function routerCallers(src: Record<string, string>): string[] {
  return Object.entries(src)
    .filter(([file]) => file !== "routes.ts")
    .filter(([, text]) => /\broute\s*\(/.test(text))
    .map(([file]) => file)
    .sort();
}

describe("who may judge credentials", () => {
  it("reads the real source", () => {
    expect(Object.keys(files)).toEqual(expect.arrayContaining(["gate.ts", "index.ts", "routes.ts", "lib/bearer.ts"]));
  });

  it("is the gate alone: no handler or route verifies a token or assertion itself", () => {
    expect(verifierCallers(files)).toEqual(["gate.ts"]);
  });

  it("reaches the router only through index.ts, after the gate", () => {
    expect(routerCallers(files)).toEqual(["index.ts"]);
    const index = files["index.ts"];
    expect(index.indexOf("gate(")).toBeGreaterThan(-1);
    expect(index.indexOf("gate(")).toBeLessThan(index.indexOf("route("));
  });

  it("fails a made-up handler that checks credentials itself, or a second way into the router", () => {
    expect(verifierCallers({ ...files, "handlers/sneaky.ts": "const s = await verifyBearer(token, env);" })).toEqual(["gate.ts", "handlers/sneaky.ts"]);
    expect(routerCallers({ ...files, "other.ts": "return route({ request });" })).toEqual(["index.ts", "other.ts"]);
  });
});
