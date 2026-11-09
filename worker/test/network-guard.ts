// Loaded before every test file (vitest.config.ts setupFiles). Tests never
// reach the real internet.
//
// Without this, a fetch a test forgot to mock goes out, fails, and the code
// under test swallows the failure, so the test passes whether or not it
// exercises what it claims to. Here any host is refused with the TypeError a
// dead network gives, and the test then fails naming every host it tried.
//
// Mocking is unchanged: `vi.spyOn(globalThis, "fetch").mockImplementation(...)`
// replaces this wrapper for that test, and restoring the spy puts it back.
import { afterEach } from "vitest";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const realFetch = globalThis.fetch;
let unmocked: string[] = [];

globalThis.fetch = async function guardedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const request = input instanceof Request ? input : null;
  const url = new URL(request ? request.url : String(input));
  if (LOCAL_HOSTS.has(url.hostname)) return realFetch(input, init);
  unmocked.push(`${(init?.method ?? request?.method ?? "GET").toUpperCase()} ${url.origin}${url.pathname}`);
  throw new TypeError(`network-guard: unmocked fetch to ${url.origin} refused in tests`);
} as typeof fetch;

/** Takes the refused fetches so far, so a test of the guard itself can expect one without failing. */
export function takeUnmockedFetches(): string[] {
  const calls = unmocked;
  unmocked = [];
  return calls;
}

afterEach(() => {
  const calls = takeUnmockedFetches();
  if (!calls.length) return;
  throw new Error(`${calls.length} unmocked fetch(es) during this test. Mock them with vi.spyOn(globalThis, "fetch"):\n  ${[...new Set(calls)].join("\n  ")}`);
});
