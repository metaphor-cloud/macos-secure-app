import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BridgeReply, BridgeRequest } from "@secure-app/shared/bridge";

// The SPA's only way out is the bridge. These check what it sends and how it reads the replies.

const posted: BridgeRequest[] = [];
let reply: BridgeReply = { kind: "ok" };

beforeEach(() => {
  posted.length = 0;
  reply = { kind: "ok" };
  vi.stubGlobal("window", {
    webkit: { messageHandlers: { secureApp: { postMessage: async (m: BridgeRequest) => (posted.push(m), reply) } } },
  });
});

afterEach(() => vi.unstubAllGlobals());

describe("the bridge client", () => {
  it("knows when it is inside the app", async () => {
    const { insideApp } = await import("./native");
    expect(insideApp()).toBe(true);
    vi.stubGlobal("window", {});
    expect(insideApp()).toBe(false);
  });

  it("sends a JSON call as a text body with a content type, and a GET with neither", async () => {
    const { api } = await import("./native");
    reply = { kind: "fetch", status: 201, headers: {}, body: { encoding: "text", data: '{"ok":true}' } };
    const res = await api("POST", "/api/notes", { title: "Hi" });
    expect(res).toEqual({ status: 201, ok: true, data: { ok: true } });
    expect(posted[0]).toEqual({
      kind: "fetch",
      method: "POST",
      path: "/api/notes",
      headers: { "Content-Type": "application/json" },
      body: { encoding: "text", data: '{"title":"Hi"}' },
    });
    await api("GET", "/api/notes");
    expect(posted[1]).toEqual({ kind: "fetch", method: "GET", path: "/api/notes" });
  });

  it("returns a non-2xx as a result and reads a base64 body", async () => {
    const { api } = await import("./native");
    reply = { kind: "fetch", status: 404, headers: {}, body: { encoding: "base64", data: btoa('{"error":"No note"}') } };
    expect(await api("GET", "/api/notes/x/export")).toEqual({ status: 404, ok: false, data: { error: "No note" } });
  });

  it("keeps a body that is not JSON as an error message", async () => {
    const { api } = await import("./native");
    reply = { kind: "fetch", status: 502, headers: {}, body: { encoding: "text", data: "bad gateway" } };
    expect((await api("GET", "/api/me")).data).toEqual({ error: "bad gateway" });
  });

  it("throws when the shell refuses the request itself", async () => {
    const { api, RefusedError } = await import("./native");
    reply = { kind: "refused", reason: "path_not_allowed" };
    await expect(api("GET", "/elsewhere")).rejects.toBeInstanceOf(RefusedError);
  });

  it("asks the shell to open a download, with a suggested name", async () => {
    const { openFile } = await import("./native");
    await openFile("/api/notes/abc/export", "note-abc.md");
    expect(posted[0]).toEqual({ kind: "open", path: "/api/notes/abc/export", suggestedName: "note-abc.md" });
  });

  it("receives events the shell pushes in, until unsubscribed", async () => {
    const { onEvent } = await import("./native");
    const seen: unknown[] = [];
    const off = onEvent((e) => seen.push(e));
    const receiver = (window as unknown as Record<string, { receive(e: unknown): void }>).__secureAppNative;
    receiver.receive({ type: "liveState", connected: true });
    off();
    receiver.receive({ type: "liveState", connected: false });
    expect(seen).toEqual([{ type: "liveState", connected: true }]);
  });
});
