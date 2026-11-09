import { DurableObject } from "cloudflare:workers";
import type { Bindings } from "../types";
import { log, serializeError } from "../log";

/**
 * The live hub. One instance holds every open app's socket and tells them all
 * which tables just changed. The message carries table names, never rows: each
 * app refetches through the signed API, so a socket that outlives its session
 * learns nothing it could not already see.
 *
 * Hibernatable sockets, so an idle hub costs nothing between messages.
 */
export class LiveHub extends DurableObject<Bindings> {
  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;

    if (path === "/connect") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected a WebSocket upgrade", { status: 426 });
      }
      const pair = new WebSocketPair();
      // Tagged with the App Attest key the gate admitted it under, so
      // revoking that key can close it. Untagged when no key admitted it.
      const key = request.headers.get(HUB_KEY_HEADER);
      this.ctx.acceptWebSocket(pair[1], key ? [key] : []);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    if (path === "/revoke" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as { keyId?: unknown } | null;
      const keyId = typeof body?.keyId === "string" ? body.keyId : "";
      if (!keyId) return Response.json({ error: "No key" }, { status: 400 });
      let closed = 0;
      for (const socket of this.ctx.getWebSockets(keyId)) {
        try {
          socket.close(4403, "Device revoked");
          closed++;
        } catch {
          // Already closing.
        }
      }
      return Response.json({ closed });
    }

    if (path === "/notify" && request.method === "POST") {
      const body = (await request.json().catch(() => null)) as { tables?: unknown } | null;
      const tables = Array.isArray(body?.tables) ? body.tables.filter((t): t is string => typeof t === "string") : [];
      if (tables.length === 0) return Response.json({ error: "No tables" }, { status: 400 });
      const message = JSON.stringify({ type: "changed", tables });
      let sent = 0;
      for (const socket of this.ctx.getWebSockets()) {
        try {
          socket.send(message);
          sent++;
        } catch {
          // A socket closing as we send; its close handler tidies it up.
        }
      }
      return Response.json({ sent });
    }

    return new Response("Not found", { status: 404 });
  }

  // The app never sends anything that matters; answering keeps a ping-based
  // keepalive from looking like a dead connection.
  async webSocketMessage(socket: WebSocket): Promise<void> {
    socket.send(JSON.stringify({ type: "pong" }));
  }
}

function hub(env: Bindings): DurableObjectStub<LiveHub> {
  return env.LIVE_HUB.get(env.LIVE_HUB.idFromName("hub"));
}

/** Internal: names the App Attest key a socket was admitted under. Never taken from the client. */
const HUB_KEY_HEADER = "X-Hub-Key";

/**
 * Hand a socket upgrade to the hub, tagged with the App Attest key the gate
 * admitted it under, if any. A client-sent copy of the tag header is dropped
 * first, so only the gate's word tags a socket.
 */
export function connectToHub(request: Request, env: Bindings, keyId?: string | null): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.delete(HUB_KEY_HEADER);
  if (keyId) headers.set(HUB_KEY_HEADER, keyId);
  return hub(env).fetch("https://hub/connect", { headers });
}

/**
 * Close every live socket admitted under this key. Never throws: the revoke is
 * already in the database, and the gate refuses the key's next request
 * whatever happens here.
 */
export async function revokeHubKey(env: Bindings, keyId: string): Promise<void> {
  try {
    const res = await hub(env).fetch("https://hub/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keyId }),
    });
    if (!res.ok) log("error", "hub revoke failed", { reason: "hub_status", status: res.status, keyRef: keyId.slice(0, 12) });
  } catch (error) {
    log("error", "hub revoke failed", { reason: "hub_unavailable", keyRef: keyId.slice(0, 12), error: serializeError(error) });
  }
}

/**
 * Tell every open app these tables changed. Never throws: a hub that is down
 * costs an app its live update, and must not cost anyone their write.
 */
export async function notifyTablesChanged(env: Bindings, tables: string[]): Promise<void> {
  if (tables.length === 0) return;
  try {
    const res = await hub(env).fetch("https://hub/notify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tables }),
    });
    if (!res.ok) log("warn", "hub notify refused", { reason: "hub_status", status: res.status, tables });
  } catch (error) {
    log("warn", "hub notify failed", { reason: "hub_unreachable", tables, error: serializeError(error) });
  }
}
