import { DEVICES_PATH, DEVICES_REVOKE_PATH, LIVE_PATH, ME_PATH, NOTES_PATH, PUSH_TEST_PATH, PUSH_TOKEN_PATH } from "@secure-app/shared/request";
import { listDevices, revokeDevice } from "./handlers/devices";
import { me } from "./handlers/me";
import { createNote, exportNote, listNotes } from "./handlers/notes";
import { deleteToken, registerToken, sendTest } from "./handlers/push";
import { connectToHub } from "./lib/hub";
import { notFound, type Identity } from "./gate";
import { log, serializeError } from "./log";
import type { Bindings } from "./types";

/** What a handler gets. The identity is the one the gate admitted. */
export interface RouteContext {
  request: Request;
  url: URL;
  env: Bindings;
  ctx: ExecutionContext;
  identity: Identity;
  params: Record<string, string>;
}

export type Handler = (rc: RouteContext) => Promise<Response>;

export interface Route {
  method: string;
  /** A path, with :name for one segment. */
  pattern: string;
  handler: Handler;
}

/** Every route the app serves. Add yours here: the gate already covers anything under /api. */
export const routes: Route[] = [
  { method: "GET", pattern: ME_PATH, handler: me },
  { method: "GET", pattern: DEVICES_PATH, handler: listDevices },
  { method: "POST", pattern: DEVICES_REVOKE_PATH, handler: revokeDevice },
  { method: "POST", pattern: PUSH_TOKEN_PATH, handler: registerToken },
  { method: "DELETE", pattern: PUSH_TOKEN_PATH, handler: deleteToken },
  { method: "POST", pattern: PUSH_TEST_PATH, handler: sendTest },
  { method: "GET", pattern: LIVE_PATH, handler: ({ request, env, identity }) => connectToHub(request, env, identity.keyId) },
  { method: "GET", pattern: NOTES_PATH, handler: listNotes },
  { method: "POST", pattern: NOTES_PATH, handler: createNote },
  { method: "GET", pattern: `${NOTES_PATH}/:id/export`, handler: exportNote },
];

function match(pattern: string, pathname: string): Record<string, string> | null {
  const want = pattern.split("/");
  const have = pathname.split("/");
  if (want.length !== have.length) return null;
  const params: Record<string, string> = {};
  for (const [i, part] of want.entries()) {
    if (part.startsWith(":")) {
      if (have[i] === "") return null;
      params[part.slice(1)] = decodeURIComponent(have[i]);
    } else if (part !== have[i]) {
      return null;
    }
  }
  return params;
}

/** Dispatches an admitted request. A path no route has is a 404, a method it does not take a 405. */
export async function route(rc: Omit<RouteContext, "params">): Promise<Response> {
  const { request, url } = rc;
  let pathMatched = false;
  for (const r of routes) {
    const params = safeMatch(r.pattern, url.pathname);
    if (!params) continue;
    pathMatched = true;
    if (r.method !== request.method) continue;
    try {
      return await r.handler({ ...rc, params });
    } catch (error) {
      log("error", "handler failed", { reason: "handler_error", path: url.pathname, method: request.method, keyRef: rc.identity.keyId.slice(0, 12), error: serializeError(error) });
      return Response.json({ error: "Something went wrong" }, { status: 500 });
    }
  }
  log("warn", "route not served", { reason: pathMatched ? "method_not_allowed" : "no_route", path: url.pathname, method: request.method });
  return pathMatched ? Response.json({ error: "Method not allowed" }, { status: 405 }) : notFound();
}

/** A malformed percent escape in a path is a path no route has. */
function safeMatch(pattern: string, pathname: string): Record<string, string> | null {
  try {
    return match(pattern, pathname);
  } catch {
    return null;
  }
}
