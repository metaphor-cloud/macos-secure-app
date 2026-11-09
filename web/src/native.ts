/**
 * The page's only way out: the bridge to the native shell
 * (shared/src/bridge.ts). Nothing here, or anywhere in the SPA, calls the
 * network. The shell adds the bearer token and the App Attest assertion.
 */
import {
  BRIDGE_HANDLER,
  BRIDGE_RECEIVER,
  type BridgeBody,
  type BridgeEvent,
  type BridgeReply,
  type BridgeRequest,
  type NavGroup,
} from "@secure-app/shared/bridge";

interface WebKitHandler {
  postMessage(message: BridgeRequest): Promise<BridgeReply>;
}

interface NativeWindow {
  webkit?: { messageHandlers?: Record<string, WebKitHandler | undefined> };
  [name: string]: unknown;
}

const nativeWindow = (): NativeWindow => window as unknown as NativeWindow;

/** Whether the page is running inside the Mac app. In a plain browser it is not, and nothing works. */
export function insideApp(): boolean {
  return nativeWindow().webkit?.messageHandlers?.[BRIDGE_HANDLER] !== undefined;
}

export async function send(request: BridgeRequest): Promise<BridgeReply> {
  const handler = nativeWindow().webkit?.messageHandlers?.[BRIDGE_HANDLER];
  if (!handler) throw new Error("not inside the app");
  return handler.postMessage(request);
}

export class RefusedError extends Error {
  constructor(public readonly reason: string) {
    super(`the app refused the request: ${reason}`);
    this.name = "RefusedError";
  }
}

export function decodeBody(body: BridgeBody): string {
  if (body.encoding === "text") return body.data;
  const binary = atob(body.data);
  return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

export interface ApiResult<T> {
  status: number;
  ok: boolean;
  data: T;
}

/** An API call through the bridge. JSON in, JSON out. A non-2xx is a result, not a throw. */
export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<ApiResult<T>> {
  const reply = await send({
    kind: "fetch",
    method,
    path,
    ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: { encoding: "text" as const, data: JSON.stringify(body) } }),
  });
  if (reply.kind === "refused") throw new RefusedError(reply.reason);
  if (reply.kind !== "fetch") throw new Error(`unexpected reply: ${reply.kind}`);
  const text = decodeBody(reply.body);
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text.slice(0, 200) };
  }
  return { status: reply.status, ok: reply.status >= 200 && reply.status < 300, data: data as T };
}

export interface Identity {
  email: string;
  name: string;
  sub: string;
  deviceLabel: string;
  keyId: string;
}

export async function identity(): Promise<Identity> {
  const reply = await send({ kind: "identity" });
  if (reply.kind !== "identity") throw new Error(`unexpected reply: ${reply.kind}`);
  return reply;
}

/** Fetch an API path natively and hand the file to the system (a save panel, or Preview). */
export async function openFile(path: string, suggestedName?: string): Promise<void> {
  const reply = await send({ kind: "open", path, ...(suggestedName ? { suggestedName } : {}) });
  if (reply.kind === "refused") throw new RefusedError(reply.reason);
}

export const setLive = (on: boolean) => send({ kind: "live", on });
export const signOut = () => send({ kind: "signOut" });

/** Tells the shell where this page is, for its window title and sidebar. */
export const reportPage = (path: string, title: string, badge: number, nav: NavGroup[]) => send({ kind: "page", path, title, badge, nav });

type Listener = (event: BridgeEvent) => void;
const listeners = new Set<Listener>();

/** Subscribes to events the shell pushes in. Returns the unsubscribe. */
export function onEvent(listener: Listener): () => void {
  listeners.add(listener);
  nativeWindow()[BRIDGE_RECEIVER] = { receive: (event: BridgeEvent) => listeners.forEach((l) => l(event)) };
  return () => void listeners.delete(listener);
}
