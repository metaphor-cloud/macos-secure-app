/**
 * The contract between the bundled web app and the native Mac shell.
 *
 * The SPA is bundled inside the Mac app and never talks to the network
 * itself. Every API call goes to native code through one WebKit message
 * handler, which adds the bearer token and an App Attest assertion
 * (request.ts) and performs the request with URLSession. The bridge carries
 * only API paths and allow-listed headers, so a page compromised by injected
 * content can reach nothing the API does not already gate.
 *
 * The Swift side mirrors these names and shapes; change both together.
 */

/** window.webkit.messageHandlers[BRIDGE_HANDLER].postMessage(request) resolves with the reply (WKScriptMessageHandlerWithReply). */
export const BRIDGE_HANDLER = "secureApp";

/** Native calls window[BRIDGE_RECEIVER].receive(event) to push events into the page. */
export const BRIDGE_RECEIVER = "__secureAppNative";

/**
 * Custom URL scheme the native shell serves for direct loads the page cannot
 * route through fetch: iframe src, download links, attachments and images.
 * `secureapp-native:///api/...` is fetched and signed natively.
 */
export const NATIVE_SCHEME = "secureapp-native";

/** Request headers the page may set. Anything else is dropped by native code. */
export const BRIDGE_REQUEST_HEADERS = ["Content-Type", "Accept"] as const;

/** Response headers native code hands back to the page. */
export const BRIDGE_RESPONSE_HEADERS = ["Content-Type", "Content-Disposition", "Retry-After"] as const;

/** Bodies over this size are refused by the bridge. */
export const BRIDGE_MAX_BODY_BYTES = 25 * 1024 * 1024;

/** The longest unread or badge count a "page" message carries; the shell shows more as 99+. */
export const PAGE_BADGE_MAX = 100_000;

export type BridgeBody = { encoding: "text"; data: string } | { encoding: "base64"; data: string };

/** One entry in the shell's sidebar. `path` is a hash route in the SPA, e.g. "#/notes". */
export interface NavItem {
  title: string;
  path: string;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

export type BridgeRequest =
  /** An API call: method, path with query, allow-listed headers and an optional body. */
  | { kind: "fetch"; method: string; path: string; headers?: Record<string, string>; body?: BridgeBody }
  /** Who is signed in to the shell. */
  | { kind: "identity" }
  /** End the session on this Mac and return to the sign-in screen. */
  | { kind: "signOut" }
  /** Start or stop the native live socket; changes arrive as "live" events. */
  | { kind: "live"; on: boolean }
  /** Fetch an API path natively and hand it to the system (save a download, open a PDF in Preview). */
  | { kind: "open"; path: string; suggestedName?: string }
  /**
   * Where this tab is, for the shell's window title and sidebar: its hash
   * route, title, a badge count and the nav list. Sent on every route, title
   * or count change.
   */
  | { kind: "page"; path: string; title: string; badge: number; nav: NavGroup[] };

export type BridgeReply =
  | { kind: "fetch"; status: number; headers: Record<string, string>; body: BridgeBody }
  /**
   * `keyId` is this Mac's enrolled App Attest key id, exactly as sent to
   * /api/attest/register, so the device list can mark "this Mac". It is a
   * hash of a public key, not a secret.
   */
  | { kind: "identity"; email: string; name: string; sub: string; deviceLabel: string; keyId: string }
  | { kind: "ok" }
  /** The bridge refused the request itself (bad path, header or size); `reason` is a code, never request content. */
  | { kind: "refused"; reason: string };

export type BridgeEvent =
  /** The live socket's message, as the hub sends it. */
  | { type: "live"; data: unknown }
  /** The live socket is up or down, for the page's connection indicator. */
  | { type: "liveState"; connected: boolean }
  /** The shell locked (inactivity) or signed out; the page should drop sensitive state. */
  | { type: "session"; state: "locked" | "unlocked" | "signedOut" };

/**
 * API paths the bridge carries. Enrolment and session paths (/api/attest/*)
 * and the live socket are native-only and never come from the page.
 */
export function isBridgedApiPath(path: string): boolean {
  if (typeof path !== "string" || !path.startsWith("/")) return false;
  const [pathname] = path.split("?");
  // A path that tries to climb out of its prefix is refused even if it starts right.
  if (pathname.includes("..") || pathname.includes("//") || /%2e|%2f/i.test(pathname)) return false;
  if (!pathname.startsWith("/api/")) return false;
  if (pathname === "/api/attest" || pathname.startsWith("/api/attest/")) return false;
  if (pathname === "/api/live") return false;
  return true;
}
