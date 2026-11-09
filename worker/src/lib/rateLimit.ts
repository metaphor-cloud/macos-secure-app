import type { Bindings } from "../types";
import { log } from "../log";
import { isDevEnvironment } from "./environment";

/**
 * The address a per-IP limit keys on. An IPv4 address is used as is. An IPv6
 * subscriber is handed at least a /64, so the full address would let one
 * caller rotate through 2^64 fresh allowances: IPv6 is cut to its first four
 * groups. A request without CF-Connecting-IP (only a direct call or a test)
 * shares one strict key.
 */
export function rateLimitIpKey(request: Request): string {
  const ip = request.headers.get("CF-Connecting-IP")?.trim().toLowerCase();
  if (!ip) {
    log("debug", "rate limit key without a client ip", { reason: "no_connecting_ip" });
    return "unknown";
  }
  if (!ip.includes(":")) return ip;
  const head = ip.split("::")[0].split(":").slice(0, 4);
  return `${head.join(":")}::/64`;
}

/**
 * Spends one unit of `purpose` for `key` and returns false, or returns true
 * when the key is already at `max` in this window. Off in development and
 * test. Counted in KV, which is not atomic: two requests at the same instant
 * can both pass, which is fine for a limit that exists to stop guessing.
 */
export async function overLimit(env: Bindings, purpose: string, key: string, max: number, hours: number): Promise<boolean> {
  if (isDevEnvironment(env)) return false;
  const window = Math.floor(Date.now() / (hours * 3_600_000));
  const kvKey = `rate:${purpose}:${key}:${window}`;
  const used = Number((await env.KV.get(kvKey)) ?? 0);
  if (used >= max) return true;
  await env.KV.put(kvKey, String(used + 1), { expirationTtl: hours * 3600 + 60 });
  return false;
}
