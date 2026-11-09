import type { Bindings } from "../types";
import { log, serializeError } from "../log";
import { apnsConfig, apnsTopic, sendApns, type ApnsEnvironment } from "./apns";

/**
 * Push notifications to enrolled Macs, through APNs direct (apns.ts).
 *
 * Lock-screen text should name no one and carry no business data: a push is a
 * hint to open the app, and the app fetches the detail over the signed API.
 * A push is a side effect: sendPush never throws, so the action that
 * triggered it cannot fail because of it.
 */

export const PUSH_TITLE = "Secure App";

/** What made the push, for the log line. */
export type PushEvent = "note_created" | "push_test";

export interface Push {
  event: PushEvent;
  body: string;
  /** Where a tap takes the app: a hash route in the SPA, e.g. #/notes. */
  path: string | null;
  /** The Dock badge, or null to leave it. */
  badge?: number | null;
  /** Do not send to this key (the device that caused the push). */
  exceptKeyId?: string;
  /** Identifiers for the log line. No personal data. */
  context?: Record<string, unknown>;
}

export interface PushOutcome {
  devices: number;
  sent: number;
  failed: number;
  pruned: number;
  /** Devices not sent to because APNs is not configured. */
  skipped: number;
}

interface TokenRow {
  key_id: string;
  token: string;
  apns_environment: ApnsEnvironment;
}

export interface PushTokenParams {
  keyId: string;
  sub: string;
  email: string;
  token: string;
  apnsEnvironment: ApnsEnvironment;
}

/** Stores this device's token against its key, replacing any it had. A token seen on another key moves here. */
export async function savePushToken(env: Bindings, params: PushTokenParams): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM push_tokens WHERE token = ? AND key_id != ?").bind(params.token, params.keyId),
    env.DB.prepare(
      `INSERT INTO push_tokens (key_id, token, sub, email, apns_environment) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (key_id) DO UPDATE SET token = excluded.token, sub = excluded.sub, email = excluded.email,
         apns_environment = excluded.apns_environment, updated_at = datetime('now')`,
    ).bind(params.keyId, params.token, params.sub, params.email.toLowerCase(), params.apnsEnvironment),
  ]);
}

/** Removes this key's token. True when it had one. */
export async function deletePushToken(env: Bindings, keyId: string): Promise<boolean> {
  const res = await env.DB.prepare("DELETE FROM push_tokens WHERE key_id = ?").bind(keyId).run();
  return res.meta.changes > 0;
}

/** Whether `keyId` has registered a token. */
export async function hasPushToken(env: Bindings, keyId: string): Promise<boolean> {
  return (await env.DB.prepare("SELECT 1 AS found FROM push_tokens WHERE key_id = ?").bind(keyId).first()) !== null;
}

const TOKEN_SELECT = `SELECT p.key_id, p.token, p.apns_environment FROM push_tokens p
   JOIN app_keys k ON k.key_id = p.key_id AND k.revoked_at IS NULL`;

/** Sends one push to every enrolled device with a token. */
export async function sendPush(env: Bindings, push: Push): Promise<PushOutcome> {
  return deliver(env, push, () => env.DB.prepare(TOKEN_SELECT).all<TokenRow>());
}

/** Sends one push to one device, the one holding `keyId`: the test notification. */
export async function sendPushToKey(env: Bindings, push: Push, keyId: string): Promise<PushOutcome> {
  return deliver(env, push, () => env.DB.prepare(`${TOKEN_SELECT} WHERE p.key_id = ?`).bind(keyId).all<TokenRow>());
}

async function deliver(env: Bindings, push: Push, select: () => Promise<D1Result<TokenRow>>): Promise<PushOutcome> {
  const outcome: PushOutcome = { devices: 0, sent: 0, failed: 0, pruned: 0, skipped: 0 };
  const base = { event: push.event, ...push.context };
  try {
    const targets = (await select()).results.filter((t) => t.key_id !== push.exceptKeyId);
    outcome.devices = targets.length;
    if (targets.length === 0) {
      log("debug", "push skipped", { ...base, reason: "no_devices" });
      return outcome;
    }
    const config = apnsConfig(env);
    if (!config) {
      outcome.skipped = targets.length;
      log("info", "push apns off", { ...base, reason: "apns_not_configured", devices: targets.length });
      return outcome;
    }
    const topic = apnsTopic((env.ATTEST_APP_ID ?? "").trim());
    const results = await Promise.all(
      targets.map(async (target) => ({
        target,
        result: await sendApns(config, topic, target.token, target.apns_environment, {
          title: PUSH_TITLE,
          body: push.body,
          badge: push.badge ?? null,
          threadId: push.path ?? push.event,
          path: push.path,
        }),
      })),
    );
    for (const { target, result } of results) {
      const keyRef = target.key_id.slice(0, 12);
      if (result.kind === "sent") {
        outcome.sent++;
        continue;
      }
      outcome.failed++;
      if (result.kind === "drop") {
        await env.DB.prepare("DELETE FROM push_tokens WHERE key_id = ? AND token = ?").bind(target.key_id, target.token).run();
        outcome.pruned++;
        log("info", "push token pruned", { ...base, reason: "apns_token_dead", apnsReason: result.reason, status: result.status, keyRef });
      } else {
        log("warn", "push not delivered", { ...base, reason: result.reason, status: result.status, keyRef, environment: target.apns_environment });
      }
    }
  } catch (error) {
    log("error", "push failed", { ...base, ...outcome, reason: "push_error", error: serializeError(error) });
    return outcome;
  }
  log(outcome.failed > 0 ? "warn" : "info", "push sent", { ...base, ...outcome, reason: outcome.failed > 0 ? "partial_failure" : "ok" });
  return outcome;
}
