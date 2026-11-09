import { recordAttestEvent } from "../gate";
import { revokeHubKey } from "../lib/hub";
import { deletePushToken } from "../lib/push";
import { log } from "../log";
import type { Handler } from "../routes";

interface KeyRow {
  key_id: string;
  sub: string;
  email: string;
  app_id: string;
  device_label: string;
  environment: string;
  validation_category: number | null;
  bundle_version: string | null;
  mfa_required: number;
  mfa_acr: string | null;
  enrolled_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revoked_reason: string | null;
}

const MAX_REASON = 200;

/**
 * GET /api/devices: every enrolled device, newest first. The key id is the
 * hash of a public key, not a secret; the public key and receipt stay out.
 */
export const listDevices: Handler = async ({ env }) => {
  const rows = await env.DB.prepare(
    `SELECT key_id, sub, email, app_id, device_label, environment, validation_category, bundle_version,
            mfa_required, mfa_acr, enrolled_at, last_used_at, revoked_at, revoked_by, revoked_reason
       FROM app_keys ORDER BY enrolled_at DESC, key_id`,
  ).all<KeyRow>();
  return Response.json({
    keys: rows.results.map((r) => ({
      keyId: r.key_id,
      sub: r.sub,
      email: r.email,
      appId: r.app_id,
      deviceLabel: r.device_label,
      environment: r.environment,
      validationCategory: r.validation_category,
      bundleVersion: r.bundle_version,
      mfaRequired: r.mfa_required === 1,
      mfaAcr: r.mfa_acr,
      enrolledAt: r.enrolled_at,
      lastUsedAt: r.last_used_at,
      active: r.revoked_at === null,
      revokedAt: r.revoked_at,
      revokedBy: r.revoked_by,
      revokedReason: r.revoked_reason,
    })),
  });
};

/**
 * POST /api/devices/revoke {keyId, reason}. Anyone in the access group may
 * revoke any key: that is how a lost Mac or a leaver is cut off. The gate
 * refuses the key on its next request; its live socket is closed now.
 */
export const revokeDevice: Handler = async ({ request, env, identity }) => {
  let body: { keyId?: unknown; reason?: unknown };
  try {
    body = await request.json();
  } catch {
    log("warn", "revoke refused", { reason: "bad_json", keyRef: identity.keyId.slice(0, 12), actor: identity.email });
    return Response.json({ error: "Bad request" }, { status: 400 });
  }
  const keyId = typeof body.keyId === "string" ? body.keyId : "";
  const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, MAX_REASON) : "";
  if (!keyId || keyId.length > 128 || !reason) {
    log("warn", "revoke refused", { reason: "bad_request", keyRef: identity.keyId.slice(0, 12), actor: identity.email });
    return Response.json({ error: "A key and a reason are required" }, { status: 400 });
  }
  const revoked = await env.DB.prepare(
    `UPDATE app_keys SET revoked_at = datetime('now'), revoked_by = ?, revoked_reason = ?
      WHERE key_id = ? AND revoked_at IS NULL RETURNING sub`,
  ).bind(identity.email, reason, keyId).first<{ sub: string }>();
  if (!revoked) {
    log("warn", "revoke refused", { reason: "no_active_key", keyRef: keyId.slice(0, 12), actor: identity.email });
    return Response.json({ error: "No active device with that key" }, { status: 404 });
  }

  await recordAttestEvent(env, "revoke", { sub: revoked.sub, actor: identity.email, keyId, reason, path: "/api/devices/revoke" });
  log("info", "device revoked", { keyRef: keyId.slice(0, 12), sub: revoked.sub, actor: identity.email });
  await revokeHubKey(env, keyId);
  // A revoked device gets no more pushes.
  if (await deletePushToken(env, keyId)) log("info", "push token removed", { reason: "key_revoked", keyRef: keyId.slice(0, 12) });
  return Response.json({ ok: true });
};
