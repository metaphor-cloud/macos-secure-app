import { PUSH_TITLE, deletePushToken, hasPushToken, savePushToken, sendPushToKey } from "../lib/push";
import { apnsConfig, isApnsDeviceToken, isApnsEnvironment } from "../lib/apns";
import { log } from "../log";
import type { Handler } from "../routes";

/**
 * POST /api/push/token {token, environment}: this Mac's APNs device token and
 * the APNs environment it works on, stored against the key that signed the
 * request. The key is the one the gate admitted, never one named in the body.
 */
export const registerToken: Handler = async ({ request, env, identity }) => {
  const keyRef = identity.keyId.slice(0, 12);
  let body: { token?: unknown; environment?: unknown };
  try {
    body = await request.json();
  } catch {
    log("warn", "push token refused", { reason: "bad_json", keyRef, sub: identity.sub });
    return Response.json({ error: "Bad request" }, { status: 400 });
  }
  if (!isApnsDeviceToken(body.token) || !isApnsEnvironment(body.environment)) {
    log("warn", "push token refused", { reason: "bad_apns_token", keyRef, sub: identity.sub });
    return Response.json({ error: "Not an APNs device token and environment" }, { status: 400 });
  }
  await savePushToken(env, { keyId: identity.keyId, sub: identity.sub, email: identity.email, token: body.token, apnsEnvironment: body.environment });
  log("info", "push token registered", { keyRef, sub: identity.sub, environment: body.environment });
  return Response.json({ ok: true });
};

/** DELETE /api/push/token: removes this device's token, on sign-out. */
export const deleteToken: Handler = async ({ env, identity }) => {
  const removed = await deletePushToken(env, identity.keyId);
  log("info", "push token removed", { reason: "signed_out", keyRef: identity.keyId.slice(0, 12), sub: identity.sub, had: removed });
  return Response.json({ ok: true });
};

/** POST /api/push/test: a test notification to the device that asks, so delivery can be checked once the APNs key is set. */
export const sendTest: Handler = async ({ env, identity }) => {
  const keyRef = identity.keyId.slice(0, 12);
  if (!(await hasPushToken(env, identity.keyId))) {
    log("warn", "push test refused", { reason: "no_token", keyRef, sub: identity.sub });
    return Response.json({ error: "This device has not registered for notifications" }, { status: 409 });
  }
  if (!apnsConfig(env)) {
    log("warn", "push test refused", { reason: "apns_not_configured", keyRef, sub: identity.sub });
    return Response.json(
      { error: "Notifications are off: APNS_KEY_P8, APNS_KEY_ID and APNS_TEAM_ID are not all set on the Worker" },
      { status: 503 },
    );
  }
  const outcome = await sendPushToKey(
    env,
    { event: "push_test", body: "Test notification. Push is working on this device.", path: null, context: { keyRef } },
    identity.keyId,
  );
  if (outcome.sent === 1) return Response.json({ ok: true, title: PUSH_TITLE });
  if (outcome.pruned === 1) {
    return Response.json(
      { error: "The push service says this device's token is no longer valid, so it was removed. Quit and reopen the app to register again." },
      { status: 410 },
    );
  }
  return Response.json({ error: "Not delivered. The Worker log has the reason." }, { status: 502 });
};
