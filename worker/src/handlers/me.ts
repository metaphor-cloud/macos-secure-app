import type { Handler } from "../routes";

/** GET /api/me: who is signed in, and on which device. */
export const me: Handler = async ({ identity }) =>
  Response.json({ sub: identity.sub, email: identity.email, name: identity.name, keyId: identity.keyId });
