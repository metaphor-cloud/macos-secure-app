import type { Bindings } from "../types";

/**
 * Whether this is a development or test deployment, where rate limits are off
 * and development App Attest keys are taken.
 *
 * Named on the allowed values rather than on "not production". ENVIRONMENT is
 * set outside the repo, so an unset or misspelled value is possible, and the
 * negative form would turn that typo into production running with its limits
 * off. This way a surprise value is treated as production.
 */
export function isDevEnvironment(env: Bindings): boolean {
  return env.ENVIRONMENT === "development" || env.ENVIRONMENT === "test";
}
