import type { Bindings } from "../types";
import { log } from "../log";
import { APPLE_APP_ATTEST_ROOT_DER } from "./appIntegrity/appleAppAttest";

/**
 * Tests attest against a CA they generate and hand it in here. It is a module
 * variable set from test code only, and it is honoured only when ENVIRONMENT
 * is exactly "test". Anywhere else Apple's pinned root is used and the attempt
 * is logged. No request, header or deployed var can set it.
 */
let testRoot: Uint8Array | null = null;

export function setAppAttestRootForTests(der: Uint8Array | null): void {
  testRoot = der;
}

/** The trust anchor for this Worker. */
export function attestRoot(env: Bindings): Uint8Array {
  if (testRoot) {
    if (env.ENVIRONMENT === "test") return testRoot;
    log("error", "app attest test root ignored", { reason: "test_root_outside_test", environment: env.ENVIRONMENT ?? null });
  }
  return APPLE_APP_ATTEST_ROOT_DER;
}
