import { describe, it, expect } from "vitest";
import wrangler from "../wrangler.jsonc?raw";
import gateSource from "../src/gate.ts?raw";
import verifierSource from "../src/lib/appIntegrity/appAttest.ts?raw";
import contract from "../../docs/CONTRACT.md?raw";

// What the deployed config may say about the gate. wrangler.jsonc is the
// production Worker's config (ENVIRONMENT is set outside the repo), so these
// hold for production.

/** A var's value as written in wrangler.jsonc outside comments, or null when it is not there. */
function wranglerVar(name: string): string | null {
  const code = wrangler.replace(/^\s*\/\/.*$/gm, "");
  const m = code.match(new RegExp(`"${name}"\\s*:\\s*"([^"]*)"`));
  return m ? m[1] : null;
}

describe("production config for the gate", () => {
  it("has no mode setting: the gate is always on", () => {
    expect(wrangler).not.toMatch(/ATTEST_MODE|ATTEST_ENFORCE|ATTEST_DISABLED|BYPASS|BREAK_GLASS/i);
    expect(gateSource).not.toMatch(/ATTEST_MODE|attestMode|"report"|bypass|skipAttest|allowlist|break.?glass/i);
  });

  it("names the app, and MFA as required or deliberately off", () => {
    expect(wranglerVar("ATTEST_APP_ID")).toBe("TEAMID1234.com.example.secureapp");
    expect(contract).toContain("`TEAMID1234.com.example.secureapp`");
    expect(["required", "off"]).toContain(wranglerVar("ATTEST_MFA"));
    // The accepted acr list is unset (urn:acr:mfa only) or never names a single-factor value.
    const acrs = wranglerVar("ATTEST_MFA_ACR");
    if (acrs !== null) for (const acr of acrs.split(",").map((v) => v.trim()).filter(Boolean)) expect(acr).not.toMatch(/1fa/);
  });

  it("sets nothing that widens what attestations are accepted", () => {
    // No test trust root and no development environment in the deployed vars.
    expect(wrangler).not.toMatch(/"[A-Z_]*(TEST_ROOT|ATTEST_ROOT|ROOT_CA)[A-Z_]*"\s*:/);
    expect(wranglerVar("ENVIRONMENT")).toBeNull();
  });

  it("enables structured logs in the Workers Logs dashboard", () => {
    expect(wrangler).toMatch(/"observability"\s*:\s*\{\s*"enabled"\s*:\s*true,\s*"logs"\s*:\s*\{\s*"enabled"\s*:\s*true/);
  });

  it("keeps secrets out of wrangler.jsonc", () => {
    for (const name of ["APNS_KEY_P8", "APNS_KEY_ID", "APNS_TEAM_ID"]) expect(wranglerVar(name)).toBeNull();
  });

  it("has no bypass: the gate and the verifier read only their own settings", () => {
    const read = (src: string) => new Set([...src.matchAll(/\benv\.([A-Z_]+)/g)].map((m) => m[1]));
    expect([...read(gateSource)].sort()).toEqual(
      ["ATTEST_APP_ID", "ATTEST_MFA", "ATTEST_MFA_ACR", "ATTEST_MIN_BUNDLE_VERSION", "ATTEST_REQUIRE_EXTENSIONS", "DB"].sort(),
    );
    expect([...read(verifierSource)]).toEqual([]);
  });
});
