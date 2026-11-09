import { describe, expect, it } from "vitest";
import { APPLE_APP_ATTEST_ROOT_DER } from "../src/lib/appIntegrity/appleAppAttest";
import { parseCertificate } from "../src/lib/appIntegrity/der";
import { sha256, toHex } from "../src/lib/appIntegrity/bytes";

describe("Apple's pinned App Attest root", () => {
  it("is the certificate Apple publishes: the SHA-256 of its DER is the known value", async () => {
    expect(toHex(await sha256(APPLE_APP_ATTEST_ROOT_DER)).toUpperCase()).toBe("1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932");
  });

  it("is a P-384 certificate valid until 2045", () => {
    const cert = parseCertificate(APPLE_APP_ATTEST_ROOT_DER);
    expect(cert.curve).toBe("P-384");
    expect(cert.notAfter.getUTCFullYear()).toBe(2045);
  });
});
