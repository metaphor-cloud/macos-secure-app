import { describe, it, expect, beforeAll } from "vitest";
import { decodePartialCBOR, encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import {
  MACOS_ACL_BLOB_BASE64,
  PRODUCTION_CATEGORIES,
  bundleVersionAtLeast,
  verifyMacAssertion,
  verifyMacAttestation,
  type AttestPolicy,
} from "../src/lib/appIntegrity/appAttest";
import { AppAttestError } from "../src/lib/appIntegrity/appleAppAttest";
import { readTlv } from "../src/lib/appIntegrity/der";
import { fromBase64, sha256, toBase64 } from "../src/lib/appIntegrity/bytes";
import { AAGUID_DEVELOPMENT, assertion, attest, makeTestCa, type AttestOptions, type TestCa } from "./helpers/appAttestFixture";
import { APP_ID, MACOS_ACL_BLOB, appleExtensions, categoryBytes } from "./helpers/attestKit";

// The macOS verifier. Real ECDSA over real DER and CBOR, from a CA made for
// this suite. Apple's published sample attestation is not used; every branch
// is covered synthetically instead.

let ca: TestCa;
beforeAll(async () => {
  ca = await makeTestCa();
});

function policy(overrides: Partial<AttestPolicy> = {}): AttestPolicy {
  return {
    appId: APP_ID,
    allowedEnvironments: ["production"],
    allowedCategories: PRODUCTION_CATEGORIES,
    requireExtensions: false,
    minBundleVersion: null,
    ...overrides,
  };
}

/** An attestation from a Mac: Apple's aclBlob, and the extensions unless the test says otherwise. */
async function attestation(opts: AttestOptions, challenge = "challenge-0123456789") {
  const device = await attest(ca, challenge, { appId: APP_ID, aclBlob: MACOS_ACL_BLOB, ...opts });
  return { device, input: { attestation: fromBase64(device.attestation), keyId: device.keyId, challenge, root: ca.root.der } };
}

async function reason(promise: Promise<unknown>): Promise<string | null> {
  try {
    await promise;
    return null;
  } catch (error) {
    if (error instanceof AppAttestError) return error.reason;
    throw error;
  }
}

describe("Apple's attestation steps", () => {
  it("accepts a Mac key with no extensions (macOS 27.0 sends none) and records none", async () => {
    const { device, input } = await attestation({});
    const key = await verifyMacAttestation({ ...input, policy: policy() });
    expect(key).toMatchObject({ environment: "production", validationCategory: null, bundleVersion: null });
    const spki = new Uint8Array((await crypto.subtle.exportKey("spki", device.keys.publicKey)) as ArrayBuffer);
    expect(toBase64(key.publicKeySpki)).toBe(toBase64(spki));
  });

  it("reads the validation category and bundle version from the extensions", async () => {
    const { input } = await attestation({ extensions: appleExtensions(2, "4.1.0") });
    expect(await verifyMacAttestation({ ...input, policy: policy() })).toMatchObject({ validationCategory: 2, bundleVersion: "4.1.0" });
  });

  it("takes TestFlight (2) and App Store, the Custom App, (4) builds only on a production policy", async () => {
    for (const category of [0, 1, 3, 5, 6, 7, 10]) {
      const { input } = await attestation({ extensions: appleExtensions(category) });
      expect(await reason(verifyMacAttestation({ ...input, policy: policy() })), String(category)).toBe("validation_category_not_allowed");
    }
    for (const category of [2, 4]) {
      const { input } = await attestation({ extensions: appleExtensions(category) });
      expect(await reason(verifyMacAttestation({ ...input, policy: policy() })), String(category)).toBeNull();
    }
  });

  it("takes a development-signed build only where the policy allows category 3 and the development AAGUID", async () => {
    const { input } = await attestation({ extensions: appleExtensions(3), aaguid: AAGUID_DEVELOPMENT });
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("aaguid_not_allowed");
    const dev = policy({ allowedEnvironments: ["production", "development"], allowedCategories: [...PRODUCTION_CATEGORIES, 3] });
    expect(await verifyMacAttestation({ ...input, policy: dev })).toMatchObject({ environment: "development", validationCategory: 3 });
  });

  it("refuses a key without the extensions when the policy requires them", async () => {
    const { input } = await attestation({});
    const error = await verifyMacAttestation({ ...input, policy: policy({ requireExtensions: true }) }).catch((e: unknown) => e);
    expect((error as AppAttestError).reason).toBe("extensions_missing");
    expect((error as AppAttestError).detail).toEqual({ hasCategory: "false", hasBundleVersion: "false" });
    const half = await attestation({ extensions: new Map<string, CBORType>([["apple_validation_category_01", categoryBytes(2)]]) });
    expect(await reason(verifyMacAttestation({ ...half.input, policy: policy({ requireExtensions: true }) }))).toBe("extensions_missing");
  });

  it("refuses a bundle version below the minimum, and takes one at or above it", async () => {
    const old = await attestation({ extensions: appleExtensions(2, "1.9") });
    expect(await reason(verifyMacAttestation({ ...old.input, policy: policy({ minBundleVersion: "1.10" }) }))).toBe("bundle_version_too_old");
    const ok = await attestation({ extensions: appleExtensions(2, "1.10") });
    expect(await reason(verifyMacAttestation({ ...ok.input, policy: policy({ minBundleVersion: "1.10" }) }))).toBeNull();
  });

  it("refuses extensions of the wrong shape rather than guessing", async () => {
    const asText = await attestation({ extensions: new Map<string, CBORType>([["apple_validation_category_01", "2"]]) });
    expect(await reason(verifyMacAttestation({ ...asText.input, policy: policy() }))).toBe("extensions_malformed");
    const asInteger = await attestation({ extensions: new Map<string, CBORType>([["apple_validation_category_01", 2]]) });
    expect(await reason(verifyMacAttestation({ ...asInteger.input, policy: policy() }))).toBe("extensions_malformed");
    const version = await attestation({ extensions: new Map<string, CBORType>([["apple_bundle_version_01", 1]]) });
    expect(await reason(verifyMacAttestation({ ...version.input, policy: policy() }))).toBe("extensions_malformed");
  });

  it("reads the extensions a TestFlight build sent", async () => {
    const sent = fromBase64("ondhcHBsZV9idW5kbGVfdmVyc2lvbl8wMWIyMngcYXBwbGVfdmFsaWRhdGlvbl9jYXRlZ29yeV8wMUQCAAAA");
    const { input } = await attestation({ extensions: decodePartialCBOR(sent, 0)[0] as Map<string, CBORType> });
    expect(await verifyMacAttestation({ ...input, policy: policy() })).toMatchObject({ validationCategory: 2, bundleVersion: "22" });
  });

  it("puts malformed extensions in the error, for the refusal log", async () => {
    const extensions = new Map<string, CBORType>([["apple_validation_category_01", "2"]]);
    const { input } = await attestation({ extensions });
    const error = await verifyMacAttestation({ ...input, policy: policy() }).catch((e: unknown) => e);
    const encoded = encodeCBOR(extensions);
    expect((error as AppAttestError).detail).toEqual({ extensions: toBase64(encoded), extensionsLength: encoded.length });
  });

  it("refuses bytes after the authenticator data", async () => {
    const { input } = await attestation({ trailing: new Uint8Array([0]) });
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("attestation_malformed");
  });

  it("refuses an attestation for another App ID (the RP ID hash)", async () => {
    const { input } = await attestation({ appId: "TEAMID1234.com.example.other" });
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("rp_id_mismatch");
  });

  it("refuses a chain that does not reach the pinned root, and an expired certificate", async () => {
    const other = await makeTestCa("Another Root");
    const stranger = await attest(other, "c", { appId: APP_ID, aclBlob: MACOS_ACL_BLOB });
    expect(
      await reason(verifyMacAttestation({ attestation: fromBase64(stranger.attestation), keyId: stranger.keyId, challenge: "c", root: ca.root.der, policy: policy() })),
    ).toBe("chain_invalid");
    const { input } = await attestation({ leafNotBefore: new Date(Date.now() - 3 * 86_400_000), leafNotAfter: new Date(Date.now() - 86_400_000) });
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("chain_expired");
  });

  it("refuses the wrong challenge (nonce), the wrong key id, and a non-zero counter", async () => {
    const { input } = await attestation({});
    expect(await reason(verifyMacAttestation({ ...input, challenge: "another", policy: policy() }))).toBe("nonce_mismatch");
    const wrongKey = await attestation({ reportedKeyId: toBase64(await sha256("not the key")) });
    expect(await reason(verifyMacAttestation({ ...wrongKey.input, policy: policy() }))).toBe("key_id_mismatch");
    const counted = await attestation({ counter: 1 });
    expect(await reason(verifyMacAttestation({ ...counted.input, policy: policy() }))).toBe("counter_not_zero");
  });
});

describe("the macOS access policy (aclBlob)", () => {
  it("is Apple's fixed aclBlob, a whole DER SEQUENCE", () => {
    const tlv = readTlv(fromBase64(MACOS_ACL_BLOB_BASE64));
    expect(tlv.tag).toBe(0x30);
    expect(tlv.raw.length).toBe(fromBase64(MACOS_ACL_BLOB_BASE64).length);
  });

  it("refuses a key whose certificate carries no aclBlob: that is not a Mac", async () => {
    const device = await attest(ca, "c", { appId: APP_ID, extensions: appleExtensions(4) });
    const input = { attestation: fromBase64(device.attestation), keyId: device.keyId, challenge: "c", root: ca.root.der };
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("acl_blob_missing");
  });

  it("refuses the policy an iPhone sends", async () => {
    const sent = fromBase64("MEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwCb2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/");
    const { input } = await attestation({ aclBlob: sent, aclBlobRaw: true, extensions: appleExtensions(2, "22") });
    expect(await reason(verifyMacAttestation({ ...input, policy: policy() }))).toBe("acl_blob_mismatch");
  });

  it("refuses a policy outside Apple's wrapping, even the macOS one", async () => {
    const bare = await attestation({ aclBlob: MACOS_ACL_BLOB, aclBlobRaw: true, extensions: appleExtensions(4) });
    expect(await reason(verifyMacAttestation({ ...bare.input, policy: policy() }))).toBe("acl_blob_mismatch");
  });

  it("refuses any other aclBlob", async () => {
    const altered = MACOS_ACL_BLOB.slice();
    altered[altered.length - 1] ^= 1;
    const wrong = await attestation({ aclBlob: altered, extensions: appleExtensions(4) });
    expect(await reason(verifyMacAttestation({ ...wrong.input, policy: policy() }))).toBe("acl_blob_mismatch");
    const empty = await attestation({ aclBlob: new Uint8Array(0), extensions: appleExtensions(4) });
    expect(await reason(verifyMacAttestation({ ...empty.input, policy: policy() }))).toBe("acl_blob_mismatch");
  });

  it("puts a mismatched aclBlob in the error, for the refusal log", async () => {
    const other = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x07]);
    const { input } = await attestation({ aclBlob: other, aclBlobRaw: true, extensions: appleExtensions(4) });
    const error = await verifyMacAttestation({ ...input, policy: policy() }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AppAttestError);
    expect((error as AppAttestError).detail).toEqual({ aclBlob: toBase64(other), aclBlobLength: 5 });
  });
});

describe("assertions", () => {
  async function enrolled() {
    const { device, input } = await attestation({});
    const key = await verifyMacAttestation({ ...input, policy: policy() });
    return { device, spki: key.publicKeySpki };
  }

  it("accepts a signature over this clientData with a higher counter", async () => {
    const { device, spki } = await enrolled();
    const a = fromBase64(await assertion(device, "client data", 7, APP_ID));
    expect(await verifyMacAssertion({ assertion: a, clientData: "client data", publicKeySpki: spki, storedCounter: 6, policy: policy() })).toMatchObject({
      counter: 7,
      validationCategory: null,
    });
  });

  it("refuses other client data, another App ID, and a counter that does not rise", async () => {
    const { device, spki } = await enrolled();
    const a = fromBase64(await assertion(device, "client data", 7, APP_ID));
    const base = { assertion: a, clientData: "client data", publicKeySpki: spki, policy: policy() };
    expect(await reason(verifyMacAssertion({ ...base, clientData: "other", storedCounter: 0 }))).toBe("signature_invalid");
    expect(await reason(verifyMacAssertion({ ...base, storedCounter: 7 }))).toBe("counter_not_increasing");
    expect(await reason(verifyMacAssertion({ ...base, storedCounter: 8 }))).toBe("counter_not_increasing");
    const otherApp = fromBase64(await assertion(device, "client data", 9, "TEAMID1234.com.example.other"));
    expect(await reason(verifyMacAssertion({ ...base, assertion: otherApp, storedCounter: 0 }))).toBe("rp_id_mismatch");
  });

  it("refuses another key's signature", async () => {
    const { spki } = await enrolled();
    const { device: other } = await enrolled();
    const a = fromBase64(await assertion(other, "client data", 1, APP_ID));
    expect(await reason(verifyMacAssertion({ assertion: a, clientData: "client data", publicKeySpki: spki, storedCounter: 0, policy: policy() }))).toBe("signature_invalid");
  });

  it("checks the category an assertion carries", async () => {
    const { device, spki } = await enrolled();
    const developerId = fromBase64(await assertion(device, "cd", 1, APP_ID, appleExtensions(6)));
    expect(await reason(verifyMacAssertion({ assertion: developerId, clientData: "cd", publicKeySpki: spki, storedCounter: 0, policy: policy() }))).toBe(
      "validation_category_not_allowed",
    );
    const testFlight = fromBase64(await assertion(device, "cd", 2, APP_ID, appleExtensions(2)));
    expect(await verifyMacAssertion({ assertion: testFlight, clientData: "cd", publicKeySpki: spki, storedCounter: 1, policy: policy() })).toMatchObject({
      validationCategory: 2,
    });
  });

  it("refuses an assertion that is not CBOR, or lacks its fields", async () => {
    const { spki } = await enrolled();
    const base = { clientData: "cd", publicKeySpki: spki, storedCounter: 0, policy: policy() };
    expect(await reason(verifyMacAssertion({ ...base, assertion: new Uint8Array([1, 2, 3]) }))).toBe("assertion_malformed");
    expect(await reason(verifyMacAssertion({ ...base, assertion: encodeCBOR(new Map<string, CBORType>([["signature", new Uint8Array(8)]])) }))).toBe("assertion_malformed");
  });
});

describe("bundle versions", () => {
  it("compares dotted numbers, not strings", () => {
    expect(bundleVersionAtLeast("1.10", "1.9")).toBe(true);
    expect(bundleVersionAtLeast("1.9", "1.10")).toBe(false);
    expect(bundleVersionAtLeast("2", "1.99.99")).toBe(true);
    expect(bundleVersionAtLeast("1.0", "1")).toBe(true);
    expect(bundleVersionAtLeast("1.0-beta", "1.0")).toBe(false);
  });
});
