/**
 * App Attest for the macOS app. Apple's steps (appleAppAttest.ts, whose core
 * this calls), plus the checks Apple documents for macOS:
 *
 * - The App ID is the one configured on the Worker (ATTEST_APP_ID), never a
 *   default.
 * - The key must be a Mac's, which the certificate says through the aclBlob
 *   (OID 1.2.840.113635.100.8.6). Its value must be Apple's exact macOS
 *   policy, which needs System Integrity Protection and full security mode
 *   ("Attested keys on macOS should only be trusted for this exact hash
 *   value"). No aclBlob, or any other value, is refused.
 * - The authenticator data extensions `apple_validation_category_01` and
 *   `apple_bundle_version_01` (macOS 27). When present the category has to be
 *   one the app can ship as. They are required only when
 *   ATTEST_REQUIRE_EXTENSIONS is "true".
 *
 * Pure functions: every failure throws AppAttestError with a reason code, and
 * nothing here logs or puts key, attestation or assertion bytes in an error.
 * A mismatched aclBlob is put in one, because it is a policy hash, not a key.
 *
 * Assumptions Apple's pages do not settle:
 * - extnValue is SEQUENCE { [3] { OCTET STRING policy } }. The policy is what
 *   is compared, and Apple's documented macOS base64 is taken to be a policy
 *   in the same wrapping.
 * - The extensions are a CBOR map with text keys; the category is a 4-byte
 *   byte string holding a little-endian UInt32 and the bundle version a text
 *   string. Anything else is refused rather than guessed at.
 */
import { decodePartialCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { AppAttestError, verifyAssertion, verifyAttestation, type AppAttestEnvironment, type AppAttestReason } from "./appleAppAttest";
import { bytesEqual, fromBase64, toBase64 } from "./bytes";
import { OID, readChildren, readTlv } from "./der";

/**
 * The access-policy hash Apple says a macOS key must carry, from "Validating
 * apps that connect to your server": "the encoded hash of the access policy
 * for the attested key on macOS corresponding with both SIP and full security
 * mode enabled ... This value should never change across macOS versions."
 */
export const MACOS_ACL_BLOB_BASE64 = "MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB";
const MACOS_ACL_BLOB = fromBase64(MACOS_ACL_BLOB_BASE64);

/** extnValue = SEQUENCE { [3] { OCTET STRING policy } }; null when it is any other shape. */
function readAclPolicy(value: Uint8Array): Uint8Array | null {
  try {
    const seq = readTlv(value);
    if (seq.tag !== 0x30 || seq.raw.length !== value.length) return null;
    const children = readChildren(seq.value);
    if (children.length !== 1 || children[0].tag !== 0xa3) return null;
    const inner = readTlv(children[0].value);
    if (inner.tag !== 0x04 || inner.raw.length !== children[0].value.length) return null;
    return inner.value;
  } catch {
    return null;
  }
}

/**
 * apple_validation_category_01, from Apple's guide: 0 invalid, 1 OS
 * executable, 2 TestFlight, 3 development signing, 4 App Store, 5 Enterprise
 * or ad hoc, 6 Developer ID, 7 to 9 not appropriate, 10 other.
 *
 * A private business app ships as a Custom App through Apple Business
 * Manager, which signs as App Store (4), and is tested through TestFlight
 * (2). Nothing else on a production server: Developer ID carries no App
 * Attest, and ad hoc is not used. A development-signed build (3) is taken
 * only by a development Worker. Change this list if you ship another way.
 */
export const PRODUCTION_CATEGORIES: readonly number[] = [2, 4];
export const DEVELOPMENT_CATEGORY = 3;

const EXT_CATEGORY = "apple_validation_category_01";
const EXT_BUNDLE_VERSION = "apple_bundle_version_01";

const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

export interface AttestPolicy {
  /** Team ID, a period, and the signing identifier. */
  appId: string;
  allowedEnvironments: readonly AppAttestEnvironment[];
  allowedCategories: readonly number[];
  /**
   * Refuse a key without the extensions. Apple documents them for iOS 27; a
   * macOS 27.0 Mac sent none, so leave this off while any Mac is on it.
   */
  requireExtensions: boolean;
  /** Lowest apple_bundle_version_01 accepted, dotted numbers, or null for any. */
  minBundleVersion: string | null;
}

export interface AppleExtensions {
  validationCategory: number | null;
  bundleVersion: string | null;
}

function fail(reason: AppAttestReason, detail?: Record<string, string | number>): never {
  throw new AppAttestError(reason, detail);
}

/** Read the CBOR extensions map and the two fields we use. */
function readExtensions(data: Uint8Array, offset: number, reason: AppAttestReason): { ext: AppleExtensions; end: number } {
  // The extensions are a category and a bundle version, not key material, so
  // a refusal logs them: it is how a format Apple changes shows up.
  const malformed: () => never = () => fail(reason, { extensions: toBase64(data.subarray(offset, offset + 256)), extensionsLength: data.length - offset });
  let value: CBORType;
  let read: number;
  try {
    [value, read] = decodePartialCBOR(data, offset);
  } catch {
    malformed();
  }
  if (!(value instanceof Map)) malformed();
  const category = value.get(EXT_CATEGORY);
  const version = value.get(EXT_BUNDLE_VERSION);
  // A UInt32 as four little-endian bytes: an iOS 27 TestFlight build sent
  // h'02000000' on 2026-10-28. Apple's page says only "UInt32 value".
  if (category !== undefined && !(category instanceof Uint8Array && category.length === 4)) malformed();
  if (version !== undefined && !(typeof version === "string" && version.length > 0 && version.length <= 64)) malformed();
  return {
    ext: {
      validationCategory: category === undefined ? null : new DataView(category.buffer, category.byteOffset, 4).getUint32(0, true),
      bundleVersion: version === undefined ? null : version,
    },
    end: offset + read,
  };
}

/**
 * The extensions in attestation authData: rpIdHash(32) flags(1) counter(4)
 * aaguid(16) credIdLen(2) credId, the COSE key, then the extensions when the
 * ED flag is set. Nothing may follow.
 */
export function attestationExtensions(authData: Uint8Array): AppleExtensions {
  const flags = authData[32];
  if (!(flags & FLAG_AT)) fail("attestation_malformed");
  const credIdLen = (authData[53] << 8) | authData[54];
  let offset = 55 + credIdLen;
  try {
    offset += decodePartialCBOR(authData, offset)[1]; // the COSE public key
  } catch {
    fail("attestation_malformed");
  }
  let ext: AppleExtensions = { validationCategory: null, bundleVersion: null };
  if (flags & FLAG_ED) ({ ext, end: offset } = readExtensions(authData, offset, "extensions_malformed"));
  if (offset !== authData.length) fail("attestation_malformed");
  return ext;
}

/** The extensions in assertion authenticatorData: rpIdHash(32) flags(1) counter(4), then extensions when ED is set. */
export function assertionExtensions(authenticatorData: Uint8Array): AppleExtensions {
  const flags = authenticatorData[32];
  let offset = 37;
  let ext: AppleExtensions = { validationCategory: null, bundleVersion: null };
  if (flags & FLAG_ED) ({ ext, end: offset } = readExtensions(authenticatorData, offset, "extensions_malformed"));
  if (offset !== authenticatorData.length) fail("assertion_malformed");
  return ext;
}

/** Dotted numeric versions, "1.10" above "1.9". Anything not dotted digits sorts lowest. */
export function bundleVersionAtLeast(version: string, minimum: string): boolean {
  const parse = (v: string) => (/^\d{1,9}(\.\d{1,9}){0,3}$/.test(v) ? v.split(".").map(Number) : null);
  const have = parse(version);
  const want = parse(minimum);
  if (!have || !want) return false;
  for (let i = 0; i < Math.max(have.length, want.length); i++) {
    const a = have[i] ?? 0;
    const b = want[i] ?? 0;
    if (a !== b) return a > b;
  }
  return true;
}

function checkExtensions(ext: AppleExtensions, policy: AttestPolicy, required: boolean): void {
  if (required && (ext.validationCategory === null || ext.bundleVersion === null)) {
    fail("extensions_missing", { hasCategory: String(ext.validationCategory !== null), hasBundleVersion: String(ext.bundleVersion !== null) });
  }
  if (ext.validationCategory !== null && !policy.allowedCategories.includes(ext.validationCategory)) {
    fail("validation_category_not_allowed");
  }
  if (policy.minBundleVersion && ext.bundleVersion !== null && !bundleVersionAtLeast(ext.bundleVersion, policy.minBundleVersion)) {
    fail("bundle_version_too_old");
  }
}

export interface MacAttestationInput {
  attestation: Uint8Array;
  keyId: string;
  challenge: string;
  /** Trust anchor, DER. Production passes APPLE_APP_ATTEST_ROOT_DER. */
  root: Uint8Array;
  policy: AttestPolicy;
  now?: Date;
}

export interface AttestedMacKey extends AppleExtensions {
  publicKeySpki: Uint8Array;
  environment: AppAttestEnvironment;
  receipt: Uint8Array | null;
}

/**
 * Apple's attestation steps 1 to 9 (appleAppAttest.ts), then the aclBlob, which
 * must be a Mac's, and the extensions.
 */
export async function verifyMacAttestation(input: MacAttestationInput): Promise<AttestedMacKey> {
  const { policy } = input;
  const core = await verifyAttestation({
    attestation: input.attestation,
    keyId: input.keyId,
    challenge: input.challenge,
    allowedEnvironments: policy.allowedEnvironments,
    root: input.root,
    now: input.now,
    appId: policy.appId,
  });

  const acl = core.leaf.extensions.get(OID.appleAppAttestAclBlob);
  if (!acl) fail("acl_blob_missing");
  const aclPolicy = readAclPolicy(acl.value);
  if (!aclPolicy || !bytesEqual(aclPolicy, MACOS_ACL_BLOB)) {
    // The blob is the key's access policy, the same for every device in a
    // given mode, so it goes in the refusal log: it is how a new OS's value
    // shows up. A Mac in Reduced Security lands here.
    fail("acl_blob_mismatch", { aclBlob: toBase64(acl.value), aclBlobLength: acl.value.length });
  }

  const ext = attestationExtensions(core.authData);
  checkExtensions(ext, policy, policy.requireExtensions);

  return { publicKeySpki: core.publicKeySpki, environment: core.environment, receipt: core.receipt, ...ext };
}

export interface MacAssertionInput {
  assertion: Uint8Array;
  clientData: string;
  publicKeySpki: Uint8Array;
  storedCounter: number;
  policy: AttestPolicy;
}

/**
 * Apple's assertion steps (the consumer core: signature over
 * SHA256(authenticatorData || SHA256(clientData)), RP ID, counter strictly
 * above the stored one), then the extensions. The caller stores the counter
 * with a conditional UPDATE so concurrent copies cannot both pass.
 */
export async function verifyMacAssertion(input: MacAssertionInput): Promise<{ counter: number } & AppleExtensions> {
  const core = await verifyAssertion({
    assertion: input.assertion,
    clientData: input.clientData,
    publicKeySpki: input.publicKeySpki,
    storedCounter: input.storedCounter,
    appId: input.policy.appId,
  });
  const ext = assertionExtensions(core.authenticatorData);
  // The attestation already settled whether this key needs extensions; an
  // assertion is checked on what it carries, so an older OS that sends none
  // is not refused here for a key enrolled without them.
  checkExtensions(ext, input.policy, false);
  return { counter: core.counter, ...ext };
}
