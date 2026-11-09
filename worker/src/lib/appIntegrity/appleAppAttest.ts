/**
 * Apple App Attest verification, per Apple's "Validating apps that
 * connect to your server". Pure functions: the caller supplies the challenge,
 * the stored key and counter, and persists what comes back.
 *
 * Every failure throws AppAttestError with a reason code the caller logs.
 * Nothing here logs, and nothing here ever puts an attestation, assertion or
 * key into an error message.
 */
import { decodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { bytesEqual, concatBytes, fromBase64, sha256 } from "./bytes";
import { OID, isCa, isSignedBy, parseCertificate, pemToDer, readChildren, readTlv, ecdsaDerToRaw, type Certificate } from "./der";

/**
 * Apple App Attestation Root CA, from
 * https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
 * SHA-256 of the DER: 1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932
 * (asserted in worker/test/appleRoot.test.ts). Valid 2020-03-18 to 2045-03-15.
 */
export const APPLE_APP_ATTEST_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

export const APPLE_APP_ATTEST_ROOT_DER = pemToDer(APPLE_APP_ATTEST_ROOT_PEM);

const AAGUID_PRODUCTION = concatBytes(new TextEncoder().encode("appattest"), new Uint8Array(7));
const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");

export type AppAttestEnvironment = "production" | "development";

export type AppAttestReason =
  | "attestation_malformed"
  | "attestation_format"
  | "chain_invalid"
  | "chain_expired"
  | "nonce_mismatch"
  | "key_id_mismatch"
  | "rp_id_mismatch"
  | "counter_not_zero"
  | "aaguid_unknown"
  | "aaguid_not_allowed"
  | "assertion_malformed"
  | "signature_invalid"
  | "counter_not_increasing"
  // The macOS app's checks (appAttest.ts).
  | "acl_blob_missing"
  | "acl_blob_mismatch"
  | "extensions_malformed"
  | "extensions_missing"
  | "validation_category_not_allowed"
  | "bundle_version_too_old";

export class AppAttestError extends Error {
  constructor(
    public readonly reason: AppAttestReason,
    /** Non-secret facts for the refusal log, never key, attestation or assertion bytes. */
    public readonly detail?: Record<string, string | number>,
  ) {
    super(reason);
    this.name = "AppAttestError";
  }
}

function fail(reason: AppAttestReason): never {
  throw new AppAttestError(reason);
}

function field(map: CBORType, key: string): CBORType {
  if (!(map instanceof Map)) fail("attestation_malformed");
  return map.get(key);
}

function bytesField(map: CBORType, key: string, reason: AppAttestReason): Uint8Array {
  const v = map instanceof Map ? map.get(key) : undefined;
  if (!(v instanceof Uint8Array)) fail(reason);
  return v;
}

function readCounter(authData: Uint8Array): number {
  return ((authData[33] << 24) >>> 0) + (authData[34] << 16) + (authData[35] << 8) + authData[36];
}

export interface VerifyAttestationInput {
  /** The CBOR attestation object, decoded from the app's base64. */
  attestation: Uint8Array;
  /** The key id the app reported, base64 (SHA-256 of the public key). */
  keyId: string;
  /** The server challenge the app attested over, as the string it was given. */
  challenge: string;
  /** Which AAGUIDs to accept. A production server accepts only "production". */
  allowedEnvironments: readonly AppAttestEnvironment[];
  /** Trust anchor, DER. Production passes APPLE_APP_ATTEST_ROOT_DER. */
  root: Uint8Array;
  now?: Date;
  /** Team ID, a period, and the signing identifier. Its SHA-256 is the RP ID hash. */
  appId: string;
}

export interface AttestedKey {
  /** The credential certificate's P-256 SubjectPublicKeyInfo, DER. */
  publicKeySpki: Uint8Array;
  environment: AppAttestEnvironment;
  receipt: Uint8Array | null;
}

/** What the checks saw, for a caller that adds its own (appAttest.ts). */
export interface AttestationDetails extends AttestedKey {
  /** The credential certificate, already chained to the root. */
  leaf: Certificate;
  authData: Uint8Array;
}

/**
 * Verify an attestation object end to end. The App ID is required: there is
 * no default, so a caller cannot forget to name its own. Apple's steps,
 * numbered as theirs:
 *  1. x5c chains credCert -> intermediate -> pinned Apple root.
 *  2-4. nonce = SHA256(authData || SHA256(challenge)) equals the credCert extension.
 *  5. SHA256(credCert public key) is the key id.
 *  6. rpIdHash is SHA256 of our App ID.
 *  7. counter is 0.
 *  8. aaguid is appattest or appattestdevelop, as allowed.
 *  9. credentialId is the key id.
 */
export async function verifyAttestation(input: VerifyAttestationInput): Promise<AttestationDetails> {
  const now = input.now ?? new Date();
  let obj: CBORType;
  try {
    obj = decodeCBOR(input.attestation);
  } catch {
    fail("attestation_malformed");
  }
  if (field(obj, "fmt") !== "apple-appattest") fail("attestation_format");
  const attStmt = field(obj, "attStmt");
  const authData = bytesField(obj, "authData", "attestation_malformed");
  const x5c = field(attStmt, "x5c");
  if (!Array.isArray(x5c) || x5c.length !== 2 || !x5c.every((c) => c instanceof Uint8Array)) fail("attestation_malformed");
  const receiptRaw = field(attStmt, "receipt");
  const receipt = receiptRaw instanceof Uint8Array ? receiptRaw : null;

  // 1. The chain, against the pinned root only: x5c never supplies the anchor.
  let leaf: Certificate, intermediate: Certificate, root: Certificate;
  try {
    leaf = parseCertificate(x5c[0] as Uint8Array);
    intermediate = parseCertificate(x5c[1] as Uint8Array);
    root = parseCertificate(input.root);
  } catch {
    fail("chain_invalid");
  }
  for (const cert of [leaf, intermediate, root]) {
    if (now < cert.notBefore || now > cert.notAfter) fail("chain_expired");
  }
  if (!isCa(intermediate)) fail("chain_invalid");
  if (leaf.curve !== "P-256") fail("chain_invalid");
  try {
    if (!(await isSignedBy(intermediate, root)) || !(await isSignedBy(leaf, intermediate))) fail("chain_invalid");
  } catch (error) {
    if (error instanceof AppAttestError) throw error;
    fail("chain_invalid");
  }

  // 2-4. The nonce binds this authData and our challenge to Apple's certificate.
  const clientDataHash = await sha256(input.challenge);
  const expectedNonce = await sha256(concatBytes(authData, clientDataHash));
  const ext = leaf.extensions.get(OID.appleAppAttestNonce);
  if (!ext) fail("nonce_mismatch");
  let certNonce: Uint8Array;
  try {
    certNonce = readNonceExtension(ext.value);
  } catch {
    fail("nonce_mismatch");
  }
  if (!bytesEqual(certNonce, expectedNonce)) fail("nonce_mismatch");

  // 5. The key id is the hash of the certified public key.
  let keyId: Uint8Array;
  try {
    keyId = fromBase64(input.keyId);
  } catch {
    fail("key_id_mismatch");
  }
  const key = await crypto.subtle.importKey("spki", leaf.spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const point = new Uint8Array((await crypto.subtle.exportKey("raw", key)) as ArrayBuffer);
  if (!bytesEqual(await sha256(point), keyId)) fail("key_id_mismatch");

  // authData: rpIdHash(32) flags(1) counter(4) aaguid(16) credIdLen(2) credId ...
  if (authData.length < 55) fail("attestation_malformed");
  // 6.
  if (!bytesEqual(authData.subarray(0, 32), await sha256(input.appId))) fail("rp_id_mismatch");
  // 7.
  if (readCounter(authData) !== 0) fail("counter_not_zero");
  // 8.
  const aaguid = authData.subarray(37, 53);
  const environment: AppAttestEnvironment | null = bytesEqual(aaguid, AAGUID_PRODUCTION)
    ? "production"
    : bytesEqual(aaguid, AAGUID_DEVELOPMENT)
      ? "development"
      : null;
  if (!environment) fail("aaguid_unknown");
  if (!input.allowedEnvironments.includes(environment)) fail("aaguid_not_allowed");
  // 9.
  const credIdLen = (authData[53] << 8) | authData[54];
  if (authData.length < 55 + credIdLen) fail("attestation_malformed");
  if (!bytesEqual(authData.subarray(55, 55 + credIdLen), keyId)) fail("key_id_mismatch");

  return { publicKeySpki: leaf.spki, environment, receipt, leaf, authData };
}

/** extnValue = SEQUENCE { [1] EXPLICIT OCTET STRING nonce }. */
function readNonceExtension(value: Uint8Array): Uint8Array {
  const seq = readTlv(value);
  if (seq.tag !== 0x30) throw new Error("nonce: not a sequence");
  const [tagged] = readChildren(seq.value);
  // Apple's certificates carry [1] constructed around the OCTET STRING. An
  // implicit primitive [1] is read too: the bytes still have to match the
  // nonce, and the certificate still has to chain to Apple.
  if (tagged?.tag === 0x81 && tagged.value.length === 32) return tagged.value;
  if (tagged?.tag !== 0xa1) throw new Error("nonce: not [1]");
  const inner = readTlv(tagged.value);
  if (inner.tag !== 0x04 || inner.value.length !== 32) throw new Error("nonce: not a 32-byte octet string");
  return inner.value;
}

export interface VerifyAssertionInput {
  /** The CBOR assertion object, decoded from the app's base64. */
  assertion: Uint8Array;
  /** The exact string the app passed to generateAssertion. */
  clientData: string;
  publicKeySpki: Uint8Array;
  storedCounter: number;
  appId: string;
}

/**
 * Verify a per-request assertion. Returns the counter the caller must store,
 * atomically, guarded by the stored counter still being lower: two copies of
 * one assertion racing each other must not both pass. Also returns the
 * authenticator data for a caller's own checks.
 */
export async function verifyAssertion(input: VerifyAssertionInput): Promise<{ counter: number; authenticatorData: Uint8Array }> {
  let obj: CBORType;
  try {
    obj = decodeCBOR(input.assertion);
  } catch {
    fail("assertion_malformed");
  }
  const signature = bytesField(obj, "signature", "assertion_malformed");
  const authenticatorData = bytesField(obj, "authenticatorData", "assertion_malformed");
  if (authenticatorData.length < 37) fail("assertion_malformed");

  // The Secure Enclave signs nonce = SHA256(authenticatorData || clientDataHash)
  // with ECDSA-SHA256, so the verified message is the nonce itself.
  const clientDataHash = await sha256(input.clientData);
  const nonce = await sha256(concatBytes(authenticatorData, clientDataHash));
  let ok = false;
  try {
    const key = await crypto.subtle.importKey("spki", input.publicKeySpki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ecdsaDerToRaw(signature, 32), nonce);
  } catch {
    ok = false;
  }
  if (!ok) fail("signature_invalid");
  if (!bytesEqual(authenticatorData.subarray(0, 32), await sha256(input.appId))) fail("rp_id_mismatch");
  const counter = readCounter(authenticatorData);
  if (counter <= input.storedCounter) fail("counter_not_increasing");
  return { counter, authenticatorData };
}
