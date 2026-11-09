/**
 * Real App Attest objects signed by a CA generated per suite. The
 * root here is never Apple's: tests hand it to the verifier through
 * setAppAttestRootForTests, which only an ENVIRONMENT of "test" honours.
 */
import { encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { concatBytes, sha256, toBase64 } from "../../src/lib/appIntegrity/bytes";

// ---- DER writer ---------------------------------------------------------------

function len(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const body = concatBytes(...parts);
  return concatBytes(new Uint8Array([tag]), len(body.length), body);
}

const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const octets = (b: Uint8Array) => tlv(0x04, b);

function oid(text: string): Uint8Array {
  const [a, b, ...rest] = text.split(".").map(Number);
  const out = [a * 40 + b];
  for (const n of rest) {
    const chunk = [n & 0x7f];
    let v = n >> 7;
    while (v > 0) {
      chunk.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    out.push(...chunk);
  }
  return tlv(0x06, new Uint8Array(out));
}

function int(bytes: Uint8Array): Uint8Array {
  let v = bytes;
  while (v.length > 1 && v[0] === 0 && v[1] < 0x80) v = v.subarray(1);
  if (v[0] >= 0x80) v = concatBytes(new Uint8Array([0]), v);
  return tlv(0x02, v);
}

function utcTime(d: Date): Uint8Array {
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}

const name = (cn: string) => seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));

// ---- Certificates -------------------------------------------------------------

type Curve = "P-256" | "P-384";

export interface Issuer {
  name: string;
  keys: CryptoKeyPair;
  curve: Curve;
  der: Uint8Array;
}

async function genKey(curve: Curve): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"])) as CryptoKeyPair;
}

/** WebCrypto r||s to DER ECDSA-Sig-Value. */
export function rawToDerSignature(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  return seq(int(raw.subarray(0, half)), int(raw.subarray(half)));
}

async function signWith(issuer: { keys: CryptoKeyPair; curve: Curve }, data: Uint8Array): Promise<Uint8Array> {
  const hash = issuer.curve === "P-384" ? "SHA-384" : "SHA-256";
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, issuer.keys.privateKey, data));
  return rawToDerSignature(raw);
}

interface CertSpec {
  subject: string;
  subjectKey: CryptoKey;
  issuer: { name: string; keys: CryptoKeyPair; curve: Curve };
  ca?: boolean;
  extensions?: Uint8Array[];
  notBefore?: Date;
  notAfter?: Date;
}

async function makeCert(spec: CertSpec): Promise<Uint8Array> {
  const algOid = spec.issuer.curve === "P-384" ? "1.2.840.10045.4.3.3" : "1.2.840.10045.4.3.2";
  const alg = seq(oid(algOid));
  const spki = new Uint8Array((await crypto.subtle.exportKey("spki", spec.subjectKey)) as ArrayBuffer);
  const exts = [...(spec.extensions ?? [])];
  if (spec.ca) exts.push(seq(oid("2.5.29.19"), tlv(0x01, new Uint8Array([0xff])), octets(seq(tlv(0x01, new Uint8Array([0xff]))))));
  const tbs = seq(
    tlv(0xa0, int(new Uint8Array([2]))),
    int(crypto.getRandomValues(new Uint8Array(8))),
    alg,
    name(spec.issuer.name),
    seq(utcTime(spec.notBefore ?? new Date(Date.now() - 86_400_000)), utcTime(spec.notAfter ?? new Date(Date.now() + 86_400_000 * 365))),
    name(spec.subject),
    spki,
    ...(exts.length ? [tlv(0xa3, seq(...exts))] : []),
  );
  const sig = await signWith(spec.issuer, tbs);
  return seq(tbs, alg, tlv(0x03, new Uint8Array([0]), sig));
}

export interface TestCa {
  root: Issuer;
  intermediate: Issuer;
}

export async function makeTestCa(rootName = "Test App Attestation Root CA"): Promise<TestCa> {
  const rootKeys = await genKey("P-384");
  const rootIssuer = { name: rootName, keys: rootKeys, curve: "P-384" as const };
  const rootDer = await makeCert({ subject: rootName, subjectKey: rootKeys.publicKey, issuer: rootIssuer, ca: true });
  const interKeys = await genKey("P-384");
  const interName = "Test App Attestation CA 1";
  const interDer = await makeCert({ subject: interName, subjectKey: interKeys.publicKey, issuer: rootIssuer, ca: true });
  return {
    root: { ...rootIssuer, der: rootDer },
    intermediate: { name: interName, keys: interKeys, curve: "P-384", der: interDer },
  };
}

// ---- Attestation and assertion ------------------------------------------------

export const AAGUID_PRODUCTION = concatBytes(new TextEncoder().encode("appattest"), new Uint8Array(7));
export const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");

function counterBytes(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export interface AttestOptions {
  appId?: string;
  aaguid?: Uint8Array;
  counter?: number;
  /** Put this in the certificate instead of the real nonce. */
  nonceOverride?: Uint8Array;
  /** Report this key id instead of the real one. */
  reportedKeyId?: string;
  /** CBOR extensions after the COSE key, with the ED flag set. */
  extensions?: Map<string, CBORType>;
  /** Raw bytes after everything else in authData, for malformed cases. */
  trailing?: Uint8Array;
  /** The aclBlob's access policy (OID 1.2.840.113635.100.8.6), wrapped as Apple sends it. */
  aclBlob?: Uint8Array;
  /** Put aclBlob in the extension as it is, without Apple's SEQUENCE { [3] { OCTET STRING } } around it. */
  aclBlobRaw?: boolean;
  /** The credential certificate's validity, for expiry cases. */
  leafNotBefore?: Date;
  leafNotAfter?: Date;
  /** Attest this key pair again instead of a new one. */
  keys?: CryptoKeyPair;
}

export interface TestDevice {
  keyId: string;
  keys: CryptoKeyPair;
  attestation: string;
}

export async function attest(ca: TestCa, challenge: string, opts: AttestOptions = {}): Promise<TestDevice> {
  const keys = opts.keys ?? (await genKey("P-256"));
  const point = new Uint8Array((await crypto.subtle.exportKey("raw", keys.publicKey)) as ArrayBuffer);
  const keyIdBytes = await sha256(point);
  const cose = new Map<number, CBORType>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, point.subarray(1, 33)],
    [-3, point.subarray(33)],
  ]);
  const authData = concatBytes(
    await sha256(opts.appId ?? "TEAMID1234.com.example.secureapp"),
    new Uint8Array([opts.extensions ? 0xc0 : 0x40]),
    counterBytes(opts.counter ?? 0),
    opts.aaguid ?? AAGUID_PRODUCTION,
    new Uint8Array([0, keyIdBytes.length]),
    keyIdBytes,
    encodeCBOR(cose),
    opts.extensions ? encodeCBOR(opts.extensions) : new Uint8Array(),
    opts.trailing ?? new Uint8Array(),
  );
  const nonce = opts.nonceOverride ?? (await sha256(concatBytes(authData, await sha256(challenge))));
  const nonceExt = seq(oid("1.2.840.113635.100.8.2"), octets(seq(tlv(0xa1, octets(nonce)))));
  const extensions = [nonceExt];
  if (opts.aclBlob) extensions.push(seq(oid("1.2.840.113635.100.8.6"), octets(opts.aclBlobRaw ? opts.aclBlob : seq(tlv(0xa3, octets(opts.aclBlob))))));
  const leaf = await makeCert({
    subject: "test-device",
    subjectKey: keys.publicKey,
    issuer: ca.intermediate,
    extensions,
    notBefore: opts.leafNotBefore,
    notAfter: opts.leafNotAfter,
  });
  const attestation = encodeCBOR(
    new Map<string, CBORType>([
      ["fmt", "apple-appattest"],
      ["attStmt", new Map<string, CBORType>([["x5c", [leaf, ca.intermediate.der]], ["receipt", new Uint8Array([1, 2, 3])]])],
      ["authData", authData],
    ]),
  );
  return { keyId: opts.reportedKeyId ?? toBase64(keyIdBytes), keys, attestation: toBase64(attestation) };
}

/** What DCAppAttestService.generateAssertion returns for this clientData. */
export async function assertion(
  device: TestDevice,
  clientData: string,
  counter: number,
  appId = "TEAMID1234.com.example.secureapp",
  extensions?: Map<string, CBORType>,
): Promise<string> {
  const authenticatorData = concatBytes(
    await sha256(appId),
    new Uint8Array([extensions ? 0x80 : 0]),
    counterBytes(counter),
    extensions ? encodeCBOR(extensions) : new Uint8Array(),
  );
  const nonce = await sha256(concatBytes(authenticatorData, await sha256(clientData)));
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, device.keys.privateKey, nonce));
  return toBase64(
    encodeCBOR(new Map<string, CBORType>([["signature", rawToDerSignature(raw)], ["authenticatorData", authenticatorData]])),
  );
}
