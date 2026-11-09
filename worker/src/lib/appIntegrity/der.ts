/**
 * The DER this Worker needs to check an App Attest certificate chain
 *, and nothing more: read TLVs, pull the fields of an X.509
 * certificate out with the exact bytes they were signed over, and verify one
 * certificate's signature with another's key through WebCrypto.
 *
 * Hand-rolled rather than @peculiar/x509: that package loads tsyringe and
 * reflect-metadata, and re-serialising a parsed TBSCertificate is not
 * guaranteed to give back the bytes that were signed. Here the signed bytes
 * are sliced straight out of the input.
 */
import { bytesEqual } from "./bytes";

export interface Tlv {
  tag: number;
  /** The whole element, header included. */
  raw: Uint8Array;
  /** The contents only. */
  value: Uint8Array;
}

export function readTlv(buf: Uint8Array, off = 0): Tlv {
  if (off + 2 > buf.length) throw new Error("der: truncated header");
  const tag = buf[off];
  if ((tag & 0x1f) === 0x1f) throw new Error("der: multi-byte tags unsupported");
  let p = off + 1;
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("der: unsupported length form");
    if (p + n > buf.length) throw new Error("der: truncated length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > buf.length) throw new Error("der: contents run past the buffer");
  return { tag, raw: buf.subarray(off, p + len), value: buf.subarray(p, p + len) };
}

/** Every element directly inside a constructed value. */
export function readChildren(value: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < value.length) {
    const tlv = readTlv(value, off);
    out.push(tlv);
    off += tlv.raw.length;
  }
  return out;
}

function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv || tlv.tag !== tag) throw new Error(`der: expected ${what}`);
  return tlv;
}

export function decodeOid(value: Uint8Array): string {
  if (value.length === 0) throw new Error("der: empty oid");
  const parts: number[] = [Math.floor(value[0] / 40), value[0] % 40];
  let n = 0;
  for (let i = 1; i < value.length; i++) {
    n = n * 128 + (value[i] & 0x7f);
    if ((value[i] & 0x80) === 0) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join(".");
}

function decodeTime(tlv: Tlv): Date {
  const s = new TextDecoder().decode(tlv.value);
  let m: RegExpMatchArray | null;
  if (tlv.tag === 0x17 && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const yy = Number(m[1]);
    return new Date(Date.UTC(yy >= 50 ? 1900 + yy : 2000 + yy, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  if (tlv.tag === 0x18 && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  throw new Error("der: unsupported time");
}

export const OID = {
  ecPublicKey: "1.2.840.10045.2.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  basicConstraints: "2.5.29.19",
  /** Apple's App Attest nonce extension on the credential certificate. */
  appleAppAttestNonce: "1.2.840.113635.100.8.2",
  /** Apple's App Attest access-policy hash (aclBlob), present on macOS keys. */
  appleAppAttestAclBlob: "1.2.840.113635.100.8.6",
} as const;

export interface Extension {
  critical: boolean;
  /** The contents of extnValue's OCTET STRING. */
  value: Uint8Array;
}

export interface Certificate {
  /** The TBSCertificate exactly as signed. */
  tbs: Uint8Array;
  signatureAlgorithm: string;
  /** DER ECDSA-Sig-Value. */
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  /** SubjectPublicKeyInfo, whole. */
  spki: Uint8Array;
  /** "P-256" or "P-384"; anything else is refused at parse. */
  curve: "P-256" | "P-384";
  extensions: Map<string, Extension>;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const cert = expectTag(readTlv(der), 0x30, "certificate");
  if (cert.raw.length !== der.length) throw new Error("der: trailing bytes after certificate");
  const [tbsTlv, sigAlgTlv, sigTlv] = readChildren(cert.value);
  expectTag(tbsTlv, 0x30, "tbsCertificate");
  const sigAlg = readChildren(expectTag(sigAlgTlv, 0x30, "signatureAlgorithm").value);
  const signatureAlgorithm = decodeOid(expectTag(sigAlg[0], 0x06, "algorithm oid").value);
  const sigBits = expectTag(sigTlv, 0x03, "signature bit string").value;
  if (sigBits[0] !== 0) throw new Error("der: signature has unused bits");

  const fields = readChildren(tbsTlv.value);
  let i = 0;
  if (fields[i]?.tag === 0xa0) i++; // [0] version
  expectTag(fields[i++], 0x02, "serial");
  const innerAlg = readChildren(expectTag(fields[i++], 0x30, "tbs signature").value);
  if (decodeOid(expectTag(innerAlg[0], 0x06, "tbs algorithm oid").value) !== signatureAlgorithm) {
    throw new Error("der: signature algorithm mismatch");
  }
  const issuer = expectTag(fields[i++], 0x30, "issuer").raw;
  const validity = readChildren(expectTag(fields[i++], 0x30, "validity").value);
  const subject = expectTag(fields[i++], 0x30, "subject").raw;
  const spkiTlv = expectTag(fields[i++], 0x30, "subjectPublicKeyInfo");
  const spkiAlg = readChildren(expectTag(readChildren(spkiTlv.value)[0], 0x30, "spki algorithm").value);
  if (decodeOid(expectTag(spkiAlg[0], 0x06, "key oid").value) !== OID.ecPublicKey) throw new Error("der: key is not EC");
  const curveOid = decodeOid(expectTag(spkiAlg[1], 0x06, "curve oid").value);
  const curve = curveOid === OID.p256 ? "P-256" : curveOid === OID.p384 ? "P-384" : null;
  if (!curve) throw new Error("der: unsupported curve");

  const extensions = new Map<string, Extension>();
  for (; i < fields.length; i++) {
    if (fields[i].tag !== 0xa3) continue; // [1]/[2] unique ids
    const list = readChildren(expectTag(readChildren(fields[i].value)[0], 0x30, "extensions").value);
    for (const ext of list) {
      const parts = readChildren(expectTag(ext, 0x30, "extension").value);
      const oid = decodeOid(expectTag(parts[0], 0x06, "extension oid").value);
      let critical = false;
      let valueTlv = parts[1];
      if (valueTlv?.tag === 0x01) {
        critical = valueTlv.value[0] !== 0;
        valueTlv = parts[2];
      }
      if (extensions.has(oid)) throw new Error("der: duplicate extension");
      extensions.set(oid, { critical, value: expectTag(valueTlv, 0x04, "extnValue").value });
    }
  }

  return {
    tbs: tbsTlv.raw,
    signatureAlgorithm,
    signature: sigBits.subarray(1),
    issuer,
    subject,
    notBefore: decodeTime(validity[0]),
    notAfter: decodeTime(validity[1]),
    spki: spkiTlv.raw,
    curve,
    extensions,
  };
}

/** True when basicConstraints says this certificate is a CA. */
export function isCa(cert: Certificate): boolean {
  const ext = cert.extensions.get(OID.basicConstraints);
  if (!ext) return false;
  const seq = readChildren(expectTag(readTlv(ext.value), 0x30, "basicConstraints").value);
  return seq[0]?.tag === 0x01 && seq[0].value[0] !== 0;
}

/** DER ECDSA-Sig-Value to the r||s form WebCrypto verifies. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  const seq = expectTag(readTlv(der), 0x30, "ecdsa signature");
  if (seq.raw.length !== der.length) throw new Error("der: trailing bytes after signature");
  const [r, s, extra] = readChildren(seq.value);
  if (extra) throw new Error("der: extra signature fields");
  const out = new Uint8Array(size * 2);
  for (const [k, int] of [r, s].entries()) {
    let v = expectTag(int, 0x02, "signature integer").value;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error("der: signature integer too long");
    out.set(v, k * size + (size - v.length));
  }
  return out;
}

/** Whether `child` carries a valid signature by `issuer`'s key, and names it as issuer. */
export async function isSignedBy(child: Certificate, issuer: Certificate): Promise<boolean> {
  if (!bytesEqual(child.issuer, issuer.subject)) return false;
  const hash =
    child.signatureAlgorithm === OID.ecdsaSha256 ? "SHA-256" : child.signatureAlgorithm === OID.ecdsaSha384 ? "SHA-384" : null;
  if (!hash) return false;
  const key = await crypto.subtle.importKey("spki", issuer.spki, { name: "ECDSA", namedCurve: issuer.curve }, false, ["verify"]);
  const raw = ecdsaDerToRaw(child.signature, issuer.curve === "P-256" ? 32 : 48);
  return crypto.subtle.verify({ name: "ECDSA", hash }, key, raw, child.tbs);
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
