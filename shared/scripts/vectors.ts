/**
 * Golden vectors for the signed request. The Swift tests read the generated
 * file (shared/vectors/request.json) and check their own clientData, hashes
 * and canonical targets against it, so the app and the Worker cannot drift.
 * Change the inputs here only together with the app, then run
 * `npm run generate:vectors`. test/vectors.test.ts fails if the file is stale.
 */
import { createHash } from "node:crypto";
import { canonicalRequestTarget, clientData, CLIENT_DATA_VERSION, type RequestParts } from "../src/request.ts";

const sha256Hex = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

const BODY = '{"title":"Hello","body":"First note"}';
const TOKEN = "eyJ.test.token";
const APP_ID = "TEAMID1234.com.example.secureapp";
const KEY_ID = "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0=";
const CHALLENGE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

const base = {
  appId: APP_ID,
  keyId: KEY_ID,
  tokenSha256: sha256Hex(TOKEN),
  time: 1792800000000,
  nonce: "n0nce_0123456789-AB",
  challenge: CHALLENGE,
};

const CLIENT_DATA_CASES: { name: string; parts: RequestParts }[] = [
  {
    name: "POST with a query and a body",
    parts: { ...base, method: "post", pathAndQuery: "/api/notes?dry=1", bodySha256: sha256Hex(BODY) },
  },
  {
    name: "GET with no body",
    parts: { ...base, method: "GET", pathAndQuery: "/api/me", bodySha256: sha256Hex("") },
  },
  {
    name: "the session path with the bootstrap challenge",
    parts: { ...base, method: "GET", pathAndQuery: "/api/attest/session", bodySha256: sha256Hex(""), challenge: "bootstrap" },
  },
];

const SHA256_INPUTS: { name: string; input: string }[] = [
  { name: "the body in the first clientData vector", input: BODY },
  { name: "the bearer token in every clientData vector", input: TOKEN },
  { name: "no body", input: "" },
  { name: "non-ASCII text, hashed as UTF-8", input: "café ☕" },
];

/** What the Worker's URL parser makes of each target; apps sign and send the result. */
const CANONICAL_TARGET_INPUTS: { name: string; input: string }[] = [
  { name: "plain path", input: "/api/me" },
  { name: "path with a query", input: "/api/notes?limit=10&q=a" },
  { name: "a quote in the query becomes %27", input: "/api/notes?q=it's" },
  { name: "an empty query goes", input: "/api/notes?" },
  { name: "a space in the query becomes %20", input: "/api/notes?q=a b" },
  { name: "a space in the path becomes %20", input: "/api/notes/a b/export" },
  { name: "the fragment is dropped", input: "/api/notes?q=a#top" },
  { name: "dot segments are resolved", input: "/api/notes/../me" },
  { name: "existing percent escapes are kept as written", input: "/api/notes?q=%7e%7E" },
  { name: "non-ASCII in the path is percent-encoded", input: "/api/notes/café" },
  { name: "a plus in the query is kept", input: "/api/notes?q=a+b" },
];

export function buildVectors() {
  return {
    version: CLIENT_DATA_VERSION,
    sha256: SHA256_INPUTS.map((c) => ({ name: c.name, input: c.input, sha256: sha256Hex(c.input) })),
    clientData: CLIENT_DATA_CASES.map((c) => {
      const text = clientData(c.parts);
      return { name: c.name, parts: c.parts, clientData: text, clientDataSha256: sha256Hex(text) };
    }),
    canonicalRequestTarget: CANONICAL_TARGET_INPUTS.map((c) => ({ name: c.name, input: c.input, expected: canonicalRequestTarget(c.input) })),
  };
}

export const VECTORS_PATH = new URL("../vectors/request.json", import.meta.url);

export function serializeVectors(): string {
  return `${JSON.stringify(buildVectors(), null, 2)}\n`;
}
