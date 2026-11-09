import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalRequestTarget, clientData } from "../src/request.ts";
import { isBridgedApiPath } from "../src/bridge.ts";
import { serializeVectors, VECTORS_PATH } from "../scripts/vectors.ts";

const sha256Hex = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const file = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));

describe("shared/vectors/request.json", () => {
  it("is what the generator makes: run `npm run generate:vectors` after changing request.ts", () => {
    expect(readFileSync(VECTORS_PATH, "utf8")).toBe(serializeVectors());
  });

  it("hashes each input as the file says", () => {
    expect(file.sha256.length).toBeGreaterThan(0);
    for (const v of file.sha256) expect(sha256Hex(v.input), v.name).toBe(v.sha256);
    // No body hashes the empty string.
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("builds exactly the signed string for each clientData vector", () => {
    expect(file.clientData.length).toBeGreaterThan(0);
    for (const v of file.clientData) {
      const text = clientData(v.parts);
      expect(text, v.name).toBe(v.clientData);
      expect(sha256Hex(text), v.name).toBe(v.clientDataSha256);
      expect(text.split("\n")).toHaveLength(10);
      expect(text.startsWith("secure-app-v1\n")).toBe(true);
    }
  });

  it("makes each canonical target as the Worker's URL parser would", () => {
    expect(file.canonicalRequestTarget.length).toBeGreaterThan(0);
    for (const v of file.canonicalRequestTarget) expect(canonicalRequestTarget(v.input), v.name).toBe(v.expected);
    const byName = Object.fromEntries(file.canonicalRequestTarget.map((v: { name: string; expected: string }) => [v.name, v.expected]));
    expect(byName["a quote in the query becomes %27"]).toBe("/api/notes?q=it%27s");
    expect(byName["an empty query goes"]).toBe("/api/notes");
  });

  it("upper-cases the method in the signed string", () => {
    expect(file.clientData[0].parts.method).toBe("post");
    expect(file.clientData[0].clientData.split("\n")[3]).toBe("POST");
  });
});

describe("the bridge's path rule", () => {
  it("carries API paths and refuses enrolment, the live socket and anything that climbs out", () => {
    for (const p of ["/api/me", "/api/notes?x=1", "/api/notes/abc/export", "/api/devices/revoke"]) expect(isBridgedApiPath(p), p).toBe(true);
    for (const p of ["/api/attest/register", "/api/attest/session", "/api/live", "/api", "/other", "api/me", "/api/../x", "/api//me", "/api/%2e%2e/me", "/api/a%2Fb"]) {
      expect(isBridgedApiPath(p), p).toBe(false);
    }
  });
});
