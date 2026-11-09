/**
 * App Attest test kit. Everything is real crypto: RS256 tokens from a key made
 * per suite, App Attest attestations and assertions from the test CA in
 * appAttestFixture.ts (handed to the Worker through setAppAttestRootForTests,
 * which only ENVIRONMENT "test" honours). Only the identity provider's HTTP
 * endpoints are stood in for.
 */
import { vi } from "vitest";
import type { CBORType } from "@levischuck/tiny-cbor";
import { APP_HEADER, ATTEST_CHALLENGE_PATH, ATTEST_REGISTER_PATH, clientData } from "@secure-app/shared/request";
import { getEnv } from "../setup";
import { resetBearerKeysForTests } from "../../src/lib/bearer";
import { sha256, toHex } from "../../src/lib/appIntegrity/bytes";
import { MACOS_ACL_BLOB_BASE64 } from "../../src/lib/appIntegrity/appAttest";
import { assertion, attest, type AttestOptions, type TestCa, type TestDevice } from "./appAttestFixture";
import type { Bindings } from "../../src/types";

export const ISSUER = "https://id.test";
export const APP_CLIENT = "app-test-client";
export const ACCESS_GROUP = "org-1:staff";
export const APP_ID = "TEAMID1234.com.example.secureapp";
export const ORIGIN = "https://secure-app.test";
const KID = "attest-kid";

// What the provider's ID token carries: urn:acr:mfa when amr includes "mfa",
// otherwise urn:acr:1fa.
export const ACR_MFA = "urn:acr:mfa";
export const ACR_1FA = "urn:acr:1fa";

export const MACOS_ACL_BLOB = Uint8Array.from(atob(MACOS_ACL_BLOB_BASE64), (c) => c.charCodeAt(0));

/** The category as Apple sends it: a UInt32 in four little-endian bytes. */
export function categoryBytes(category: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, category, true);
  return out;
}

/** macOS 27 authenticator data extensions. */
export function appleExtensions(category = 4, version = "1.0"): Map<string, CBORType> {
  return new Map<string, CBORType>([
    ["apple_validation_category_01", categoryBytes(category)],
    ["apple_bundle_version_01", version],
  ]);
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;

/** The test bindings, with this suite's app and provider settings, and any override. */
export function appEnv(overrides: Partial<Bindings> = {}): Bindings {
  return {
    ...getEnv(),
    ATTEST_APP_ID: APP_ID,
    ATTEST_MFA: "required",
    OIDC_ISSUER: ISSUER,
    OIDC_CLIENT_ID: APP_CLIENT,
    ACCESS_GROUP,
    ...overrides,
  } as Bindings;
}

/** Sends a request through the whole Worker. */
export async function call(request: Request, env: Bindings = appEnv(), context: ExecutionContext = ctx): Promise<Response> {
  // Loaded on first use, not imported: the whole Worker in every test file
  // that only needs a fixture would slow the suite for nothing.
  const { default: worker } = await import("../../src/index");
  return worker.fetch(request, env, context);
}

function b64url(bytes: Uint8Array | string): string {
  const raw = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  let binary = "";
  for (const b of raw) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface Person {
  sub: string;
  email: string;
}

export const ALICE: Person = { sub: "user-alice", email: "alice@example.test" };
export const BOB: Person = { sub: "user-bob", email: "bob@example.test" };

/** Stands in for the identity provider: discovery, JWKS, userinfo by token. */
export class IdentityStub {
  private key!: CryptoKeyPair;
  private userinfo = new Map<string, Record<string, unknown>>();
  userinfoCalls = 0;

  async init(): Promise<this> {
    this.key = (await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    return this;
  }

  install(): void {
    resetBearerKeysForTests();
    this.userinfo.clear();
    this.userinfoCalls = 0;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const answer = await this.respond(url, init);
      if (answer) return answer;
      throw new Error(`unexpected fetch ${url}`);
    });
  }

  /** The provider's answer to a request, or null for a URL that isn't the provider's. */
  async respond(url: string, init?: RequestInit): Promise<Response | null> {
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth/authorize`,
        token_endpoint: `${ISSUER}/oauth/token`,
        userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
      });
    }
    if (url === `${ISSUER}/.well-known/jwks.json`) {
      const publicJwk = await crypto.subtle.exportKey("jwk", this.key.publicKey);
      return Response.json({ keys: [{ ...publicJwk, kid: KID, alg: "RS256", use: "sig" }] });
    }
    if (url === `${ISSUER}/oauth/userinfo`) {
      this.userinfoCalls++;
      const auth = new Headers(init?.headers).get("Authorization") ?? "";
      const body = this.userinfo.get(auth.replace(/^Bearer /, ""));
      return body ? Response.json(body) : Response.json({ error: "invalid_token" }, { status: 401 });
    }
    return null;
  }

  async sign(header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
    const input = `${b64url(JSON.stringify({ alg: "RS256", kid: KID, ...header }))}.${b64url(JSON.stringify(claims))}`;
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", this.key.privateKey, new TextEncoder().encode(input));
    return `${input}.${b64url(new Uint8Array(sig))}`;
  }

  /** An access token for a member of the access group, which userinfo answers for. */
  async accessToken(person: Person, _env: Bindings = appEnv(), userinfo: Record<string, unknown> = {}, claims: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const token = await this.sign(
      { typ: "at+jwt" },
      { iss: ISSUER, sub: person.sub, aud: APP_CLIENT, client_id: APP_CLIENT, scope: "openid profile email groups", jti: crypto.randomUUID(), iat: now, exp: now + 900, ...claims },
    );
    this.userinfo.set(token, {
      sub: person.sub,
      email: person.email,
      email_verified: true,
      name: person.email,
      groups: [ACCESS_GROUP],
      ...userinfo,
    });
    return token;
  }

  /** An ID token from the same sign-in; by default an MFA one through SSO. */
  async idToken(person: Person, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return this.sign(
      { typ: "JWT", ...header },
      { iss: ISSUER, sub: person.sub, aud: APP_CLIENT, iat: now, exp: now + 900, auth_time: now - 10, amr: ["fed", "mfa"], acr: ACR_MFA, ...claims },
    );
  }
}

export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** How a request reaches the Worker: the whole fetch entry by default. */
export type Send = (request: Request, env: Bindings) => Promise<Response>;

export async function enrolmentChallenge(token: string, env: Bindings = appEnv(), send: Send = call): Promise<string> {
  const res = await send(new Request(`${ORIGIN}${ATTEST_CHALLENGE_PATH}`, { method: "POST", headers: bearer(token) }), env);
  if (res.status !== 200) throw new Error(`challenge: ${res.status}`);
  return ((await res.json()) as { challenge: string }).challenge;
}

export function register(token: string, body: Record<string, unknown>, env: Bindings = appEnv(), send: Send = call): Promise<Response> {
  return send(
    new Request(`${ORIGIN}${ATTEST_REGISTER_PATH}`, {
      method: "POST",
      headers: { ...bearer(token), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    env,
  );
}

export interface EnrolledDevice extends TestDevice {
  appId: string;
  sessionChallenge: string;
  /** The next counter to sign with. */
  counter: number;
  extensions?: Map<string, CBORType>;
}

/** Challenge, attest, register: an active Mac for `person`. */
export async function enrol(
  ca: TestCa,
  id: IdentityStub,
  person: Person,
  opts: { appId?: string; attest?: AttestOptions; env?: Bindings; label?: string; send?: Send } = {},
): Promise<EnrolledDevice> {
  const env = opts.env ?? appEnv();
  const appId = opts.appId ?? APP_ID;
  const token = await id.accessToken(person, env);
  const challenge = await enrolmentChallenge(token, env, opts.send);
  const attestOpts: AttestOptions = { appId, aclBlob: MACOS_ACL_BLOB, extensions: appleExtensions(4, "1.0"), ...opts.attest };
  const device = await attest(ca, challenge, attestOpts);
  const res = await register(
    token,
    { challenge, keyId: device.keyId, attestation: device.attestation, appId, deviceLabel: opts.label ?? "Test Mac", idToken: await id.idToken(person) },
    env,
    opts.send,
  );
  if (res.status !== 201) throw new Error(`register: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { sessionChallenge: string };
  return { ...device, appId, sessionChallenge: body.sessionChallenge, counter: 1 };
}

export interface SignedOpts {
  method?: string;
  path?: string;
  body?: string;
  /** Send this body instead of the signed one. */
  sendBody?: string;
  time?: number;
  nonce?: string;
  challenge?: string;
  counter?: number;
  /** Sign over this token's hash, but send `token`. */
  signedToken?: string;
  /** Header overrides, applied last; null removes the header. */
  headers?: Record<string, string | null>;
  extensions?: Map<string, CBORType>;
  /** Sign with this App ID in authenticatorData (RP ID). */
  rpAppId?: string;
}

/** A request signed the way the app signs it. Advances device.counter unless opts.counter is given. */
export async function signed(device: EnrolledDevice, token: string, opts: SignedOpts = {}): Promise<Request> {
  const method = opts.method ?? "GET";
  const path = opts.path ?? "/api/me";
  const time = opts.time ?? Date.now();
  const nonce = opts.nonce ?? crypto.randomUUID().replace(/-/g, "");
  const challenge = opts.challenge ?? device.sessionChallenge;
  const counter = opts.counter ?? device.counter++;
  const data = clientData({
    appId: device.appId,
    keyId: device.keyId,
    method,
    pathAndQuery: path,
    bodySha256: toHex(await sha256(opts.body ?? "")),
    tokenSha256: toHex(await sha256(opts.signedToken ?? token)),
    time,
    nonce,
    challenge,
  });
  const headers = new Headers({
    ...bearer(token),
    [APP_HEADER.app]: device.appId,
    [APP_HEADER.key]: device.keyId,
    [APP_HEADER.time]: String(time),
    [APP_HEADER.nonce]: nonce,
    [APP_HEADER.challenge]: challenge,
    [APP_HEADER.assertion]: await assertion(device, data, counter, opts.rpAppId ?? device.appId, opts.extensions ?? device.extensions),
  });
  for (const [name, value] of Object.entries(opts.headers ?? {})) {
    if (value === null) headers.delete(name);
    else headers.set(name, value);
  }
  const body = opts.sendBody ?? opts.body;
  return new Request(`${ORIGIN}${path}`, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body });
}

/** Log lines with this message, as their `data`. */
export function logged(spy: { mock: { calls: unknown[][] } }, message: string): Record<string, unknown>[] {
  return spy.mock.calls
    .map((args) => args[0] as { message?: string; data?: Record<string, unknown> })
    .filter((line) => line?.message === message)
    .map((line) => line.data ?? {});
}

/** Every console line from log, warn and error, as JSON text, to check nothing secret was logged. */
export function captureLogs(): string[] {
  const lines: string[] = [];
  for (const level of ["debug", "log", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void lines.push(JSON.stringify(args)));
  }
  return lines;
}
