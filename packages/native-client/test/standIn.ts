// A stand-in instance behind a fake `fetch`: the hub's manifest, a product's description, and a
// Propolis with its discovery document, key set, token and revocation endpoints. It signs ID tokens
// with a real P-256 key, and checks PKCE and refresh token rotation as Propolis does.

import { base64url, fromBase64url, queryOf, utf8 } from "../src/encoding.ts";
import type { Fetch, Platform, SecureStorage } from "../src/platform.ts";

const subtle = globalThis.crypto.subtle;

export class MemoryStorage implements SecureStorage {
  readonly values = new Map<string, string>();
  async get(key: string) {
    return this.values.get(key) ?? null;
  }
  async set(key: string, value: string) {
    this.values.set(key, value);
  }
  async delete(key: string) {
    this.values.delete(key);
  }
}

type Code = { challenge: string; nonce: string; clientId: string; resources: string[] };

export class StandInPropolis {
  readonly issuer: string;
  readonly keyPair: Promise<CryptoKeyPair>;
  readonly codes = new Map<string, Code>();
  /** Live refresh tokens, and the ones already used. */
  readonly live = new Set<string>();
  readonly spent = new Set<string>();
  readonly revoked: string[] = [];
  readonly tokenRequests: Map<string, string>[] = [];
  expiresIn = 300;
  /** What the ID token says, changed by a test to break one check. */
  tamper: { nonce?: string; aud?: string; iss?: string; foreignKey?: boolean } = {};
  #counter = 0;

  constructor(issuer: string) {
    this.issuer = issuer;
    this.keyPair = subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
  }

  async #sign(claims: Record<string, unknown>): Promise<string> {
    const key = this.tamper.foreignKey
      ? ((await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])) as CryptoKeyPair).privateKey
      : (await this.keyPair).privateKey;
    const head = base64url(utf8(JSON.stringify({ alg: "ES256", kid: "k1", typ: "JWT" })));
    const body = base64url(utf8(JSON.stringify(claims)));
    const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(`${head}.${body}`));
    return `${head}.${body}.${base64url(new Uint8Array(signature))}`;
  }

  /** The browser's part: Propolis signs the person in and sends the browser back with a code. */
  authorize(url: string, redirectUri: string, iss = this.issuer): string {
    const query = queryOf(url);
    const code = `code${++this.#counter}`;
    const resources = url
      .split("?")[1]
      .split("&")
      .filter((p) => p.startsWith("resource="))
      .map((p) => decodeURIComponent(p.slice("resource=".length)));
    this.codes.set(code, {
      challenge: query.get("code_challenge")!,
      nonce: query.get("nonce")!,
      clientId: query.get("client_id")!,
      resources,
    });
    return `${redirectUri}?code=${code}&state=${encodeURIComponent(query.get("state")!)}&iss=${encodeURIComponent(iss)}`;
  }

  #refresh(): string {
    const token = `r${++this.#counter}`;
    this.live.add(token);
    return token;
  }

  async handle(url: string, body: string): Promise<{ status: number; body: unknown }> {
    const path = url.slice(this.issuer.length);
    if (path === "/.well-known/openid-configuration") {
      return {
        status: 200,
        body: {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/oauth/authorize`,
          token_endpoint: `${this.issuer}/oauth/token`,
          jwks_uri: `${this.issuer}/oauth/jwks`,
          revocation_endpoint: `${this.issuer}/oauth/revoke`,
          authorization_response_iss_parameter_supported: true,
        },
      };
    }
    if (path === "/oauth/jwks") {
      const jwk = await subtle.exportKey("jwk", (await this.keyPair).publicKey);
      return { status: 200, body: { keys: [{ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, kid: "k1", alg: "ES256", use: "sig" }] } };
    }
    const form = queryOf(`?${body}`);
    if (path === "/oauth/revoke") {
      this.revoked.push(form.get("token")!);
      this.live.delete(form.get("token")!);
      return { status: 200, body: {} };
    }
    if (path !== "/oauth/token") return { status: 404, body: {} };
    this.tokenRequests.push(form);
    const n = ++this.#counter;
    if (form.get("grant_type") === "authorization_code") {
      const code = this.codes.get(form.get("code") ?? "");
      this.codes.delete(form.get("code") ?? "");
      const digest = new Uint8Array(await subtle.digest("SHA-256", utf8(form.get("code_verifier") ?? "")));
      if (!code || base64url(digest) !== code.challenge || code.clientId !== form.get("client_id")) {
        return { status: 400, body: { error: "invalid_grant" } };
      }
      const now = Math.floor(Date.now() / 1000);
      const idToken = await this.#sign({
        iss: this.tamper.iss ?? this.issuer,
        sub: "person-1",
        aud: this.tamper.aud ?? code.clientId,
        exp: now + 300,
        iat: now,
        nonce: this.tamper.nonce ?? code.nonce,
        name: "Ada",
      });
      return {
        status: 200,
        body: {
          access_token: `a${n}@${code.resources[0] ?? this.issuer}`,
          token_type: "Bearer",
          expires_in: this.expiresIn,
          refresh_token: this.#refresh(),
          id_token: idToken,
        },
      };
    }
    if (form.get("grant_type") === "refresh_token") {
      const held = form.get("refresh_token") ?? "";
      if (!this.live.has(held)) {
        // A spent token used again: Propolis revokes the whole grant.
        if (this.spent.has(held)) this.live.clear();
        return { status: 400, body: { error: "invalid_grant" } };
      }
      this.live.delete(held);
      this.spent.add(held);
      return {
        status: 200,
        body: {
          access_token: `a${n}@${form.get("resource")}`,
          token_type: "Bearer",
          expires_in: this.expiresIn,
          refresh_token: this.#refresh(),
        },
      };
    }
    return { status: 400, body: { error: "unsupported_grant_type" } };
  }
}

export interface World {
  platform: Platform;
  storage: MemoryStorage;
  propolis: StandInPropolis;
  others: StandInPropolis[];
  clock: { now: number };
  requests: string[];
  /** What the browser does with the authorization URL; the stand-in signs in by default. */
  browser: { authorize(url: string, redirectUri: string): string };
}

/** An instance at `example.org` (hub, drive, a calendar that does not answer), and a second Propolis. */
export function world(): World {
  const propolis = new StandInPropolis("https://id.example.org");
  const other = new StandInPropolis("https://id.other.example");
  const storage = new MemoryStorage();
  const clock = { now: Date.now() };
  const requests: string[] = [];
  const all = [propolis, other];
  const w: World = {
    storage,
    propolis,
    others: [other],
    clock,
    requests,
    browser: {
      authorize: (url, redirectUri) => {
        const target = all.find((p) => url.startsWith(p.issuer))!;
        return target.authorize(url, redirectUri);
      },
    },
    platform: undefined as unknown as Platform,
  };
  const fetch: Fetch = async (url, init) => {
    requests.push(`${init?.method ?? "GET"} ${url}`);
    let answer: { status: number; body: unknown };
    if (url === "https://hub.example.org/.well-known/ruchoir-manifest") {
      answer = {
        status: 200,
        body: {
          version: 1,
          domain: "example.org",
          services: {
            propolis: { url: "https://id.example.org" },
            hub: { url: "https://hub.example.org" },
            drive: { url: "https://drive.example.org" },
            calendar: { url: "https://calendar.example.org" },
          },
        },
      };
    } else if (url === "https://drive.example.org/.well-known/ruchoir-product") {
      answer = { status: 200, body: { name: "drive", version: "0.3.0", api: ["v1"], features: ["versions"] } };
    } else if (url === "https://hub.example.org/.well-known/ruchoir-product") {
      answer = { status: 200, body: { name: "hub", version: "0.2.0", api: ["v1"], features: [] } };
    } else {
      const target = all.find((p) => url.startsWith(`${p.issuer}/`));
      answer = target ? await target.handle(url, init?.body ?? "") : { status: 503, body: {} };
    }
    return { ok: answer.status < 300, status: answer.status, json: async () => answer.body };
  };
  w.platform = {
    fetch,
    authorize: async (url, redirectUri) => w.browser.authorize(url, redirectUri),
    storage,
    randomBytes: (length) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
    sha256: async (data) => new Uint8Array(await subtle.digest("SHA-256", new Uint8Array(data))),
    now: () => clock.now,
  };
  return w;
}

export { fromBase64url };
