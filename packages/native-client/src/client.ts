/**
 * Sign-in and tokens of a native app (RFC 8252, Propolis's design, section 11).
 *
 * - Signing in: an authorization request with an `S256` challenge, `state`, `nonce` and the
 *   products as `resource` (RFC 8707), opened in the authentication browser; the response's `state`
 *   and `iss` (RFC 9207) checked; the code traded at the token endpoint as a public client; the ID
 *   token checked.
 * - One grant per issuer: its refresh token in the device's secure storage, replaced at each
 *   rotation. A refresh token Propolis refuses (spent, revoked) ends the grant.
 * - One access token per product, its `resource`, in memory only, refreshed a minute before it
 *   expires. Refreshes of one issuer run one at a time, so a rotation is never raced.
 * - Signing out revokes the refresh token (RFC 7009) and forgets the grant.
 *
 * In a webview, `fetch` must not be the page's: Propolis refuses a token request that carries
 * `Origin` or `Sec-Fetch-Site` (design, section 9.3). Hand the client a fetch that runs outside the
 * page, or use the `ruchoir-native` crate in the desktop's core.
 */

import { discoverIssuer, type IssuerMetadata, type Product } from "./discovery.ts";
import { base64url, form, queryOf, utf8, withoutQuery } from "./encoding.ts";
import { NativeError } from "./errors.ts";
import { checkIdToken } from "./idToken.ts";
import type { Platform } from "./platform.ts";

/** How long before its expiry an access token is refreshed. */
export const REFRESH_MARGIN_MS = 60_000;

/** The scopes asked by default: `offline_access` brings the refresh token. */
export const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

export interface NativeClientOptions {
  platform: Platform;
  /** The app's client id at Propolis (`ruchoir-mobile`, `ruchoir-desktop`). */
  clientId: string;
  /**
   * Where Propolis sends the browser back: `com.ruchoir.app:/oauth/callback` on the phone,
   * `http://127.0.0.1:<port>/callback` on the desktop.
   */
  redirectUri: string;
  scopes?: string[];
  /** The prefix of the storage keys, `ruchoir` by default. */
  storagePrefix?: string;
}

/** What to sign in to: an `Instance` from `discoverInstance` fits. */
export interface SignInTarget {
  issuer: string;
  /** The products whose origins are asked as resources, unless `resources` is given. */
  products?: Product[];
  resources?: string[];
}

/** A signed-in person on one instance. */
export interface Account {
  issuer: string;
  subject: string;
  name?: string;
  email?: string;
}

/** What the secure storage keeps for one issuer. */
interface Grant extends Account {
  clientId: string;
  refreshToken: string;
  tokenEndpoint: string;
  revocationEndpoint?: string;
}

interface Cached {
  token: string;
  expiresAt: number;
}

interface TokenAnswer {
  access_token?: unknown;
  expires_in?: unknown;
  refresh_token?: unknown;
  id_token?: unknown;
  error?: unknown;
}

export class NativeClient {
  readonly #platform: Platform;
  readonly #clientId: string;
  readonly #redirectUri: string;
  readonly #scopes: string[];
  readonly #prefix: string;
  /** Access tokens by issuer, then by resource. Never stored. */
  readonly #tokens = new Map<string, Map<string, Cached>>();
  /** The tail of each issuer's queue of refreshes. */
  readonly #queues = new Map<string, Promise<unknown>>();

  constructor(options: NativeClientOptions) {
    this.#platform = options.platform;
    this.#clientId = options.clientId;
    this.#redirectUri = options.redirectUri;
    this.#scopes = options.scopes ?? DEFAULT_SCOPES;
    this.#prefix = options.storagePrefix ?? "ruchoir";
  }

  #now(): number {
    return this.#platform.now?.() ?? Date.now();
  }

  #random(): string {
    return base64url(this.#platform.randomBytes(32));
  }

  #grantKey(issuer: string): string {
    return `${this.#prefix}.grant.${base64url(utf8(issuer))}`;
  }

  get #indexKey(): string {
    return `${this.#prefix}.issuers`;
  }

  /** Run `task` after every earlier task of `issuer`, whatever they ended with. */
  #serial<T>(issuer: string, task: () => Promise<T>): Promise<T> {
    const previous = this.#queues.get(issuer) ?? Promise.resolve();
    const run = previous.then(task, task);
    this.#queues.set(
      issuer,
      run.catch(() => undefined),
    );
    return run;
  }

  /** The issuers a grant is kept for, in the order they were signed in. */
  async issuers(): Promise<string[]> {
    const raw = await this.#platform.storage.get(this.#indexKey);
    try {
      const list: unknown = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list.filter((i): i is string => typeof i === "string") : [];
    } catch {
      return [];
    }
  }

  async #grant(issuer: string): Promise<Grant | null> {
    const raw = await this.#platform.storage.get(this.#grantKey(issuer));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as Grant;
    } catch {
      return null;
    }
  }

  async #keep(grant: Grant): Promise<void> {
    await this.#platform.storage.set(this.#grantKey(grant.issuer), JSON.stringify(grant));
    const issuers = await this.issuers();
    if (!issuers.includes(grant.issuer)) {
      await this.#platform.storage.set(this.#indexKey, JSON.stringify([...issuers, grant.issuer]));
    }
  }

  async #forget(issuer: string): Promise<void> {
    this.#tokens.delete(issuer);
    await this.#platform.storage.delete(this.#grantKey(issuer));
    const issuers = await this.issuers();
    await this.#platform.storage.set(this.#indexKey, JSON.stringify(issuers.filter((i) => i !== issuer)));
  }

  #cache(issuer: string, resource: string, answer: TokenAnswer): string {
    if (typeof answer.access_token !== "string") throw new NativeError("token", "no access token");
    const lifetime = typeof answer.expires_in === "number" ? answer.expires_in : 300;
    let byResource = this.#tokens.get(issuer);
    if (!byResource) this.#tokens.set(issuer, (byResource = new Map()));
    byResource.set(resource, { token: answer.access_token, expiresAt: this.#now() + lifetime * 1000 });
    return answer.access_token;
  }

  #fresh(issuer: string, resource: string): string | null {
    const cached = this.#tokens.get(issuer)?.get(resource);
    return cached && this.#now() < cached.expiresAt - REFRESH_MARGIN_MS ? cached.token : null;
  }

  async #post(endpoint: string, pairs: [string, string][]): Promise<{ status: number; ok: boolean; body: TokenAnswer }> {
    let response;
    try {
      response = await this.#platform.fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: form(pairs),
      });
    } catch (error) {
      throw new NativeError("network", `${endpoint}: ${String(error)}`);
    }
    const body = ((await response.json().catch(() => null)) ?? {}) as TokenAnswer;
    return { status: response.status, ok: response.ok, body };
  }

  /** Sign in to `target` in the authentication browser, and keep the grant. */
  async signIn(target: SignInTarget): Promise<Account> {
    const metadata: IssuerMetadata = await discoverIssuer(this.#platform.fetch, target.issuer);
    const issuer = metadata.issuer;
    const resources = target.resources ?? (target.products ?? []).map((p) => p.url);
    const verifier = this.#random();
    const state = this.#random();
    const nonce = this.#random();
    const challenge = base64url(await this.#platform.sha256(utf8(verifier)));
    const params: [string, string][] = [
      ["response_type", "code"],
      ["client_id", this.#clientId],
      ["redirect_uri", this.#redirectUri],
      ["scope", this.#scopes.join(" ")],
      ["state", state],
      ["nonce", nonce],
      ["code_challenge", challenge],
      ["code_challenge_method", "S256"],
      ...resources.map((r): [string, string] => ["resource", r]),
    ];
    const separator = metadata.authorization_endpoint.includes("?") ? "&" : "?";
    const callback = await this.#platform.authorize(
      `${metadata.authorization_endpoint}${separator}${form(params)}`,
      this.#redirectUri,
    );

    if (withoutQuery(callback) !== withoutQuery(this.#redirectUri)) {
      throw new NativeError("state", "the browser came back to another address");
    }
    const answer = queryOf(callback);
    // The issuer first: an answer from another instance is not read any further (RFC 9207).
    if (answer.get("iss") !== issuer) throw new NativeError("issuer", "the response names another issuer");
    if (answer.get("state") !== state) throw new NativeError("state", "the response carries another state");
    const error = answer.get("error");
    if (error) throw new NativeError("denied", `sign-in refused: ${error}`, error);
    const code = answer.get("code");
    if (!code) throw new NativeError("denied", "the response carries no code");

    const { ok, status, body } = await this.#post(metadata.token_endpoint, [
      ["grant_type", "authorization_code"],
      ["code", code],
      ["redirect_uri", this.#redirectUri],
      ["client_id", this.#clientId],
      ["code_verifier", verifier],
    ]);
    if (!ok) {
      const reason = typeof body.error === "string" ? body.error : String(status);
      throw new NativeError("token", `the code was refused: ${reason}`, reason);
    }
    if (typeof body.refresh_token !== "string") throw new NativeError("token", "no refresh token (offline_access)");
    if (typeof body.id_token !== "string") throw new NativeError("token", "no ID token (openid)");
    const claims = await checkIdToken(this.#platform, body.id_token, {
      issuer,
      clientId: this.#clientId,
      nonce,
      jwksUri: metadata.jwks_uri,
    });

    const grant: Grant = {
      issuer,
      subject: claims.sub,
      name: typeof claims.name === "string" ? claims.name : undefined,
      email: typeof claims.email === "string" ? claims.email : undefined,
      clientId: this.#clientId,
      refreshToken: body.refresh_token,
      tokenEndpoint: metadata.token_endpoint,
      revocationEndpoint: metadata.revocation_endpoint,
    };
    await this.#serial(issuer, async () => {
      const previous = await this.#grant(issuer);
      this.#tokens.delete(issuer);
      await this.#keep(grant);
      // A new sign-in replaces the earlier grant: Propolis forgets it too.
      if (previous && previous.refreshToken !== grant.refreshToken) await this.#revoke(previous);
      // Without `resource`, the code's access token is for the first resource asked, or Propolis.
      this.#cache(issuer, resources[0] ?? issuer, body);
    });
    return { issuer, subject: grant.subject, name: grant.name, email: grant.email };
  }

  /** The person signed in at `issuer`, or `null`. */
  async account(issuer: string): Promise<Account | null> {
    const grant = await this.#grant(issuer);
    return grant ? { issuer, subject: grant.subject, name: grant.name, email: grant.email } : null;
  }

  /**
   * An access token for `resource` (a product's origin) at `issuer`, from memory while it has more
   * than a minute left, else refreshed. Throws `session_ended` when Propolis refused the refresh
   * token: the grant is gone and the person signs in again.
   */
  async accessToken(issuer: string, resource: string): Promise<string> {
    const cached = this.#fresh(issuer, resource);
    if (cached) return cached;
    return this.#serial(issuer, async () => {
      const again = this.#fresh(issuer, resource);
      if (again) return again;
      const grant = await this.#grant(issuer);
      if (!grant) throw new NativeError("signed_out", "no grant for this issuer");
      const { ok, status, body } = await this.#post(grant.tokenEndpoint, [
        ["grant_type", "refresh_token"],
        ["refresh_token", grant.refreshToken],
        ["client_id", grant.clientId],
        ["resource", resource],
      ]);
      if (!ok) {
        const reason = typeof body.error === "string" ? body.error : String(status);
        if (reason === "invalid_grant") {
          await this.#forget(issuer);
          throw new NativeError("session_ended", "the refresh token was refused", reason);
        }
        throw new NativeError("token", `the refresh was refused: ${reason}`, reason);
      }
      // The rotated refresh token is kept before the access token is handed out: the old one is
      // spent, and using it again would end the grant.
      if (typeof body.refresh_token === "string" && body.refresh_token !== grant.refreshToken) {
        await this.#keep({ ...grant, refreshToken: body.refresh_token });
      }
      return this.#cache(issuer, resource, body);
    });
  }

  async #revoke(grant: Grant): Promise<void> {
    if (!grant.revocationEndpoint) return;
    // Best effort: the grant is forgotten on the device whatever Propolis answers.
    await this.#post(grant.revocationEndpoint, [
      ["token", grant.refreshToken],
      ["token_type_hint", "refresh_token"],
      ["client_id", grant.clientId],
    ]).catch(() => undefined);
  }

  /** Revoke the grant of `issuer` (RFC 7009) and forget it, with its access tokens. */
  async signOut(issuer: string): Promise<void> {
    await this.#serial(issuer, async () => {
      const grant = await this.#grant(issuer);
      await this.#forget(issuer);
      if (grant) await this.#revoke(grant);
    });
  }
}
