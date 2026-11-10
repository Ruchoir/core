/**
 * What the app gives the client: the few things that differ between Expo, a Tauri webview and Node.
 * The client itself touches no global, so it runs the same everywhere.
 */

/** The part of a `fetch` response the client reads. */
export interface HttpResponse {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
}

/** The part of `fetch` the client calls. The global `fetch` of Node, Expo and browsers fits. */
export type Fetch = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<HttpResponse>;

/**
 * The secure storage of the device: `expo-secure-store` (with `WHEN_UNLOCKED_THIS_DEVICE_ONLY`) on
 * the phone. Keys only use letters, digits, `.`, `-` and `_`, which every keychain accepts.
 */
export interface SecureStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

/** A public key of Propolis's JWK set, as published. */
export interface PublicJwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  kid?: string;
  alg?: string;
  use?: string;
}

export interface Platform {
  fetch: Fetch;
  /**
   * Open `url` in the authentication browser and resolve with the address Propolis sent it back to,
   * query included (`com.ruchoir.app:/oauth/callback?code=...`). On the phone this is
   * `WebBrowser.openAuthSessionAsync(url, redirectUri)`; on the desktop, the system browser and a
   * loopback listener (RFC 8252, section 7.3). Reject when the person closes the browser.
   */
  authorize(url: string, redirectUri: string): Promise<string>;
  storage: SecureStorage;
  /** Cryptographically secure random bytes (`crypto.getRandomValues`, `expo-crypto`). */
  randomBytes(length: number): Uint8Array;
  /** The SHA-256 digest of `data` (`crypto.subtle.digest`, `expo-crypto`). */
  sha256(data: Uint8Array): Promise<Uint8Array>;
  /**
   * Verify an ES256 signature (`r || s`, 64 bytes) of `data` with `key`. When the platform gives
   * none, WebCrypto is used where it exists. Where neither exists (Hermes without a WebCrypto
   * polyfill), the ID token's signature is not checked: it comes straight from Propolis's token
   * endpoint over TLS, which OpenID Connect Core (section 3.1.3.7) accepts in place of the
   * signature. Every claim is still checked.
   */
  verifyEs256?(key: PublicJwk, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
  /** The clock, in milliseconds since the epoch. `Date.now` by default. */
  now?(): number;
}
