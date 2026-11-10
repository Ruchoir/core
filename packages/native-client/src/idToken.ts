/**
 * The checks of an ID token from Propolis's token endpoint (OpenID Connect Core, section 3.1.3.7):
 * ES256 only (never the algorithm a token claims beyond that), the issuer the sign-in started with,
 * this app as audience, the nonce it sent, expiry, and the signature against Propolis's JWK set.
 */

import { fromBase64url, fromUtf8, utf8 } from "./encoding.ts";
import { NativeError } from "./errors.ts";
import type { Platform, PublicJwk } from "./platform.ts";

/** The clock skew every check accepts, as Propolis does. */
export const SKEW_SECONDS = 60;

export interface IdClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  azp?: string;
  name?: string;
  email?: string;
  [claim: string]: unknown;
}

export interface Expected {
  issuer: string;
  clientId: string;
  nonce: string;
  jwksUri: string;
}

function refuse(why: string): never {
  throw new NativeError("id_token", `ID token refused: ${why}`);
}

function json(part: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(fromUtf8(fromBase64url(part)));
    if (value && typeof value === "object") return value as Record<string, unknown>;
  } catch {
    // Reported below.
  }
  return refuse("unreadable");
}

/** WebCrypto's ES256 verification, where the runtime has WebCrypto. */
function webCrypto(): Platform["verifyEs256"] {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) return undefined;
  return async (jwk, data, signature) => {
    const key = await subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(signature), new Uint8Array(data));
  };
}

/** The claims of `token` once every check passed. */
export async function checkIdToken(platform: Platform, token: string, expected: Expected): Promise<IdClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) refuse("not a compact JWS");
  const header = json(parts[0]);
  const claims = json(parts[1]) as Partial<IdClaims>;
  if (header.alg !== "ES256") refuse("not ES256");

  const now = (platform.now?.() ?? Date.now()) / 1000;
  if (claims.iss !== expected.issuer) refuse("another issuer");
  const audiences = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
  if (!audiences.includes(expected.clientId)) refuse("another audience");
  if (audiences.length > 1 && claims.azp !== expected.clientId) refuse("another authorized party");
  if (typeof claims.exp !== "number" || claims.exp + SKEW_SECONDS < now) refuse("expired");
  if (typeof claims.iat === "number" && claims.iat - SKEW_SECONDS > now) refuse("issued in the future");
  if (claims.nonce !== expected.nonce) refuse("another nonce");
  if (typeof claims.sub !== "string" || !claims.sub) refuse("no subject");

  const verify = platform.verifyEs256 ?? webCrypto();
  if (verify) {
    const kid = header.kid;
    if (typeof kid !== "string") refuse("no key id");
    const response = await platform.fetch(expected.jwksUri, { headers: { accept: "application/json" } }).catch(() => {
      throw new NativeError("network", "the key set could not be fetched");
    });
    const set = response.ok ? ((await response.json().catch(() => null)) as { keys?: PublicJwk[] } | null) : null;
    const key = set?.keys?.find(
      (k) => k.kid === kid && k.kty === "EC" && k.crv === "P-256" && (k.alg ?? "ES256") === "ES256" && (k.use ?? "sig") === "sig",
    );
    if (!key) refuse("unknown key");
    const signature = fromBase64url(parts[2]);
    const valid = signature.length === 64 && (await verify(key, utf8(`${parts[0]}.${parts[1]}`), signature).catch(() => false));
    if (!valid) refuse("bad signature");
  }
  return claims as IdClaims;
}
