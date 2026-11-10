/**
 * Base64url, UTF-8 and query strings, written out so the client needs neither `btoa`, `URL` nor
 * `TextEncoder`, which React Native does not always provide in full.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Base64url without padding (RFC 4648, section 5). */
export function base64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += ALPHABET[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += ALPHABET[n & 63];
  }
  return out;
}

/** The bytes of base64url text, padded or not. Throws on any other character. */
export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  const clean = text.replace(/=+$/, "");
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    const value = ALPHABET.indexOf(char);
    if (value < 0) throw new Error("not base64url");
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 255);
    }
  }
  return Uint8Array.from(out);
}

/** The UTF-8 bytes of `text`. */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(unescape(encodeURIComponent(text)), (c) => c.charCodeAt(0));
}

/** The text of UTF-8 bytes. */
export function fromUtf8(bytes: Uint8Array): string {
  return decodeURIComponent(escape(String.fromCharCode(...bytes)));
}

/** `application/x-www-form-urlencoded` pairs, a name repeated as often as it appears. */
export function form(pairs: [string, string][]): string {
  return pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

/** The address before its query and fragment. */
export function withoutQuery(address: string): string {
  return address.split("#")[0].split("?")[0];
}

/** The parameters of an address's query, the first value of each name. */
export function queryOf(address: string): Map<string, string> {
  const params = new Map<string, string>();
  const query = address.split("#")[0].split("?").slice(1).join("?");
  for (const part of query.split("&")) {
    if (!part) continue;
    const [name, ...rest] = part.split("=");
    const decode = (s: string) => decodeURIComponent(s.replace(/\+/g, " "));
    const key = decode(name);
    if (!params.has(key)) params.set(key, decode(rest.join("=")));
  }
  return params;
}

/** Whether an address may carry tokens: `https`, or `http` to this device's loopback. */
export function secure(address: string): boolean {
  return /^https:\/\/[^/?#]+/.test(address) || /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?(\/|$)/.test(address);
}
