/** Why a step failed. An app branches on `code`; `message` is for logs and never holds a token. */
export type NativeErrorCode =
  /** A manifest, product description or discovery document is missing or unreadable. */
  | "discovery"
  /** The device could not reach the server. Nothing was lost: try again. */
  | "network"
  /** The authorization response does not carry the `state` the sign-in left with. */
  | "state"
  /** The authorization response names another issuer, or none (RFC 9207). */
  | "issuer"
  /** Propolis answered the authorization request with an error (`error` in `detail`). */
  | "denied"
  /** The token endpoint refused a request (its `error` in `detail`). */
  | "token"
  /** The ID token failed a check. */
  | "id_token"
  /** The refresh token was spent or revoked: the person signs in again. */
  | "session_ended"
  /** No grant is kept for this issuer. */
  | "signed_out";

export class NativeError extends Error {
  readonly code: NativeErrorCode;
  readonly detail: string | undefined;

  constructor(code: NativeErrorCode, message: string, detail?: string) {
    super(message);
    this.name = "NativeError";
    this.code = code;
    this.detail = detail;
  }
}
