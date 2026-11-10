/**
 * `@ruchoir/native-client`: how the Ruchoir apps find an instance and sign in with its Propolis
 * (RFC 8252). Pure logic over the functions the app injects (`Platform`), so it runs in Expo, in a
 * Tauri webview and in Node.
 */

export { NativeClient, DEFAULT_SCOPES, REFRESH_MARGIN_MS } from "./client.ts";
export type { Account, NativeClientOptions, SignInTarget } from "./client.ts";
export { discoverInstance, discoverIssuer, manifestUrl } from "./discovery.ts";
export type { Instance, IssuerMetadata, Product, ProductDescription } from "./discovery.ts";
export { NativeError } from "./errors.ts";
export type { NativeErrorCode } from "./errors.ts";
export { checkIdToken, SKEW_SECONDS } from "./idToken.ts";
export type { IdClaims } from "./idToken.ts";
export type { Fetch, HttpResponse, Platform, PublicJwk, SecureStorage } from "./platform.ts";
