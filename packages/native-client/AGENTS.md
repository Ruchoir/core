# AGENTS.md - packages/native-client

`@ruchoir/native-client`: how the Ruchoir apps (mobile, desktop) find an instance and sign in with its
Propolis, following OAuth 2.0 for Native Apps (RFC 8252) and Propolis's design
(`docs/design/openid-connect.md` of `Ruchoir/propolis`, section 11). The `ruchoir-native` crate holds
the same logic in Rust for the desktop's core. See the root `AGENTS.md` for the rules.

## Layout

```
src/platform.ts   Platform: what the app injects (fetch, the authentication browser, secure storage,
                  random bytes, SHA-256, optionally ES256 verification and the clock)
src/discovery.ts  discoverInstance (the hub's manifest, each product's description), discoverIssuer
src/client.ts     NativeClient: signIn, accessToken(issuer, resource), signOut, issuers, account
src/idToken.ts    checkIdToken: ES256, issuer, audience, nonce, expiry, signature
src/encoding.ts   base64url, UTF-8 and query strings without platform globals
src/errors.ts     NativeError and its codes
test/             node --test against a stand-in instance behind a fake fetch (test/standIn.ts)
```

Entry points (`package.json` `exports`): `.`, `./discovery`, `./client`, `./platform`.

## Rules

- **No global.** Every platform function is injected, so the code runs in Expo, in a Tauri webview
  and in Node. WebCrypto is only used, when present, to verify the ID token's signature.
- **Tokens.** One refresh token per issuer in the secure storage, replaced at each rotation and
  stored before the new access token is handed out; access tokens in memory only, one per product
  (`resource`), refreshed a minute before they expire; one refresh at a time per issuer.
- **Checks.** `iss` (RFC 9207) before `state`, then the code; the ID token's issuer, audience, nonce,
  expiry and signature. A refused refresh token (`invalid_grant`) forgets the grant.
- **Webviews.** Propolis refuses a token request carrying `Origin` or `Sec-Fetch-Site`: a webview
  hands the client a fetch that runs outside the page, or leaves the tokens to the Rust core.
- **Tests on Windows**: `pnpm test` quotes its glob for the CI's shell; run
  `node --test test/*.test.ts` from Git Bash.
