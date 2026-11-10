// Run with `pnpm --filter @ruchoir/native-client test` (Node's own runner, types stripped by Node).
import { test } from "node:test";
import assert from "node:assert/strict";

import { NativeClient } from "../src/client.ts";
import { discoverInstance, manifestUrl } from "../src/discovery.ts";
import { base64url, fromBase64url, fromUtf8, queryOf, utf8 } from "../src/encoding.ts";
import { NativeError } from "../src/errors.ts";
import { world, type World } from "./standIn.ts";

const REDIRECT = "com.ruchoir.app:/oauth/callback";
const DRIVE = "https://drive.example.org";
const HUB = "https://hub.example.org";

function client(w: World): NativeClient {
  return new NativeClient({ platform: w.platform, clientId: "ruchoir-mobile", redirectUri: REDIRECT });
}

async function rejects(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof NativeError && error.code === code);
}

test("encoding round-trips", () => {
  for (const text of ["", "a", "ab", "abc", "été ✓ 𝄞"]) {
    assert.equal(fromUtf8(fromBase64url(base64url(utf8(text)))), text);
  }
  assert.equal(base64url(Uint8Array.from([251, 255])), "-_8");
  assert.deepEqual([...queryOf("x:/c?a=1&b=two%20words&a=2#f")], [["a", "1"], ["b", "two words"]]);
});

test("an instance is discovered from its domain", async () => {
  const w = world();
  assert.equal(manifestUrl("example.org"), "https://hub.example.org/.well-known/ruchoir-manifest");
  const instance = await discoverInstance(w.platform.fetch, "example.org");
  assert.equal(instance.issuer, "https://id.example.org");
  assert.deepEqual(
    instance.products.map((p) => [p.name, p.url, p.description?.version ?? null]),
    [
      ["hub", HUB, "0.2.0"],
      ["drive", DRIVE, "0.3.0"],
      // A product that does not answer is still listed, without a description.
      ["calendar", "https://calendar.example.org", null],
    ],
  );
});

test("signing in follows RFC 8252 and keeps one refresh token per issuer", async () => {
  const w = world();
  const instance = await discoverInstance(w.platform.fetch, "example.org");
  let authorizeUrl = "";
  const browser = w.browser.authorize;
  w.browser.authorize = (url, redirectUri) => {
    authorizeUrl = url;
    return browser(url, redirectUri);
  };
  const account = await client(w).signIn(instance);
  assert.deepEqual(account, { issuer: "https://id.example.org", subject: "person-1", name: "Ada", email: undefined });

  const query = queryOf(authorizeUrl);
  assert.equal(query.get("code_challenge_method"), "S256");
  assert.equal(query.get("client_id"), "ruchoir-mobile");
  assert.equal(query.get("redirect_uri"), REDIRECT);
  assert.ok(query.get("state") && query.get("nonce"));
  assert.match(query.get("scope")!, /offline_access/);
  const resources = authorizeUrl.split("&").filter((p) => p.startsWith("resource="));
  assert.equal(resources.length, 3);

  const exchange = w.propolis.tokenRequests[0];
  assert.equal(exchange.get("grant_type"), "authorization_code");
  assert.equal(exchange.has("client_secret"), false);

  const stored = [...w.storage.values.values()].join("\n");
  assert.match(stored, /"refreshToken":"r\d+"/);
  assert.doesNotMatch(stored, /"a\d+@/, "access tokens are never stored");
  assert.deepEqual(await client(w).issuers(), ["https://id.example.org"]);
});

test("the response must carry the issuer and the state the sign-in left with", async () => {
  const w = world();
  w.browser.authorize = (url, redirectUri) => w.propolis.authorize(url, redirectUri, "https://id.other.example");
  await rejects(client(w).signIn({ issuer: "https://id.example.org", resources: [DRIVE] }), "issuer");

  w.browser.authorize = (url, redirectUri) => w.propolis.authorize(url, redirectUri).replace(/state=[^&]+/, "state=forged");
  await rejects(client(w).signIn({ issuer: "https://id.example.org", resources: [DRIVE] }), "state");

  w.browser.authorize = (_url, redirectUri) => `${redirectUri}?error=access_denied&state=x&iss=https%3A%2F%2Fid.example.org`;
  await rejects(client(w).signIn({ issuer: "https://id.example.org" }), "state");
  assert.deepEqual(await client(w).issuers(), []);
});

test("the ID token is checked: nonce, audience, issuer and signature", async () => {
  for (const tamper of [{ nonce: "other" }, { aud: "another-app" }, { iss: "https://id.other.example" }, { foreignKey: true }]) {
    const w = world();
    w.propolis.tamper = tamper;
    await rejects(client(w).signIn({ issuer: "https://id.example.org", resources: [DRIVE] }), "id_token");
    assert.equal(w.storage.values.size, 0, JSON.stringify(tamper));
  }
});

test("access tokens are per product, kept in memory and refreshed a minute before expiry", async () => {
  const w = world();
  const app = client(w);
  await app.signIn({ issuer: "https://id.example.org", resources: [DRIVE, HUB] });
  const issuer = "https://id.example.org";

  // The code's token is the first resource's.
  const drive = await app.accessToken(issuer, DRIVE);
  assert.match(drive, new RegExp(`@${DRIVE}$`));
  assert.equal(w.propolis.tokenRequests.length, 1);

  // Two products at once: the refreshes run one after the other, each with the rotated token.
  const [hub, again] = await Promise.all([app.accessToken(issuer, HUB), app.accessToken(issuer, HUB)]);
  assert.equal(hub, again);
  assert.match(hub, new RegExp(`@${HUB}$`));
  assert.equal(w.propolis.tokenRequests.length, 2);
  assert.equal(w.propolis.tokenRequests[1].get("resource"), HUB);

  // Four minutes later the drive's token has less than a minute left.
  w.clock.now += 241_000;
  const next = await app.accessToken(issuer, DRIVE);
  assert.notEqual(next, drive);
  const [first, second] = [w.propolis.tokenRequests[1], w.propolis.tokenRequests[2]];
  assert.notEqual(first.get("refresh_token"), second.get("refresh_token"), "the rotated token is used");
  assert.equal(w.propolis.spent.size, 2);
});

test("a refused refresh token ends the session", async () => {
  const w = world();
  const app = client(w);
  const issuer = "https://id.example.org";
  await app.signIn({ issuer, resources: [DRIVE] });
  w.propolis.live.clear();
  await rejects(app.accessToken(issuer, HUB), "session_ended");
  assert.deepEqual(await app.issuers(), []);
  assert.equal(await app.account(issuer), null);
  await rejects(app.accessToken(issuer, DRIVE), "signed_out");
});

test("several instances keep separate grants, and signing out revokes one", async () => {
  const w = world();
  const app = client(w);
  await app.signIn({ issuer: "https://id.example.org", resources: [DRIVE] });
  await app.signIn({ issuer: "https://id.other.example", resources: ["https://drive.other.example"] });
  assert.deepEqual(await app.issuers(), ["https://id.example.org", "https://id.other.example"]);

  const live = [...w.propolis.live];
  await app.signOut("https://id.example.org");
  assert.deepEqual(w.propolis.revoked, live);
  assert.deepEqual(await app.issuers(), ["https://id.other.example"]);
  assert.ok(await app.accessToken("https://id.other.example", "https://drive.other.example"));
  await rejects(app.accessToken("https://id.example.org", DRIVE), "signed_out");
});
