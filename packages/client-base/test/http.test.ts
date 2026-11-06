// Run with `pnpm --filter @ruchoir/client-base test` (Node's own runner, types stripped by Node).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import { configureClient, resetClientForTests } from "../src/config.ts";
import { apiRequest } from "../src/http.ts";
import { fakeFetch, header } from "./fakeFetch.ts";

// A product's own list of background writes, as one passes it when it creates its client. The
// transport knows none: these routes are only the test's.
function productBackground(request: { method: string; path: string }): boolean {
  const path = request.path.split("?")[0];
  if (request.method === "PUT") {
    return /^\/conversations\/[^/]+\/read$/.test(path) || path === "/notifications/read" || /^\/notifications\/[^/]+\/read$/.test(path) || path === "/push/devices" || path === "/push/subscription";
  }
  if (request.method === "POST") return path === "/realtime/typing" || /^\/files\/[^/]+\/office\/heartbeat$/.test(path);
  return false;
}

beforeEach(() => resetClientForTests());

test("requests_join_base_url_and_api_prefix", async () => {
  const calls = fakeFetch({ body: { ok: true } });
  configureClient({ baseUrl: "https://a.test" });
  await apiRequest("GET", "/auth/session");
  assert.equal(calls[0].url, "https://a.test/api/v1/auth/session");
});

test("bearer_is_sent_when_configured", async () => {
  const calls = fakeFetch({ body: {} });
  configureClient({ baseUrl: "https://a.test", authorization: () => "Bearer t1" });
  await apiRequest("GET", "/me/spaces");
  assert.equal(header(calls[0], "authorization"), "Bearer t1");
  assert.equal(calls[0].init.credentials, "omit");
});

test("web_defaults_stay_same_origin", async () => {
  const calls = fakeFetch({ body: {} });
  await apiRequest("GET", "/me/spaces");
  assert.equal(calls[0].url, "/api/v1/me/spaces");
  assert.equal(calls[0].init.credentials, "same-origin");
  assert.equal(header(calls[0], "authorization"), null);
});

test("a_401_calls_onUnauthorized_once", async () => {
  fakeFetch({ status: 401, body: { error: "unauthorized" } });
  let seen = 0;
  configureClient({ baseUrl: "https://a.test", onUnauthorized: () => seen++ });
  await assert.rejects(apiRequest("GET", "/auth/session"), (err: { status: number }) => err.status === 401);
  assert.equal(seen, 1);
});

test("a_204_resolves_undefined", async () => {
  fakeFetch({ status: 204 });
  assert.equal(await apiRequest("POST", "/auth/logout"), undefined);
});

test("a_401_tells_why", async () => {
  fakeFetch({ status: 401, body: { error: "invalid_credentials", message: "Invalid email or password." } });
  const codes: (string | undefined)[] = [];
  configureClient({ baseUrl: "https://a.test", onUnauthorized: (code) => codes.push(code) });
  // A wrong current password is a 401 too, and says so: the session itself is fine.
  await assert.rejects(apiRequest("POST", "/auth/password", {}));
  assert.deepEqual(codes, ["invalid_credentials"]);
});

test("a_write_refused_by_a_preview_calls_onPreviewReadOnly", async () => {
  fakeFetch({ status: 403, body: { error: "preview_read_only" } }, { status: 403, body: { error: "forbidden", reason: "preview_read_only" } }, { status: 403, body: { error: "forbidden", reason: "cannot_grant" } });
  const heard: string[] = [];
  configureClient({ baseUrl: "https://a.test", onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`) });
  for (let i = 0; i < 3; i++) await apiRequest("PUT", "/x").catch(() => {});
  assert.deepEqual(heard, ["PUT /x", "PUT /x"]);
});

test("a_preview_sends_no_background_write_and_toasts_nothing_unasked", async () => {
  const heard: string[] = [];
  let previewing = true;
  configureClient({ baseUrl: "https://a.test", previewActive: () => previewing, isBackground: productBackground, onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`) });
  const background = [
    ["PUT", "/conversations/c1/read"], ["PUT", "/notifications/n1/read?guest_notices=true"], ["PUT", "/notifications/read"],
    ["POST", "/realtime/typing"], ["PUT", "/push/devices"], ["PUT", "/push/subscription"], ["POST", "/files/f1/office/heartbeat?tab=t"],
  ] as const;
  // While previewing none of them leaves the client, and nothing is heard.
  const calls = fakeFetch();
  for (const [method, path] of background) await apiRequest(method, path);
  assert.equal(calls.length, 0);
  assert.deepEqual(heard, []);
  // What the person starts is sent, and its refusal is heard.
  fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("POST", "/conversations/c1/messages").catch(() => {});
  assert.deepEqual(heard, ["POST /conversations/c1/messages"]);
  // Reads are never held back.
  const reads = fakeFetch({ body: {} });
  await apiRequest("GET", "/conversations/c1/read");
  assert.equal(reads.length, 1);
  // Before the preview is known, a background write goes out; if the server refuses it, silently.
  previewing = false;
  fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("PUT", "/conversations/c1/read").catch(() => {});
  assert.deepEqual(heard, ["POST /conversations/c1/messages"]);
  // Outside a preview everything is sent as before.
  const normal = fakeFetch({ body: {} });
  await apiRequest("PUT", "/conversations/c1/read");
  assert.equal(normal.length, 1);
});

test("a_get_refused_for_rate_is_tried_once_more_after_the_wait_the_server_names", async () => {
  const calls = fakeFetch({ status: 429, body: { error: "rate_limited", retry_after: 0 } }, { body: { ok: true } });
  assert.deepEqual(await apiRequest("GET", "/me/spaces"), { ok: true });
  assert.equal(calls.length, 2);
});

test("a_second_429_is_the_answer_and_a_write_is_never_repeated", async () => {
  const calls = fakeFetch({ status: 429, body: { error: "rate_limited", retry_after: 0 } }, { status: 429, body: { error: "rate_limited", retry_after: 0 } });
  await assert.rejects(apiRequest("GET", "/x"), (err: { status: number }) => err.status === 429);
  assert.equal(calls.length, 2);
  const writes = fakeFetch({ status: 429, body: { error: "rate_limited", retry_after: 0 } }, { body: {} });
  await assert.rejects(apiRequest("POST", "/x", {}), (err: { status: number }) => err.status === 429);
  assert.equal(writes.length, 1);
});

test("a_long_wait_is_not_waited_for", async () => {
  const calls = fakeFetch({ status: 429, body: { error: "rate_limited", retry_after: 60 } }, { body: {} });
  await assert.rejects(apiRequest("GET", "/x"), (err: { status: number }) => err.status === 429);
  assert.equal(calls.length, 1);
});

test("the_product_decides_which_writes_are_background_ones", async () => {
  const asked: string[] = [];
  const heard: string[] = [];
  let previewing = true;
  configureClient({
    baseUrl: "https://a.test",
    previewActive: () => previewing,
    isBackground: (request) => {
      asked.push(`${request.method} ${request.path}`);
      return request.path === "/seen";
    },
    onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`),
  });
  // The product's answer holds its write back, and it is asked with the request as written.
  const held = fakeFetch();
  await apiRequest("PUT", "/seen");
  assert.equal(held.length, 0);
  assert.deepEqual(asked, ["PUT /seen"]);
  // Any other write goes out, and its refusal is heard.
  fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("PUT", "/other").catch(() => {});
  assert.deepEqual(heard, ["PUT /other"]);
  // Once sent before the preview was known, its own refusal stays silent.
  previewing = false;
  fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("PUT", "/seen").catch(() => {});
  assert.deepEqual(heard, ["PUT /other"]);
  // A read is never held back, so the product is not even asked about it.
  previewing = true;
  asked.length = 0;
  const reads = fakeFetch({ body: {} });
  await apiRequest("GET", "/seen");
  assert.equal(reads.length, 1);
  assert.deepEqual(asked, []);
});

test("a_request_can_say_it_is_a_background_write_itself", async () => {
  const heard: string[] = [];
  let previewing = true;
  configureClient({ baseUrl: "https://a.test", previewActive: () => previewing, onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`) });
  // With no list given, a write that says so is held back during a preview.
  const held = fakeFetch();
  await apiRequest("POST", "/typing", { json: {}, background: true });
  assert.equal(held.length, 0);
  // A read that says so is still sent: only writes are held back.
  const reads = fakeFetch({ body: {} });
  await apiRequest("GET", "/typing", { background: true });
  assert.equal(reads.length, 1);
  // Sent before the preview was known, its refusal is silent.
  previewing = false;
  fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("POST", "/typing", { json: {}, background: true }).catch(() => {});
  assert.deepEqual(heard, []);
});

test("what_a_request_says_wins_over_the_products_list", async () => {
  const heard: string[] = [];
  configureClient({ baseUrl: "https://a.test", previewActive: () => true, isBackground: () => true, onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`) });
  // The list holds every write back, but this one says it was asked for: it is sent, and heard.
  const calls = fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("PUT", "/x", { background: false }).catch(() => {});
  assert.equal(calls.length, 1);
  assert.deepEqual(heard, ["PUT /x"]);
});

test("without_a_list_a_preview_holds_nothing_back", async () => {
  const heard: string[] = [];
  configureClient({ baseUrl: "https://a.test", previewActive: () => true, onPreviewReadOnly: (request) => heard.push(`${request.method} ${request.path}`) });
  // This package names no route: a write the old list held back is now the product's to name.
  const calls = fakeFetch({ status: 403, body: { error: "preview_read_only" } });
  await apiRequest("PUT", "/conversations/c1/read").catch(() => {});
  assert.equal(calls.length, 1);
  assert.deepEqual(heard, ["PUT /conversations/c1/read"]);
});
