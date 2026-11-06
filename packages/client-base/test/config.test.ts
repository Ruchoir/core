// Run with `pnpm --filter @ruchoir/client-base test` (Node's own runner, types stripped by Node).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import { absoluteUrl, apiBase, authInit, clientOptions, configureClient, resetClientForTests, withOptions } from "../src/config.ts";

beforeEach(() => resetClientForTests());

test("the_web_defaults_are_relative_and_carry_the_cookie", () => {
  assert.equal(apiBase(), "/api/v1");
  assert.equal(absoluteUrl("/api/v1/users/u1/avatar"), "/api/v1/users/u1/avatar");
  assert.deepEqual(authInit(), { credentials: "same-origin", headers: {} });
});

test("an_app_names_its_instance_and_presents_its_bearer", () => {
  configureClient({ baseUrl: "https://a.test/", authorization: () => "Bearer t1" });
  // A trailing slash is dropped, so paths join cleanly.
  assert.equal(apiBase(), "https://a.test/api/v1");
  assert.equal(absoluteUrl("/api/v1/users/u1/avatar"), "https://a.test/api/v1/users/u1/avatar");
  assert.equal(absoluteUrl("data:image/png;base64,AA"), "data:image/png;base64,AA");
  assert.deepEqual(authInit(), { credentials: "omit", headers: { authorization: "Bearer t1" } });
});

test("a_change_keeps_the_options_it_does_not_name", () => {
  const isBackground = () => true;
  configureClient({ baseUrl: "https://a.test", isBackground });
  configureClient({ authorization: () => "Bearer t2" });
  assert.equal(clientOptions().baseUrl, "https://a.test");
  assert.equal(clientOptions().isBackground, isBackground);
  // A client of its own starts from the defaults, not from the default client's options.
  assert.equal(withOptions({}).baseUrl, "");
  assert.equal(withOptions({}).isBackground, undefined);
});
