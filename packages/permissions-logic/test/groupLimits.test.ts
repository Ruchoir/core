// Run with `pnpm --filter @ruchoir/permissions-logic test` (Node's own runner, types stripped by Node).
import assert from "node:assert/strict";
import { test } from "node:test";
import { GROUP_DESCRIPTION_MAX } from "../src/index.ts";

// The limit mirrors the server's (`DESCRIPTION_MAX` of its group routes), which this repository does
// not hold: it is pinned here, so that changing it is a decision taken with the server's.
test("the_group_description_limit_is_the_servers", () => {
  assert.equal(GROUP_DESCRIPTION_MAX, 280);
});
