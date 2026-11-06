// Run with `pnpm --filter @ruchoir/permissions-logic test` (Node's own runner, types stripped by Node).
import assert from "node:assert/strict";
import { test } from "node:test";
import { groupColour, ROLE_COLOURS, ROLE_NAME_MAX } from "../src/index.ts";

// The name limit and the colours mirror the server's (its roles module), which this repository does
// not hold: they are pinned here, so that changing them is a decision taken with the server's.

test("the_role_name_limit_is_the_servers", () => {
  assert.equal(ROLE_NAME_MAX, 40);
});

test("the_role_colours_are_the_servers_in_the_same_order", () => {
  assert.deepEqual([...ROLE_COLOURS], ["sky", "mint", "violet", "pink", "peach", "lime", "sun"]);
});

test("a_group_wears_always_the_same_colour_from_the_list", () => {
  assert.equal(groupColour("g1"), groupColour("g1"));
  assert.ok((ROLE_COLOURS as readonly string[]).includes(groupColour("0b1c-xyz")));
});
