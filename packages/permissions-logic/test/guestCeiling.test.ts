// Run with `pnpm --filter @ruchoir/permissions-logic test` (Node's own runner, types stripped by Node).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CEILING_SENTENCES, GUEST_CEILING } from "../src/guestCeiling.ts";

// The engine is in this repository (`crates/ruchoir-permissions`): its own source is read, so a
// permission added to the ceiling there fails here until a sentence says it.
const crate = (file: string) => readFileSync(new URL(`../../../crates/ruchoir-permissions/src/${file}`, import.meta.url), "utf8");

test("the_ceiling_is_the_engines_and_every_permission_of_it_has_a_sentence", () => {
  const block = /pub const GUEST_CEILING: PermissionSet = PermissionSet::of\(&\[([\s\S]*?)\]\);/.exec(crate("system_roles.rs"))?.[1] ?? "";
  const names = [...block.matchAll(/Permission::(\w+)/g)].map((m) => m[1]);
  assert.ok(names.length > 0, "GUEST_CEILING not found in system_roles.rs");
  assert.equal(names.length, GUEST_CEILING.length);
  // Each Rust name, by its wire name in the catalogue, is in the list the screens read.
  const catalogue = crate("catalogue.rs");
  for (const name of names) {
    const wire = new RegExp(`\\b${name} = "([a-z_.]+)"`).exec(catalogue)?.[1];
    assert.ok(wire && (GUEST_CEILING as readonly string[]).includes(wire), `${name} (${wire}) missing from the ceiling`);
  }
  const covered = CEILING_SENTENCES.flatMap((s) => s.permissions);
  for (const permission of GUEST_CEILING) assert.ok(covered.includes(permission), `${permission} has no sentence`);
  for (const permission of covered) assert.ok((GUEST_CEILING as readonly string[]).includes(permission), `${permission} is not in the ceiling`);
});
