#!/usr/bin/env node
/**
 * Ruchoir/core is released as one version: every crate and every package carries it, and a release
 * tag `vX.Y.Z` names it (ADR 0013 of Ruchoir/.github).
 *
 *     node scripts/check-version.mjs           every crate and package agree
 *     node scripts/check-version.mjs v0.2.0    and the tag names that version
 *
 * The version is `[workspace.package] version` in Cargo.toml. A crate inherits it
 * (`version.workspace = true`); a package writes it in its package.json.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const problems = [];

/** The value of `key` in the TOML table `[table]`, for the simple `key = "value"` lines used here. */
function tomlValue(text, table, key) {
  const section = text.split(/^\[/m).find((part) => part.startsWith(`${table}]`));
  return section?.match(new RegExp(`^${key.replace(".", "\\.")}\\s*=\\s*(.+)$`, "m"))?.[1].trim();
}

const workspace = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
const version = tomlValue(workspace, "workspace.package", "version")?.replace(/^"|"$/g, "");
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error('Cargo.toml: [workspace.package] needs version = "X.Y.Z"');
  process.exit(1);
}

for (const crate of readdirSync(join(ROOT, "crates"))) {
  const manifest = readFileSync(join(ROOT, "crates", crate, "Cargo.toml"), "utf8");
  if (tomlValue(manifest, "package", "version.workspace") !== "true") {
    problems.push(`crates/${crate}: the version must be version.workspace = true`);
  }
}

for (const name of readdirSync(join(ROOT, "packages"))) {
  const manifest = JSON.parse(readFileSync(join(ROOT, "packages", name, "package.json"), "utf8"));
  if (manifest.version !== version) {
    problems.push(`packages/${name}: version ${manifest.version}, the workspace is ${version}`);
  }
}

const tag = process.argv[2];
if (tag !== undefined && tag !== `v${version}`) {
  problems.push(`the tag ${tag} does not name the workspace version v${version}`);
}

if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  process.exit(1);
}
console.log(`version ${version}: every crate and package agree${tag ? `, and so does ${tag}` : ""}.`);
