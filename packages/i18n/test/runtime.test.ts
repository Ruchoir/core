// Run with `pnpm --filter @ruchoir/i18n test` (Node's own runner, types stripped by Node).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEFAULT_LOCALE,
  LOCALES,
  PRODUCT_NAMES,
  PRODUCTS,
  RESERVED_SECTIONS,
  SHARED_DICTIONARIES,
  asLocale,
  currentLocale,
  formatBytes,
  formatList,
  formatNumber,
  isLocale,
  matchBrowserLocale,
  setCurrentLocale,
  withShared,
} from "../src/index.ts";

test("six_languages_with_french_as_the_source", () => {
  assert.deepEqual(LOCALES, ["fr", "en", "es", "de", "it", "pl"]);
  assert.equal(DEFAULT_LOCALE, "fr");
  assert.ok(isLocale("pl"));
  assert.ok(!isLocale("pt"));
  assert.equal(asLocale("xx"), "fr");
});

test("a_regional_browser_language_lands_on_its_language", () => {
  assert.equal(matchBrowserLocale(["de-AT", "en"]), "de");
  assert.equal(matchBrowserLocale(["pt-BR", "it-IT"]), "it");
  assert.equal(matchBrowserLocale(["pt-BR"]), null);
});

test("formatting_follows_the_language_in_force", () => {
  setCurrentLocale("en");
  assert.equal(currentLocale(), "en");
  assert.equal(formatNumber(12345), "12,345");
  assert.equal(formatList(["Nadia", "Paul", "Léa"]), "Nadia, Paul, and Léa");
  setCurrentLocale("fr");
  assert.equal(formatList(["Nadia", "Paul"]), "Nadia et Paul");
  // Intl puts a no-break space (narrow or not, by unit and version) between a number and its unit.
  const spaced = (text: string) => text.replace(/\s/g, " ");
  assert.equal(spaced(formatBytes(78)), "78 octets");
  assert.equal(spaced(formatBytes(3_400_000)), "3,4 Mo");
});

test("product_names_are_the_same_in_every_language", () => {
  assert.deepEqual(PRODUCTS, ["drive", "calendar", "chat"]);
  assert.equal(PRODUCT_NAMES.calendar, "Ruchoir Calendar");
});

test("every_shared_dictionary_has_the_french_keys_and_nothing_else", () => {
  const keys = (dict: object) =>
    Object.entries(dict).flatMap(([section, entries]) => Object.keys(entries).map((key) => `${section}.${key}`));
  const source = keys(SHARED_DICTIONARIES.fr).sort();
  for (const locale of LOCALES) {
    assert.deepEqual(keys(SHARED_DICTIONARIES[locale]).sort(), source, locale);
    assert.deepEqual(Object.keys(SHARED_DICTIONARIES[locale]).sort(), [...RESERVED_SECTIONS].sort(), locale);
  }
});

test("with_shared_adds_the_shared_sections", () => {
  const merged = withShared("en", { files: { title: "Files" } });
  assert.equal(merged.files.title, "Files");
  assert.equal(merged.common.cancel, "Cancel");
  assert.equal(merged.error.serverUnreachable, SHARED_DICTIONARIES.en.error.serverUnreachable);
});

test("with_shared_refuses_a_product_that_redefines_a_shared_section", () => {
  const dictionary = JSON.parse('{"common":{"cancel":"Annuler"}}');
  assert.throws(() => withShared("fr", dictionary), /belongs to @ruchoir\/i18n/);
});
