// The check run as a product runs it: an `i18n.config.json`, sources and six dictionaries, written
// to a temporary folder for each case.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

const PACKAGE = join(dirname(fileURLToPath(import.meta.url)), "..");
const BIN = join(PACKAGE, "bin", "i18n-check.mjs");
const LOCALES = ["fr", "en", "es", "de", "it", "pl"];
const folders: string[] = [];
after(() => {
  for (const folder of folders) rmSync(folder, { recursive: true, force: true });
});

type Product = {
  config?: Record<string, unknown> | ((root: string) => Record<string, unknown>);
  files: Record<string, string>;
  dictionary: (locale: string) => object;
};

function run(product: Product): { status: number | null; output: string } {
  const root = mkdtempSync(join(tmpdir(), "ruchoir-i18n-"));
  folders.push(root);
  const extra = typeof product.config === "function" ? product.config(root) : product.config;
  const config = { scan: ["src"], dictionaries: "dictionaries", ...extra };
  writeFileSync(join(root, "i18n.config.json"), JSON.stringify(config));
  for (const [path, text] of Object.entries(product.files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  mkdirSync(join(root, "dictionaries"));
  for (const locale of LOCALES) {
    writeFileSync(join(root, "dictionaries", `${locale}.json`), JSON.stringify(product.dictionary(locale)));
  }
  const result = spawnSync(process.execPath, [BIN], { cwd: root, encoding: "utf8" });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

const TITLES: Record<string, string> = {
  fr: "Vos fichiers",
  en: "Your files",
  es: "Tus archivos",
  de: "Deine Dateien",
  it: "I tuoi file",
  pl: "Twoje pliki",
};
const screen = `export function Files({ t }: { t: (key: string) => string }) {
  return <section><h1>{t("files.title")}</h1><button>{t("common.cancel")}</button></section>;
}
`;

test("a_translated_product_passes_with_the_shared_keys", () => {
  const result = run({ files: { "src/Files.tsx": screen }, dictionary: (l) => ({ files: { title: TITLES[l] } }) });
  assert.equal(result.status, 0, result.output);
});

test("absolute_folders_in_the_configuration_are_read_as_given", () => {
  const result = run({
    config: (root) => ({ scan: [join(root, "src")], dictionaries: join(root, "dictionaries") }),
    files: { "src/Files.tsx": `export const Empty = () => <p>Aucun fichier ici</p>;
` },
    dictionary: (l) => ({ files: { title: TITLES[l] } }),
  });
  assert.equal(result.status, 1);
  assert.match(result.output, /Aucun fichier ici/);
});

test("a_hard_coded_sentence_fails", () => {
  const result = run({
    files: { "src/Files.tsx": `export const Empty = () => <p>Aucun fichier ici</p>;\n` },
    dictionary: (l) => ({ files: { title: TITLES[l] } }),
  });
  assert.equal(result.status, 1);
  assert.match(result.output, /Aucun fichier ici/);
});

test("a_product_that_redefines_a_shared_section_fails", () => {
  const result = run({
    files: { "src/Files.tsx": screen },
    dictionary: (l) => ({ files: { title: TITLES[l] }, common: { cancel: "x" } }),
  });
  assert.equal(result.status, 1);
  assert.match(result.output, /section common belongs to @ruchoir\/i18n/);
});

test("a_key_no_dictionary_answers_fails", () => {
  const result = run({
    files: { "src/Files.tsx": `export const T = ({ t }: { t: (k: string) => string }) => <p>{t("files.gone")}</p>;\n` },
    dictionary: (l) => ({ files: { title: TITLES[l] } }),
  });
  assert.equal(result.status, 1);
  assert.match(result.output, /files\.gone/);
});

test("repeating_a_shared_sentence_fails_unless_the_reason_is_given", () => {
  const undo = (l: string) => ({ files: { title: TITLES[l], undo: l === "fr" ? "Annuler" : `undo ${l}` } });
  const repeated = run({ files: { "src/Files.tsx": screen }, dictionary: undo });
  assert.equal(repeated.status, 1);
  assert.match(repeated.output, /common\.cancel/);

  const reasoned = run({
    config: { allowedDuplicates: { "files.undo": "Takes back an action, where cancel closes a dialog." } },
    files: { "src/Files.tsx": screen },
    dictionary: undo,
  });
  assert.equal(reasoned.status, 0, reasoned.output);
});

test("a_configuration_without_its_reason_is_refused", () => {
  const result = run({
    config: { allowedDuplicates: { "files.undo": "" } },
    files: { "src/Files.tsx": screen },
    dictionary: (l) => ({ files: { title: TITLES[l] } }),
  });
  assert.notEqual(result.status, 0);
  assert.match(result.output, /needs its reason/);
});

test("the_shared_dictionaries_pass_their_own_check", () => {
  const result = spawnSync(process.execPath, [BIN], { cwd: PACKAGE, encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
});
