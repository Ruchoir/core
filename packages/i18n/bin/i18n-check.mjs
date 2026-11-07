#!/usr/bin/env node
/**
 * Three questions, answered on every run and in CI:
 *
 * 1. **Is any user-visible text still hard-coded?** A string typed into a component is invisible to
 *    translation: it ships in French to a Polish reader and nothing reports it.
 * 2. **Does every key a call site asks for exist?** `t("prefs.themeLight")` with no such key draws
 *    the key itself on the screen, which is worse than the French it replaced.
 * 3. **Do the dictionaries agree?** TypeScript already refuses a locale missing a key, but it
 *    cannot see a key nobody uses, or a French string left untranslated in another locale.
 *
 * It reads the source rather than the build: the point is to fail the change that introduces the
 * problem, next to the line that introduces it.
 *
 * The first question is answered from the TypeScript syntax tree rather than from the text of each
 * line. Line matching missed whole shapes of the same mistake: a literal inside a JSX expression
 * (`{busy ? "Envoi…" : "Enregistrer"}`), a label held in an array of tabs, a French word with no
 * accent in it. Parsing asks the question the right way round: rather than guessing which literals
 * look like prose, it finds the positions whose value reaches a person's eyes, and every literal
 * that lands in one is a finding whatever language it is written in.
 *
 * Every interface of every product runs it on its own sources and dictionaries, described by an
 * `i18n.config.json` at its root (see the README of `@ruchoir/i18n`):
 *
 *     ruchoir-i18n-check                      reads ./i18n.config.json
 *     ruchoir-i18n-check --config web/i18n.config.json
 *
 * The sections this package provides (`common`, `error`) are merged into the product's
 * dictionaries before any check, and a product that redefines one of them is refused: a shared
 * sentence has one key, in one place.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/** This package's own dictionaries: the sections every product shares. */
const SHARED_DICT_DIR = resolve(fileURLToPath(new URL("../dictionaries", import.meta.url)));
/** The top-level sections of a dictionary that belong to this package. */
const RESERVED_SECTIONS = ["common", "error"];

/**
 * What one interface asks to be checked, from its `i18n.config.json`. Paths are relative to the
 * file.
 *
 * - `scan`: the source folders to read.
 * - `dictionaries`: the folder of its six dictionaries, `fr.json` first among them.
 * - `debt` (optional): a JSON file `{ "files": [...] }` of files tolerated untranslated for now.
 * - `keyLiterals` (optional): folders of shared logic that hand keys to the screens as plain
 *   strings (`"access.level.edit"`). A string there shaped like a key the dictionaries answer counts
 *   as asked for. They are scanned too.
 * - `allowed` (optional): strings that are not prose (a brand, a font), beside the common ones.
 * - `allowedDuplicates` (optional): `{ "key": "why it may hold the same French as another key" }`.
 * - `shared` (optional): true only for this package, whose dictionaries hold nothing but the
 *   reserved sections.
 */
function readConfig() {
  const flag = process.argv.indexOf("--config");
  const path = resolve(flag >= 0 ? process.argv[flag + 1] ?? "" : "i18n.config.json");
  let config;
  try {
    config = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`cannot read the i18n configuration ${path}: ${error.message}`);
  }
  const isList = (value) => Array.isArray(value) && value.every((item) => typeof item === "string");
  if (!isList(config.scan) || config.scan.length === 0) throw new Error(`${path}: "scan" must list source folders`);
  if (typeof config.dictionaries !== "string") throw new Error(`${path}: "dictionaries" must name a folder`);
  if (config.debt != null && typeof config.debt !== "string") throw new Error(`${path}: "debt" must name a file`);
  for (const field of ["keyLiterals", "allowed"]) {
    if (config[field] != null && !isList(config[field])) throw new Error(`${path}: "${field}" must be a list of strings`);
  }
  const reasons = config.allowedDuplicates ?? {};
  if (typeof reasons !== "object" || Array.isArray(reasons)) {
    throw new Error(`${path}: "allowedDuplicates" must map each key to the reason it may repeat a text`);
  }
  for (const [key, why] of Object.entries(reasons)) {
    if (typeof why !== "string" || why.trim() === "") throw new Error(`${path}: allowedDuplicates.${key} needs its reason`);
  }
  return { ...config, root: dirname(path) };
}

const CONFIG = readConfig();
const ROOT = CONFIG.root;
const KEY_LITERAL_DIRS = (CONFIG.keyLiterals ?? []).map((dir) => resolve(ROOT, dir));
const SCAN_DIRS = [...new Set([...CONFIG.scan, ...(CONFIG.keyLiterals ?? [])])];
const DICT_DIR = resolve(ROOT, CONFIG.dictionaries);
const SHARED = CONFIG.shared === true;

/** Attributes and object fields whose value reaches a person's eyes or a screen reader. */
const TEXT_FIELDS = new Set([
  "label",
  "aria-label",
  "aria-description",
  "placeholder",
  "title",
  "subtitle",
  "description",
  "hint",
  "alt",
  "confirmLabel",
  "cancelLabel",
  "emptyLabel",
  "closeLabel",
  "heading",
  "text",
  "message",
  "summary",
  "caption",
  "tooltip",
  "name",
  // React Native's names for what a screen reader says.
  "accessibilityLabel",
  "accessibilityHint",
]);

/** Fields named like the above whose value is never drawn: they name a thing, they do not say it. */
const TECHNICAL_FIELDS = new Set(["name"]);

/**
 * Strings that are not prose, listed once rather than guessed at by pattern.
 *
 * Every entry is a decision: a CSS value, a machine identifier, a brand name. The list is short on
 * purpose. If it starts growing, the rule is wrong, not the code.
 */
const ALLOWED = new Set([
  "Ruchoir",
  // The products' names are fixed in every language (`PRODUCT_NAMES`).
  "Ruchoir Drive",
  "Ruchoir Calendar",
  "Ruchoir Chat",
  "Drive",
  "Calendar",
  "Chat",
  "IBM Plex Sans",
  "IBM Plex Mono",
  "OpenDyslexic",
  "Comic Sans MS",
  "Helvetica Neue",
  "Segoe UI",
  ...(CONFIG.allowed ?? []),
]);

/** A file is skipped entirely when it carries this marker, with the reason on the same line. */
const FILE_OPT_OUT = "i18n-audit-ignore-file";
/** A single line is skipped when the line before it carries this marker. */
const LINE_OPT_OUT = "i18n-audit-ignore-next-line";

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry === "node_modules" || entry === ".next") continue;
      walk(path, out);
    } else if (/\.tsx?$/.test(entry) && !entry.endsWith(".test.ts")) {
      // A test's fixtures are data a person never reads: file names, people's names.
      out.push(path);
    }
  }
  return out;
}

/** Whether a literal carries words at all, as opposed to punctuation, a separator or a unit. */
function carriesWords(value) {
  const text = value.trim();
  if (text.length < 2) return false;
  if (ALLOWED.has(text)) return false;
  if (!/[A-Za-zÀ-ÿ]{2}/.test(text)) return false;
  if (/^(var\(|--|#|\/|https?:|data:|blob:|mailto:)/.test(text)) return false;
  if (/^[\d.]+(px|rem|em|%|vh|vw|s|ms|fr)$/.test(text)) return false;
  return true;
}

/** Whether a literal reads as an identifier rather than as something said to a reader. */
function looksTechnical(value) {
  const text = value.trim();
  // A dictionary key, not a sentence: `mfa.totpTitle`.
  if (/^[a-z][\w]*(\.[A-Za-z]\w*)+$/.test(text)) return true;
  // camelCase, kebab-case and snake_case identifiers, icon names, CSS keywords, variants.
  if (/^[a-z][a-z\d]*([A-Z][a-z\d]*)+$/.test(text)) return true;
  if (/^[a-z\d]+([-_][a-z\d]+)*$/.test(text)) return true;
  // A CSS declaration list or shorthand value: `0 8px`, `1px solid var(--x)`, `flex-start`.
  if (/^[\d.]+\s/.test(text)) return true;
  // A font stack: quoted family names and a generic one at the end. "sans-serif" carries the French
  // word "sans", which is the sort of coincidence a word list cannot be asked to know about.
  if (/(^|,\s*)(sans-serif|serif|monospace|system-ui|cursive|fantasy)\s*$/.test(text)) return true;
  return false;
}

/** Whether a literal is French prose wherever it sits: accents, or words French alone strings together. */
const FRENCH_WORDS =
  /(?:^|[\s'’(])(?:le|la|les|un|une|des|du|de|au|aux|ce|cet|cette|ces|vous|votre|vos|votre|nos|notre|est|sont|pas|plus|dans|pour|par|avec|sans|sur|qui|que|quand|mais|donc|ou|et|ne|se|son|sa|ses|leur|tout|tous|toute|toutes|ici|encore|depuis|puis)(?:[\s'’,.:;!?)]|$)/i;

function looksFrench(value) {
  const text = value.trim();
  if (looksTechnical(text)) return false;
  if (/[À-ÿ]/.test(text)) return true;
  return FRENCH_WORDS.test(text) && /\s/.test(text);
}

/** A single capitalised word: "Membre", "Modifier", "Offline". */
const CAPITALISED_WORD = /^[A-ZÀ-Ý][a-zà-ÿ]{2,}$/;

/**
 * Whether a literal is being compared rather than shown.
 *
 * `e.key === "Escape"` and `"Notification" in window` are the shape of a word this file reads, not
 * one it writes. A default on the other hand (`dto.title ?? "Membre"`) is written, and is exactly
 * how a role shipped in one language, so `??` and `||` stay inside the rule.
 */
function isCompared(node) {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isCaseClause(parent)) return true;
  if (ts.isBinaryExpression(parent)) {
    const op = parent.operatorToken.kind;
    return op !== ts.SyntaxKind.QuestionQuestionToken && op !== ts.SyntaxKind.BarBarToken;
  }
  if (ts.isArrayLiteralExpression(parent) && parent.parent && ts.isCallExpression(parent.parent)) return true;
  if (ts.isCallExpression(parent)) return true;
  return false;
}

const TEXT_LITERAL = new Set([ts.SyntaxKind.StringLiteral, ts.SyntaxKind.NoSubstitutionTemplateLiteral]);

/**
 * Whether a literal sits somewhere the interface draws it.
 *
 * Walks up from the literal: a JSX child expression (anything between two tags, including the
 * branches of a ternary), a translatable attribute, or a field named like one. The walk stops at
 * the first enclosing JSX attribute, so `style={{ content: "x" }}` inside a child does not count.
 */
function visiblePosition(node) {
  let current = node;
  let parent = node.parent;
  while (parent) {
    if (ts.isJsxAttribute(parent)) {
      const name = parent.name.getText();
      return TEXT_FIELDS.has(name) && !TECHNICAL_FIELDS.has(name) ? `attribute ${name}` : null;
    }
    if (ts.isPropertyAssignment(parent) && parent.initializer === current) {
      const name = parent.name.getText().replace(/^["']|["']$/g, "");
      if (TEXT_FIELDS.has(name) && !TECHNICAL_FIELDS.has(name)) return `field ${name}`;
      return null;
    }
    if (ts.isJsxExpression(parent) && parent.parent && !ts.isJsxAttribute(parent.parent)) {
      return "JSX child";
    }
    if (ts.isCallExpression(parent) || ts.isFunctionLike(parent)) {
      // An argument to a function is only visible through what that function does with it, which
      // this check cannot see. `t("…")` and friends are handled by the key check instead.
      return null;
    }
    current = parent;
    parent = parent.parent;
  }
  return null;
}

/**
 * Formatting calls with a language written into them.
 *
 * `toLocaleDateString("fr-FR")` is not a hard-coded sentence, so no amount of looking at string
 * literals finds it, and it is the same bug: a Polish reader is shown "7 sept." because a call site
 * decided the language once, in French, for everyone. The same goes for an `Intl` formatter built
 * on a fixed tag. Both take the language in force instead.
 */
const LOCALE_METHODS = /\.(toLocaleDateString|toLocaleTimeString|toLocaleString|toLocaleUpperCase|toLocaleLowerCase)\s*\(/;
const LOCALE_TAG = /^[a-z]{2}(-[A-Za-z0-9]{2,8})*$/;

function findFrozenLocales(source, path) {
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const lines = source.split("\n");
  const found = [];
  const visit = (node) => {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const callee = node.expression.getText(sf);
      const first = node.arguments?.[0];
      const isFormatter = LOCALE_METHODS.test(`${callee}(`) || /^Intl\.[A-Za-z]+$/.test(callee);
      if (isFormatter && first && TEXT_LITERAL.has(first.kind) && LOCALE_TAG.test(first.text)) {
        const line = sf.getLineAndCharacterOfPosition(first.getStart(sf)).line + 1;
        if (!(line > 1 && lines[line - 2].includes(LINE_OPT_OUT))) {
          found.push({ line, text: `${callee}("${first.text}")`, file: relative(ROOT, path) });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  return found;
}

/** Hard-coded strings in one file, as `{ line, text, why }`. */
function findHardCoded(source, path) {
  if (source.includes(FILE_OPT_OUT)) return [];
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const lines = source.split("\n");
  const found = [];

  /**
   * Whether the line carries the marker in the comment above it.
   *
   * The comment is read upwards rather than one line back: a reason worth writing rarely fits on one
   * line, and a marker that stops working when its explanation grows teaches people to write shorter
   * reasons.
   */
  const optedOut = (line) => {
    for (let i = line - 2; i >= 0; i -= 1) {
      const text = lines[i].trim();
      if (text.includes(LINE_OPT_OUT)) return true;
      if (!text.startsWith("//") && !text.startsWith("*") && !text.startsWith("/*")) return false;
    }
    return false;
  };

  const visit = (node) => {
    if (ts.isJsxText(node)) {
      const text = node.text.trim();
      if (carriesWords(text) && !looksTechnical(text)) {
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        if (!optedOut(line)) found.push({ line, text, why: "JSX text" });
      }
    } else if (ts.isTemplateExpression(node)) {
      // A sentence built around a value (`${name} a rejoint l'espace`) is still a sentence. Its
      // words live in the quoted parts, which a scanner looking only at string literals never saw.
      const parts = [node.head, ...node.templateSpans.map((span) => span.literal)];
      const text = parts.map((part) => part.text).join(" ").trim();
      const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
      if (carriesWords(text) && !optedOut(line)) {
        const where = visiblePosition(node);
        if (where && !looksTechnical(text)) found.push({ line, text, why: where });
        else if (looksFrench(text)) found.push({ line, text, why: "French prose" });
      }
    } else if (TEXT_LITERAL.has(node.kind)) {
      const text = node.text.trim();
      const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
      if (carriesWords(text) && !optedOut(line)) {
        const where = visiblePosition(node);
        if (where && !looksTechnical(text)) found.push({ line, text, why: where });
        else if (looksFrench(text)) found.push({ line, text, why: "French prose" });
        else if (CAPITALISED_WORD.test(text) && !looksTechnical(text) && !isCompared(node)) {
          found.push({ line, text, why: "one word, one language" });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);

  const seen = new Set();
  return found
    .filter((f) => {
      const key = `${f.line}:${f.text}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .map((f) => ({ ...f, file: relative(ROOT, path) }));
}

/**
 * Keys that deliberately hold the same French text as another key, from `allowedDuplicates`.
 *
 * The rule is that one sentence gets one key: duplicating it costs bytes in six files and, worse,
 * lets two copies of the same sentence drift apart until the interface says it two ways. The
 * exception exists because French collapses distinctions other languages keep (a label and a verb,
 * a role and a status), so a pair that is identical here may have to differ in German or Polish.
 * Each entry is that claim, made once, in writing, with its reason in the configuration.
 */
const ALLOWED_DUPLICATES = new Set(Object.keys(CONFIG.allowedDuplicates ?? {}));

/** Every key path in a dictionary object, flattened to `a.b.c`. */
function keyPaths(value, prefix = "", out = []) {
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (child && typeof child === "object" && !Array.isArray(child)) keyPaths(child, path, out);
    else out.push(path);
  }
  return out;
}

function readDictionaries(dir) {
  const dicts = {};
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    dicts[file.replace(/\.json$/, "")] = JSON.parse(readFileSync(join(dir, file), "utf8"));
  }
  return dicts;
}

/**
 * The interface's dictionaries with this package's sections merged in, and what is wrong with how
 * they share them: a product section named like a reserved one, a language this package does not
 * carry, or (for this package itself) a section that is not reserved.
 */
function loadDictionaries() {
  const own = readDictionaries(DICT_DIR);
  const issues = [];
  if (SHARED) {
    for (const [locale, dict] of Object.entries(own)) {
      for (const section of Object.keys(dict)) {
        if (!RESERVED_SECTIONS.includes(section)) issues.push(`${locale}: section ${section} is not shared`);
      }
    }
    return { dicts: own, issues };
  }
  const shared = readDictionaries(SHARED_DICT_DIR);
  const dicts = {};
  for (const [locale, dict] of Object.entries(own)) {
    for (const section of RESERVED_SECTIONS) {
      if (section in dict) issues.push(`${locale}: section ${section} belongs to @ruchoir/i18n; use its keys`);
    }
    if (!shared[locale]) issues.push(`${locale}: @ruchoir/i18n carries no dictionary for this language`);
    dicts[locale] = { ...dict, ...(shared[locale] ?? {}) };
  }
  return { dicts, issues };
}

/** The value at a flattened key path. */
function valueAt(dict, path) {
  return path.split(".").reduce((node, key) => (node == null ? undefined : node[key]), dict);
}

/** The shape of a dictionary key: `section.name`, or `section.group.name`. */
const KEY_SHAPE = /^[a-z][\w]*(\.[A-Za-z]\w*)+$/;

/** The keys (and plural bases) of the source dictionary, which shared logic names its keys from. */
let sourceKeySet;
function knownKeys() {
  if (!sourceKeySet) sourceKeySet = new Set(sourceKeys.flatMap((key) => [key, pluralBase(key) ?? key]));
  return sourceKeySet;
}

/**
 * Keys the source asks for, and where.
 *
 * Only the literal inside a `t(...)` or `key(...)` call: a key held in a table is `key("…")`, whose
 * argument the compiler already checks against the dictionary, and guessing at every other string
 * shaped like a key reported event names ("message.created") and file names ("image.png") instead.
 */
function usedKeys(files) {
  const used = new Map();
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    const relPath = relative(ROOT, file);
    // `t("…")` and `key("…")`, but also `tRef.current("…")` and a `<Trans i18nKey="…">`: a key is a
    // key however it reaches the runtime, and a warning that cannot see three of the four shapes
    // spends its time reporting live keys as dead ones.
    const record = (name, index) => {
      if (used.has(name)) return;
      used.set(name, `${relPath}:${source.slice(0, index).split("\n").length}`);
    };
    for (const match of source.matchAll(/\b(?:t|key|tRef\.current)\(\s*["']([\w.]+)["']/g)) {
      record(match[1], match.index);
    }
    // Shared logic hands keys to the screens as plain strings (`"access.level.edit"`), so a string
    // shaped like a key that the dictionaries answer counts as asked for.
    if (KEY_LITERAL_DIRS.some((dir) => file.startsWith(dir))) {
      for (const literal of source.matchAll(/["'`]([A-Za-z][\w]*(?:\.[A-Za-z]\w*)+)["'`]/g)) {
        if (knownKeys().has(literal[1])) record(literal[1], literal.index);
      }
      // A key built from a template (`access.level.${kind}`): every key under its fixed head is asked for.
      for (const template of source.matchAll(/`([A-Za-z][\w]*(?:\.[A-Za-z]\w*)*\.)\$\{/g)) {
        for (const key of knownKeys()) if (key.startsWith(template[1])) record(pluralBase(key) ?? key, template.index);
      }
    }
    // `<Trans i18nKey={…}>` holds its key in an attribute, and sometimes chooses between two.
    for (const attr of source.matchAll(/i18nKey=\{?\s*([^}]+)/g)) {
      for (const literal of attr[1].matchAll(/["']([\w.]+)["']/g)) record(literal[1], attr.index);
    }
  }
  return used;
}

/**
 * Files not yet translated, and tolerated until they are.
 *
 * It buys nothing except time: a file on it is still untranslated, and the check fails the moment a
 * new hard-coded string appears anywhere else. Two rules keep it honest: nothing may be added to it
 * (a new screen is written translated), and a file that has become clean is reported so the line goes.
 */
// An interface written translated from its first screen has no debt file at all.
const debt = new Set(CONFIG.debt ? JSON.parse(readFileSync(resolve(ROOT, CONFIG.debt), "utf8")).files : []);

const files = SCAN_DIRS.flatMap((dir) => walk(resolve(ROOT, dir)));
const allFindings = files.flatMap((file) => findHardCoded(readFileSync(file, "utf8"), file));
const frozenLocales = files.flatMap((file) => findFrozenLocales(readFileSync(file, "utf8"), file));
const hardCoded = allFindings.filter((f) => !debt.has(f.file));
const stillOwed = new Set(allFindings.filter((f) => debt.has(f.file)).map((f) => f.file));
const settled = [...debt].filter((file) => !stillOwed.has(file));

const { dicts, issues } = loadDictionaries();
const source = dicts.fr ?? {};
const sourceKeys = keyPaths(source);
const problems = [...issues];
if (!dicts.fr) problems.push("no fr.json: French is the source every other language translates");

/**
 * Plural suffixes are i18next's, and how many a key needs depends on the language, not on French.
 *
 * `x_one`/`x_other` in French becomes `x_one`/`x_few`/`x_many`/`x_other` in Polish, which is not a
 * disagreement but the point of having plurals at all. So keys are compared on their base, and each
 * language is then held to the categories its own rules actually use (`Intl.PluralRules`), which
 * catches the real mistake: a Polish translation that stopped at two forms.
 */
const PLURAL_SUFFIXES = ["zero", "one", "two", "few", "many", "other"];

function pluralBase(key) {
  const match = key.match(/^(.*)_(\w+)$/);
  return match && PLURAL_SUFFIXES.includes(match[2]) ? match[1] : null;
}

const sourceBases = new Map();
for (const key of sourceKeys) {
  const base = pluralBase(key);
  if (base) sourceBases.set(base, true);
}
const sourcePlain = new Set(sourceKeys.filter((key) => !pluralBase(key)));

for (const [locale, dict] of Object.entries(dicts)) {
  if (locale === "fr") continue;
  const keys = new Set(keyPaths(dict));
  const categories = new Intl.PluralRules(locale).resolvedOptions().pluralCategories;

  for (const key of sourcePlain) {
    if (!keys.has(key)) problems.push(`${locale}: missing key ${key}`);
  }
  for (const base of sourceBases.keys()) {
    for (const category of categories) {
      if (!keys.has(`${base}_${category}`)) {
        problems.push(`${locale}: missing plural form ${base}_${category}`);
      }
    }
  }
  for (const key of keys) {
    const base = pluralBase(key);
    if (base ? !sourceBases.has(base) : !sourcePlain.has(key)) {
      problems.push(`${locale}: key ${key} exists in no source dictionary`);
    }
  }
}

// One sentence, one key. Checked on the source dictionary, since the others follow its shape.
const byText = new Map();
for (const key of sourceKeys) {
  const text = valueAt(source, key);
  if (typeof text !== "string" || ALLOWED_DUPLICATES.has(key)) continue;
  const normalized = text.trim();
  if (!byText.has(normalized)) byText.set(normalized, []);
  byText.get(normalized).push(key);
}
// Two plural categories of one key saying the same thing is not a duplicate: a language with no
// distinction there still has to fill both, and the key is one key.
const duplicates = [...byText.entries()]
  .map(([text, keys]) => [text, [...new Set(keys.map((k) => pluralBase(k) ?? k))]])
  .filter(([, keys]) => keys.length > 1);

const used = usedKeys(files);
// A key the source asks for and no dictionary answers draws the key itself on the screen.
const missing = [...used.entries()].filter(([key]) => {
  if (sourcePlain.has(key) || sourceBases.has(key)) return false;
  return true;
});
// A product uses the shared sections it needs, not all of them: those are never reported unused.
const isShared = (key) => !SHARED && RESERVED_SECTIONS.includes(key.split(".")[0]);
const unused = SHARED
  ? []
  : sourceKeys.filter((key) => !isShared(key) && !used.has(key) && !used.has(pluralBase(key) ?? key));

let failed = false;

if (hardCoded.length > 0) {
  failed = true;
  console.error(`\n${hardCoded.length} hard-coded string(s): they ship in French to every reader.\n`);
  for (const finding of hardCoded) {
    console.error(`  ${finding.file}:${finding.line}  ${JSON.stringify(finding.text)}  [${finding.why}]`);
  }
  console.error(
    `\nMove each into ${CONFIG.dictionaries} and call t("..."). For something that is not prose,\n` +
      `add it to "allowed" in i18n.config.json, or mark the line with ${LINE_OPT_OUT} and say why.\n`,
  );
}

if (frozenLocales.length > 0) {
  failed = true;
  console.error(
    `\n${frozenLocales.length} formatting call(s) with a language written into them: every reader\n` +
      `gets that one, whatever they chose.\n`,
  );
  for (const finding of frozenLocales) {
    console.error(`  ${finding.file}:${finding.line}  ${finding.text}`);
  }
  console.error(`\nFormat with the language in force (the format functions of @ruchoir/i18n).\n`);
}

if (missing.length > 0) {
  failed = true;
  console.error(
    `\n${missing.length} key(s) asked for and answered by no dictionary: the key itself is drawn.\n`,
  );
  for (const [key, where] of missing) console.error(`  ${key}  (${where})`);
  console.error("");
}

if (settled.length > 0) {
  failed = true;
  console.error(
    `\n${settled.length} file(s) listed as untranslated carry no hard-coded text any more.\n` +
      `Remove them from ${CONFIG.debt}: the list only ever shrinks.\n`,
  );
  for (const file of settled) console.error(`  ${file}`);
  console.error("");
}

if (duplicates.length > 0) {
  failed = true;
  console.error(
    `\n${duplicates.length} text(s) held under more than one key. One sentence, one key: two copies\n` +
      `cost six files' worth of bytes and drift apart until the interface says it two ways.\n`,
  );
  for (const [text, keys] of duplicates) {
    console.error(`  ${JSON.stringify(text)}\n    ${keys.join("\n    ")}`);
  }
  console.error(
    `\nPoint every call site at one key (a shared one when it exists). If two of them genuinely\n` +
      `have to differ in another language, add the key to "allowedDuplicates" in i18n.config.json\n` +
      `with the reason.\n`,
  );
}

if (problems.length > 0) {
  failed = true;
  console.error(`\n${problems.length} dictionary problem(s):\n`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("");
}

// Unused keys are reported without failing: a key may legitimately be built dynamically, and a
// check that cannot tell the difference must not be the one that blocks a merge.
if (unused.length > 0) {
  console.warn(`\n${unused.length} key(s) not found in the source (dynamic use, or dead):\n`);
  for (const key of unused) console.warn(`  ${key}`);
  console.warn("");
}

if (failed) process.exit(1);
const owed = [...stillOwed].length;
console.log(
  `i18n: ${sourceKeys.length} keys across ${Object.keys(dicts).length} languages, ` +
    `no hard-coded text outside the ${owed} file(s) still listed as untranslated.`,
);
if (owed > 0) {
  console.log(`Remaining: ${[...stillOwed].sort().join(", ")}`);
}
