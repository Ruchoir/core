# AGENTS.md - packages/i18n

`@ruchoir/i18n`: how every Ruchoir interface speaks six languages. The languages and how one is
chosen, formatting in the language in force, the products' names, the sentences every product
shares, and `ruchoir-i18n-check`, the check every interface runs in CI. It comes from
`apps/web/lib/i18n` and `apps/web/tools/i18n-audit` of `Ruchoir/ruchoir`, with their history. See
the root `AGENTS.md` for the rules.

## Layout

```
src/config.ts       Locale, LOCALES, DEFAULT_LOCALE (fr), LOCALE_NAMES, languageName, isLocale,
                    matchBrowserLocale
src/current.ts      the language in force outside React: setCurrentLocale, currentLocale, asLocale
src/format.ts       dates, times, sizes, numbers and lists in the language in force
src/products.ts     PRODUCTS, PRODUCT_NAMES, PRODUCT_SHORT_NAMES: fixed in every language
src/shared.ts       SHARED_DICTIONARIES, RESERVED_SECTIONS, withShared(locale, dictionary)
dictionaries/       the shared sections, `common` and `error`, in the six languages
bin/i18n-check.mjs  ruchoir-i18n-check: hard-coded text, missing keys, dictionaries that disagree
test/               node --test; the check runs on products written to a temporary folder
```

Entry points (`package.json` `exports`): `.` (everything in `src/`) and `./dictionaries/*.json`.
The `ruchoir-i18n-check` command is the package's `bin`.

## How a product uses it

1. Each of its six dictionaries goes through `withShared(locale, dictionary)` before it reaches
   i18next. Screens call the shared sentences by their keys: `t("common.cancel")`,
   `t("error.serverUnreachable")`.
2. Its CI runs `ruchoir-i18n-check` next to an `i18n.config.json`:

   ```json
   {
     "scan": ["app", "components", "lib"],
     "dictionaries": "lib/i18n/dictionaries",
     "debt": "tools/untranslated.json",
     "keyLiterals": ["node_modules/@ruchoir/permissions-logic/src"],
     "allowed": ["Nextcloud"],
     "allowedDuplicates": { "files.undo": "Takes back an action; cancel closes a dialog. German says Rückgängig and Abbrechen." }
   }
   ```

   Only `scan` and `dictionaries` are required. Paths are relative to the file. `--config <path>`
   reads another file.

## Rules

- **The shared sections belong here.** A product never defines `common` or `error`: `withShared`
  throws and the check fails. A sentence enters them when a second product needs it, in the six
  languages at once, through a pull request here.
- **No text is invented here.** A shared sentence comes from a product's reviewed dictionary, with
  its six translations.
- **Product names are not translated.** They are names, like a brand. What a product does is said in
  that product's dictionary.
- **French is the source.** It is what a missing key falls back to, and what the other five
  translate. French typography: a non-breaking space inside « » and before `?`, `:`, `;` and `!`.
- **No product knowledge in the check.** What differs between interfaces (folders, debt, allowed
  strings and duplicates, with their reasons) is in each product's `i18n.config.json`.
- **No browser global and no React here.** The runtime is plain functions over `Intl`, so the web, the
  phone and the desktop use the same code.
