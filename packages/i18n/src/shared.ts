/**
 * The sentences every product shares, and how a product's dictionary takes them in.
 *
 * Two sections of every dictionary belong to this package: `common` (the buttons and states every
 * screen has: "Annuler", "Enregistrer", "Chargement…") and `error` (what goes wrong the same way
 * everywhere: a session that expired, a server out of reach). A product merges them into each of its
 * six dictionaries with `withShared`, and calls them by their usual keys, `t("common.cancel")`.
 *
 * A product never defines these sections itself: `withShared` refuses it, and so does
 * `ruchoir-i18n-check`. One sentence has one key, in one place, translated once.
 */

import de from "../dictionaries/de.json" with { type: "json" };
import en from "../dictionaries/en.json" with { type: "json" };
import es from "../dictionaries/es.json" with { type: "json" };
import fr from "../dictionaries/fr.json" with { type: "json" };
import it from "../dictionaries/it.json" with { type: "json" };
import pl from "../dictionaries/pl.json" with { type: "json" };

import type { Locale } from "./config.ts";

/** The shared sections, shaped by the French source. */
export type SharedDictionary = typeof fr;

/** The top-level sections that belong to this package. */
export const RESERVED_SECTIONS: readonly (keyof SharedDictionary)[] = ["common", "error"];

/** The shared sections in each language. */
export const SHARED_DICTIONARIES: Readonly<Record<Locale, SharedDictionary>> = { fr, en, es, de, it, pl };

/** A product dictionary: anything but the reserved sections. */
export type ProductDictionary = { [section: string]: unknown } & {
  [section in keyof SharedDictionary]?: never;
};

/**
 * The product's dictionary for `locale`, with the shared sections added.
 *
 * Throws when the product's dictionary defines a reserved section: that is a mistake to fix in the
 * dictionary, not something to resolve at run time by picking one of the two.
 */
export function withShared<D extends ProductDictionary>(locale: Locale, dictionary: D): D & SharedDictionary {
  for (const section of RESERVED_SECTIONS) {
    if (Object.hasOwn(dictionary, section)) {
      throw new Error(`the ${locale} dictionary defines "${section}", which belongs to @ruchoir/i18n`);
    }
  }
  return { ...dictionary, ...SHARED_DICTIONARIES[locale] };
}
