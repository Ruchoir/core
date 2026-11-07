/**
 * The products' names, as every interface shows them.
 *
 * They are names, not descriptions: the same in every language, like a brand. A screen that
 * describes what a product does ("your files") says so in its own dictionary.
 */

/** A product a person meets in an interface. */
export type Product = "drive" | "calendar" | "chat";

/** Every product, in the order a list of them follows. */
export const PRODUCTS: readonly Product[] = ["drive", "calendar", "chat"];

/** Each product's full name. */
export const PRODUCT_NAMES: Readonly<Record<Product, string>> = {
  drive: "Ruchoir Drive",
  calendar: "Ruchoir Calendar",
  chat: "Ruchoir Chat",
};

/** Each product's short name, where "Ruchoir" is already on the screen (a tab, a menu entry). */
export const PRODUCT_SHORT_NAMES: Readonly<Record<Product, string>> = {
  drive: "Drive",
  calendar: "Calendar",
  chat: "Chat",
};
