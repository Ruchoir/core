# AGENTS.md - packages/permissions-logic

`@ruchoir/permissions-logic`: what the permission screens of every Ruchoir client decide without
drawing anything. Roles and their rows, groups, who may do what in a space or a channel, the access
panel and its reasons ("Pourquoi"), guests and their end dates, the journal, "view as", licences, and
the words for the catalogue. Pure functions and constants: no request, no rendering. It comes from
`packages/client/src/permissionsLogic` of `Ruchoir/ruchoir`, with its history. See the root
`AGENTS.md` for the rules.

## Layout

```
src/index.ts   the one entry point; names two files both use are told apart here
               (`AuditEntryLike`, `WhySentence`, `GUEST_CEILING_SET`...)
src/*.ts       one file per screen concern (roles, groups, access, why, guests, audit, licences...)
test/          node --test
```

## Rules

- **No product type.** A function takes the fields it reads, declared here as a small structural
  type (`ListedLicence`, `SpaceRights`, `HeldChannel`, `LicenceState`, the `...Like` types). A
  product's wider record fits as it is; a function that hands records back is generic, so it returns
  the product's own type whole.
- **Translation keys, not text.** Functions return keys of the products' dictionaries. Each product
  checks, in its own tests, that its dictionaries hold every key this package can return.
- **The server's lists.** The guest ceiling and the catalogue order follow `crates/ruchoir-permissions`
  in this repository (`test/guestCeiling.test.ts` reads it). The limits and lists another service
  holds (role name length, role colours, group description length, room-wide mention handles) are
  pinned in the tests: changing one is a decision taken with that service.
- **Shipped as TypeScript source** (`exports` point at `src`), with `.ts` extensions on relative
  imports and erasable syntax only. No DOM, no Node API in `src`.

## Checks

```bash
pnpm --filter @ruchoir/permissions-logic typecheck   # tsc --noEmit
pnpm --filter @ruchoir/permissions-logic test        # node --test
```
