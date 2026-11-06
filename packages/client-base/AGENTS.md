# AGENTS.md - packages/client-base

`@ruchoir/client-base`: the transport every Ruchoir API client is built on. Where requests go, how
they prove who is asking, how a failure reads, when a read is retried, and what a read only preview
holds back. Each product's API client (its calls and their shapes) is built over it and lives with
the product. It comes from `packages/client` of `Ruchoir/ruchoir`, with its history. See the root
`AGENTS.md` for the rules.

## Layout

```
src/config.ts     ClientOptions, the default client's options (configureClient) and the ...Of(options)
                  helpers: apiBaseOf, apiOriginOf, absoluteUrlOf, authInitOf, withOptions
src/http.ts       makeTransport(getOptions): apiRequest and the verbs, ApiError, apiErrorCode;
                  the module-level helpers are the default client's
src/multipart.ts  multipartBody: a FormData flattened into one buffer (inMemoryUploads)
test/             node --test, fetch stubbed by test/fakeFetch.ts
```

Entry points (`package.json` `exports`): `./config`, `./http`, `./multipart`.

## Rules

- **No product knowledge.** No route, no product type, no product call. What depends on a product's
  routes is an option it passes when it creates its client: `isBackground` says which writes the app
  makes on its own (held back during a preview, refused in silence), and a request can say it itself
  (`background` in `RequestOptions`, which wins). Reads are never held back.
- **No browser global at module level, no React.** The code runs in a browser, in React Native and
  in a desktop webview. `window.location` is read only when no base URL is set (the web). The DOM
  library is in `tsconfig.json` for those types only.
- **Shipped as TypeScript source** (`exports` point at `src`). Relative imports carry their `.ts`
  extension, and only erasable syntax is allowed (`erasableSyntaxOnly`), so Node's type stripping and
  any bundler read it as is.

## Checks

```bash
pnpm --filter @ruchoir/client-base typecheck   # tsc --noEmit, sources and tests
pnpm --filter @ruchoir/client-base test        # node --test
```
