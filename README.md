# Ruchoir core

The shared libraries of Ruchoir, a self-hosted, European collaboration suite: chat, files, calendar,
with one identity service. This repository holds the Rust crates and the TypeScript packages that
several products use, all released together under one version. A product reaches code it shares with
another product only through a package of this repository.

The services use the crates: [Propolis](https://github.com/Ruchoir/propolis), which signs people in
and holds organisations, the [hub](https://github.com/Ruchoir/hub), which carries notifications and
real time, and the products ([drive](https://github.com/Ruchoir/drive),
[calendar](https://github.com/Ruchoir/calendar), [chat](https://github.com/Ruchoir/chat)) answer HTTP
through `ruchoir-http`, and the hub and the products check Propolis's tokens with `ruchoir-auth`. The
[desktop](https://github.com/Ruchoir/desktop) app signs in with `ruchoir-native`, the
[mobile](https://github.com/Ruchoir/mobile) app with `@ruchoir/native-client`, and the interfaces are
drawn with `@ruchoir/design-system`. Core depends on none of them. How the pieces fit:
[architecture](https://github.com/Ruchoir/.github/blob/main/docs/architecture.md).

## What is here

| Crate or package | What |
|---|---|
| `ruchoir-auth` | What a product needs from Propolis: its keys, access and logout tokens checked, `private_key_jwt`, `client_credentials`, token exchange, and a browser session as a backend-for-frontend |
| `ruchoir-contract` | The check that a service's OpenAPI contract only grows inside a major version |
| `ruchoir-events` | Signed server-to-server events, the frame the hub pushes to clients, and a product's signed grant over a file another product keeps |
| `ruchoir-http` | The HTTP layer every service puts in front of its routes: Problem Details errors, security headers, cache policy, trace context, client address |
| `ruchoir-native` | How the desktop's core signs in with Propolis (RFC 8252): discovery of an instance, code and PKCE through a loopback redirect, one token per product; trusts the system store plus an optional extra authority (`RUCHOIR_EXTRA_CA`, a PEM file) for development instances |
| `ruchoir-permissions` | The permission catalogue, the system roles and the pure resolution engine ([ADR 0001](docs/adr/0001-permission-model.md)) |
| `@ruchoir/client-base` | The transport every API client is built on: where requests go, how they prove who is asking, errors and retries |
| `@ruchoir/design-system` | Tokens, typefaces and React components |
| `@ruchoir/i18n` | Languages, formatting, product names, the shared sentences, and `ruchoir-i18n-check`, which keeps the dictionaries honest |
| `@ruchoir/native-client` | The same as `ruchoir-native` in TypeScript, for the apps |
| `@ruchoir/permissions-logic` | What the permission screens of every client decide without drawing anything |

The crates are in `crates/`, the packages in `packages/`, each package with its own `AGENTS.md`.

## Status

Every crate and package above is released, all together, and the products pin the release they use.
Code comes here only when a second product needs it, so the repository grows as the products do.

## Prerequisites

- Rust: the version pinned in `rust-toolchain.toml` (rustup installs it on first use).
- Node 24 and pnpm 11 (`corepack enable` picks the version in `package.json`).

## Using it

One version covers every crate and package: a product's crates and packages all name the same
release, and it never mixes two.

- **Crates**, read with Cargo from the release tag:
  `ruchoir-http = { git = "https://github.com/Ruchoir/core", tag = "vX.Y.Z" }`.
- **npm packages**, published to GitHub Packages: the product's `.npmrc` holds
  `@ruchoir:registry=https://npm.pkg.github.com`, and its `package.json` pins the same version. GitHub
  Packages asks for a token even to read a public package: put one with the `read:packages` scope in
  your user `~/.npmrc` (`//npm.pkg.github.com/:_authToken=<token>`), never in a repository.

A release is a pull request that bumps every version at once (`[workspace.package] version` in
`Cargo.toml`, repeated in each `packages/*/package.json`), then the tag `vX.Y.Z` on the merged
commit. The tag runs `.github/workflows/release.yml`: the checks, the npm packages published, and a
release with notes drawn from the commits.

## Testing it

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
pnpm install
pnpm version:check
pnpm -r typecheck
pnpm -r test
```

The tests need no database or service. `pnpm version:check` refuses a crate or package whose version
differs from the others.

## Contract

SemVer across the whole repository: a breaking change to any crate or package is a new major
version for all. The permission catalogue is recorded in
`crates/ruchoir-permissions/contract/permissions-v1.json`: a permission name is never renamed or
removed and its position never moves, and an addition is recorded with
`RUCHOIR_UPDATE_CONTRACT=1 cargo test -p ruchoir-permissions the_permission_catalogue_only_grows`.

## Settings

Core reads no environment variable of its own: each product configures what it uses.

## Documentation

- [`docs/adr/`](docs/adr/README.md): this repository's decisions, starting with
  [0001. One permission engine](docs/adr/0001-permission-model.md).
- [`AGENTS.md`](AGENTS.md): how to work here, written for contributors and their tools: the common
  rules of the organization, what lives here, releases and checks. Each package has its own
  `AGENTS.md` too.
- The decisions that span several repositories, among them [0013. One version for
  core](https://github.com/Ruchoir/.github/blob/main/docs/adr/0013-one-version-for-core.md) and
  [0014. Core under the MPL](https://github.com/Ruchoir/.github/blob/main/docs/adr/0014-core-under-the-mpl.md):
  [Ruchoir/.github, `docs/adr`](https://github.com/Ruchoir/.github/tree/main/docs/adr).

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](https://github.com/Ruchoir/.github/blob/main/CONTRIBUTING.md):
your first pull request asks you to sign the [contributor licence agreement](https://github.com/Ruchoir/.github/blob/main/CLA.md).
Report a vulnerability privately, never in an issue: [`SECURITY.md`](https://github.com/Ruchoir/.github/blob/main/SECURITY.md).

## Licence

`MPL-2.0` ([`LICENSE`](LICENSE)), the Mozilla Public License 2.0:

> This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the
> MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

A changed file of this repository, once shipped, is shared under the same licence. What is here can
be combined with code under any other licence. Versions up to `v0.1.0` were released under
`MIT OR Apache-2.0`. Fonts keep their own licence (OFL), see `packages/design-system/fonts`.
