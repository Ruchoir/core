# Ruchoir core

The shared libraries of Ruchoir: the Rust crates and TypeScript packages that several products use,
all released together under one version. A product reaches code it shares with another product only
through a package of this repository.

> In construction: part of the restructuring of Ruchoir into separate products. Nothing runs here yet.

- How to work here: [`AGENTS.md`](AGENTS.md), which opens with the common rules of the organization.
- How to contribute: [Ruchoir/.github, `CONTRIBUTING.md`](https://github.com/Ruchoir/.github/blob/main/CONTRIBUTING.md).
- Decisions that span several repositories: [Ruchoir/.github, `docs/adr`](https://github.com/Ruchoir/.github/tree/main/docs/adr).

## Licence

`MPL-2.0` ([`LICENSE`](LICENSE)), the Mozilla Public License 2.0:

> This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the
> MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

A changed file of this repository, once shipped, is shared under the same licence. What is here can
be combined with code under any other licence. Versions up to `v0.1.0` were released under
`MIT OR Apache-2.0`. Fonts keep their own licence (OFL), see `packages/design-system/fonts`.
