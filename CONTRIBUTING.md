# Contributing to effect-auth

effect-auth is a pnpm workspace of thirteen `@thomasfosterau/effect-auth*` packages under `packages/*`; the core library is `packages/effect-auth`. [AGENTS.md](AGENTS.md) holds the conventions, the commands and the gate list, and each package's `CLAUDE.md` its boundary, invariants and vocabulary. This file covers what a human needs on top of them and doesn't restate them.

## Setup

You need Node.js `^20.19.0 || ^22.18.0 || >=24.11.0` (`engines` in the root `package.json`) and pnpm 11 (the `packageManager` field pins the exact version, currently `pnpm@11.11.0`; Corepack resolves it).

```bash
git clone https://github.com/thomasfosterau/effect-auth.git
cd effect-auth
vp install   # or: pnpm install
```

Either command installs against the lockfile and runs the root `prepare` script, which installs the Vite+ git hooks and patches the TypeScript 7 `tsc` (and oxlint) with `@effect/tsgo` so the Effect diagnostics run in every type check. The pre-commit hook runs `vp staged`: format and lint on the staged files. There is no pre-push hook.

You don't need to build anything first: each package's `build`, `check` and `test:unit` tasks build the workspace packages they depend on.

For Effect APIs, read what the pinned `effect` ships: `node_modules/effect/AGENTS.md`, `node_modules/effect/ai-docs/`, and the declarations in `node_modules/effect/dist/*.d.ts`.

## Making a change

1. Find or file the issue, and branch off `trunk` as `issue-<n>-<slug>` ([AGENTS.md → Branches and pull requests](AGENTS.md#branches-and-pull-requests)).
2. Follow the module conventions in [docs/DESIGN.md](docs/DESIGN.md): a service class with a static `layer`, store interfaces whose lookups return `null` on a miss, tagged errors.
   - Shared types go in `src/Types.ts`; errors raised by two or more modules go in `src/Errors.ts`, others stay in their module.
   - A new module goes in `src/<Feature>.ts`, or `src/<cluster>/<Feature>.ts` inside an existing cluster (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`), and is exported from that cluster's `index.ts` or from `src/index.ts`.
3. Put tests next to the source (`Password.test.ts` beside `Password.ts`). Tests use Vitest through `vite-plus/test`; lint rejects a direct `vitest` import.

   ```typescript
   import { describe, expect, it } from "vite-plus/test";
   ```

   Cover the error cases and the security properties (timing, entropy, expiry, replay), not only the happy path. Storage adapters test against real engines in-process: `packages/drizzle`'s PostgreSQL suites run on [PGlite](https://github.com/electric-sql/pglite) (so `jsonb`, `timestamptz` and unique-index violations behave as in production) and its SQLite suite on `better-sqlite3`; `Requests.test.ts` counts the SQL a program emits through drizzle's `logger` hook to prove the batching claims, and `MySqlSchema.test.ts` pins the MySQL SQL through the proxy driver.

4. Document the change in the affected package's `README.md` (the API reference npm shows; use absolute `https://github.com/thomasfosterau/effect-auth/blob/trunk/…` links there, since npm renders it without the repository) and its `CLAUDE.md` when an invariant changes; update [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) if the module map changes.
5. Add a changeset with `pnpm changeset` when the change affects a published package, naming every package it touches ([AGENTS.md](AGENTS.md#branches-and-pull-requests) says which changes need one). Never version or publish by hand: the Release workflow opens the `chore: version packages` PR ([PUBLISHING.md](PUBLISHING.md)).

### Security-sensitive code

- Compare secrets in constant time with `constantTimeHashEqual` / `timingSafeEqualBytes` (`src/TokenHash.ts`).
- Draw randomness from the `Crypto.Crypto` service (default `PlatformCrypto.layer`), never `Math.random`.
- Store bearer tokens as SHA-256 digests (`hashToken`), never raw.
- Never log passwords, tokens, API keys or secrets.

[docs/ARCHITECTURE.md → Security Considerations](docs/ARCHITECTURE.md#security-considerations) describes the model these rules protect.

## Running one check

The full gate list is in [AGENTS.md → Verification](AGENTS.md#verification). While iterating, run the piece you need:

| What                                   | Command                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| Format and lint everything             | `vp check` (`vp check --fix` to apply fixes)                       |
| Lint one file                          | `vp lint <file>`                                                   |
| Format files                           | `vp fmt <files> --write`                                           |
| One package's unit tests               | `vp run --filter <pkg> test:unit`                                  |
| One package's type check               | `vp run --filter <pkg> check`                                      |
| One test file (from the package's dir) | `vp test run <file>`                                               |
| The alchemy runtime suite              | `vp run --filter @thomasfosterau/effect-auth-alchemy test:alchemy` |
| Coverage map for fallow                | `vp run test:coverage` (writes `coverage/coverage-final.json`)     |
| Dead code, unused exports, boundaries  | `fallow dead-code`                                                 |
| The changed-files gate                 | `fallow audit --base origin/trunk` (after `vp run test:coverage`)  |
| API docs and their runnable examples   | `vp run build && vp run docs`                                      |

`<pkg>` is the package name, for example `@thomasfosterau/effect-auth-sql`. `vp check` (format and lint) and `vp run check` (the type gate) are different commands.

## Before you open a pull request

Run the gates in [AGENTS.md → Verification](AGENTS.md#verification), in that order, and record each result in the PR body; CI's `test` job runs the same list and its `alchemy` job runs the alchemy runtime suite. The PR template ([.github/pull_request_template.md](.github/pull_request_template.md)) asks for the rest.

## Reporting a vulnerability

Don't open a public issue; follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE.md).
