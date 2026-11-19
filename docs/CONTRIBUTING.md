# Contributing

effect-auth is a pnpm workspace of nine `@thomasfosterau/effect-auth*` packages under `packages/*`; the core is `packages/effect-auth`. Each package's `AGENTS.md` holds its boundary and invariants.

## Workflow

- Branch off `trunk` and open a pull request into `trunk`. Never commit to `trunk` directly.
- Open a draft PR as soon as you start, so others can see the work.
- Keep a change in one PR, however large; don't split it into slices.
- Rebase onto `origin/trunk` rather than merging it in.
- Found something out of scope? File an issue and move on. Keep issue bodies evergreen: update the body with context, rationale and the proposed fix rather than appending comments.
- Dependabot updates dependencies. Update one by hand only when your change needs it, or for the steps Dependabot can't do (below).

## Toolchain

[Vite+](https://viteplus.dev) (`vp`) manages Node, pnpm and the tools; use it rather than `node`, `npx` or bare `pnpm`. `vp install` installs dependencies and the git hooks (pre-commit formats and lints staged files), and its `prepare` step patches the native `tsc` and oxlint with `@effect/tsgo`.

| Command                | What it does                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `vp run build`         | Every package's `dist/`.                                                                                                                    |
| `vp check`             | Format and lint (type-aware; run after `build`, since lint reads siblings' `dist/`). `--fix` applies fixes.                                 |
| `vp run check`         | The type gate: every package's `tsc` / `svelte-check`, `vp test --typecheck` and `scripts/`.                                                |
| `vp run -r test:unit`  | Every package's unit tests.                                                                                                                 |
| `vp run docs`          | Docgen for the core: type-checks and runs every JSDoc `@example`.                                                                           |
| `vp run check:dist`    | Packs the packages, installs them from the registry and imports every entry (network). `-- --effect catalog` uses the workspace's `effect`. |
| `vp run test:coverage` | One Istanbul map at `coverage/coverage-final.json`, which `fallow audit` reads.                                                             |
| `vp run ci`            | Everything CI runs, in order, stopping at the first failure.                                                                                |

The alchemy runtime suites (`test:alchemy`) run last in `vp run ci`; alchemy-postgres's server cases need `DATABASE_URL`.

[Fallow](https://github.com/fallow-rs/fallow) checks dead code, duplication, complexity and the package boundaries (`.fallowrc.json`). Use it to guide your work (`vp run test:coverage`, then `vp exec fallow audit --base origin/trunk`); its findings are advice, not law.

## Before pushing

Run `vp run ci` (CI runs exactly that, on Node LTS and latest), then the fallow audit above. If a gate can't run where you are, say which and why in the PR body.

## Coding guidelines

- Effect v4 idioms throughout. Strongly prefer Effect's own modules (`Array`, `Option`, `Schema`, `Match`, `Clock`, `effect/crypto`, `effect/encoding`, …) over hand-rolled equivalents, and convert existing code where practical. Exceptions: Svelte code, non-Effect APIs adapted at the edge (the browser client, `./ladder`), and measured hot paths. Non-idiomatic code you can't fix trivially: file an issue listing the sites and the idiomatic replacement.
- Read the installed `effect` (`node_modules/effect/dist/*.d.ts`, its `AGENTS.md` and `ai-docs/`) rather than guessing at an API: v4 renamed much of v3.
- Services are `Context.Service` classes with a static `layer`; resolve dependencies at layer construction so methods carry `R = never`.
- Domain errors are `Data.TaggedError`; HTTP-boundary errors are `Schema.TaggedError` classes ([DESIGN.md](DESIGN.md)).
- Helper modules are namespace imports under their canonical aliases (`Arr`, `P`, `R`, `Str`, `Eq`, `Bool`); everything else comes from the `effect` barrel.
- Optional properties are `?: T | undefined` (`exactOptionalPropertyTypes` is on). Relative imports carry `.ts`.
- Compare secrets with `constantTimeHashEqual` / `timingSafeEqualBytes`, draw randomness from `SecureRandom`, store tokens as digests, and never log a credential. Keep `node:crypto` inside `Password.ts`, `TokenHash.ts` and `Cipher.ts`.
- Fix lint findings in code. A rule is turned off only in `vite.config.ts`, with the reason.

### Comments

- A file comment only when it adds non-obvious context, in under 50 words.
- JSDoc where it helps a consumer in their editor; don't restate the signature. Keep what docgen needs (`@since`, runnable `@example`s).
- Inline comments only for what the code can't say: workarounds, performance, non-obvious decisions.
- Never cite issues, PRs or CI runs; stable links to external documentation are fine.

### Tests

Tests sit beside the source (`Foo.test.ts`) and import from `vite-plus/test`, never `vitest`. Test logic that can break: error cases and the security properties (timing, entropy, expiry, replay). Don't test what the type system already checks. Storage adapters test against real engines in-process (PGlite, better-sqlite3).

## Dependencies

Every external version lives in the `pnpm-workspace.yaml` catalog (`catalogMode: strict`); after editing it, run `vp install` and commit `pnpm-lock.yaml`. Dependabot groups the sets that must move together. By hand, on the matching PR:

- The npm aliases `vite` (equal to `vite-plus`), `typescript` and `@typescript/native`, and the devcontainer image tag (equal to `vite-plus`).
- An `@effect/tsgo` whose `components` table covers the new oxlint and `@typescript/native`.
- `catalogs.peers`, `catalogs.alchemy-peers` and the advisory floors under `overrides`.

The published `effect` peer is `^4.0.0` unless a dependency or an Effect module first shipped in a later minor needs more; name the reason in the catalog comment. Raising it is a breaking change.

## Changesets

Every change to a published package's behaviour, or to a doc comment that reaches its `.d.ts`, needs a changeset (`vp exec changeset`) naming each package it touches. Docs-, CI- and tooling-only changes need none. Never version or publish by hand: the Release workflow opens the `chore: version packages` PR and the owner merges it ([PUBLISHING.md](PUBLISHING.md)).
