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

[Vite+](https://viteplus.dev) (`vp`) manages Node, pnpm and the tools; use it rather than `node`, `npx` or bare `pnpm`. `vp install` installs dependencies and the git hooks (pre-commit formats and lints staged files, then runs `vp run fallow:audit`), and its `prepare` step patches the native `tsc` and oxlint with `@effect/tsgo`.

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
| `vp run release:pack`  | Builds, then packs what the Release workflow would publish into `release/` (publishes nothing).                                             |

The alchemy runtime suites (`test:alchemy`) run last in `vp run ci`; alchemy-postgres's server cases need `DATABASE_URL`.

[Fallow](https://github.com/fallow-rs/fallow) checks dead code, duplication, complexity and the package boundaries (`.fallowrc.json`). `vp run fallow:audit` audits your change against `origin/trunk` (after a coverage run, which it reads); `vp run fallow` summarises the whole tree. Use it to guide your work; its findings are advice, not law.

## Before pushing

Run `vp run ci` (CI runs exactly that, on Node LTS and latest). The pre-commit hook has already run the fallow audit. If a gate can't run where you are, say which and why in the PR body.

## Coding guidelines

- Effect v4 idioms throughout. Strongly prefer Effect's own modules (`Array`, `Option`, `Schema`, `Match`, `Clock`, `effect/crypto`, `effect/encoding`, …) over hand-rolled equivalents, and convert existing code where practical. Exceptions: Svelte code, non-Effect APIs adapted at the edge (the browser client, `./Ladder`), and measured hot paths. Non-idiomatic code you can't fix trivially: file an issue listing the sites and the idiomatic replacement.
- Read the installed `effect` (`node_modules/effect/dist/*.d.ts`, its `AGENTS.md` and `ai-docs/`) rather than guessing at an API: v4 renamed much of v3.
- Services are `Context.Service` classes with a static `layer`; resolve dependencies at layer construction so methods carry `R = never`.
- Errors are `Schema.TaggedError` classes: domain errors carry a stable `code`, HTTP-boundary errors a status ([DESIGN.md](DESIGN.md)).
- Every Effect module is a namespace import of its own entry point: helper modules under their canonical aliases (`Arr`, `P`, `R`, `Str`, `Eq`, `Bool`), the rest under their own name (`import * as Effect from "effect/Effect"`), never a named import from the `effect` barrel.
- Exports follow Effect v4's layout: `index.ts` exports PascalCase namespaces (`export * as SessionService from "./SessionService.ts"`) and nothing flat, and each public module is also importable through a PascalCase subpath (`./SessionService`). Lowercase subpaths are kept only for the clusters that gate an optional peer or a runtime (`./http`, `./client`, `./sql`, `./saml`, `./scrypt`) and for `./testing`. A new public module gets both, in every package.
- "Nothing" is an `Option`: a lookup, result or field that may be absent is `Option<T>`, never `T | null` or `T | undefined` (`effect/prefer-option-over-null` is an error). Members of an options object are `readonly x?: T` with no `| undefined` (`exactOptionalPropertyTypes` is on), so a caller holding a value that may be `undefined` leaves the key out, with a conditional spread (`...(x !== undefined && { x })`) or, inside the core, `definedKeys`. Use `x?: Option<T>` only for a member whose absence callers inspect and pass along. Optional function parameters are plain `x?: T`. Wire-shape schemas keep their native optionals, and values a third party spells `null` (JSON, SQL rows, node-saml) keep it behind a scoped override in `vite.config.ts`; convert at the boundary (`Option.fromNullishOr` in, `Option.getOrNull` out).
- Relative imports carry `.ts`.
- Compare secrets with `constantTimeHashEqual` / `timingSafeEqualBytes`, draw randomness from `SecureRandom`, store tokens as digests, and never log a credential. Generated ids are UUIDv4s from `SecureRandom` too. Keep `node:crypto` inside `password/Scrypt.ts`. Configuration errors thrown at construction are tagged errors too, never bare `RangeError`s.
- Fix lint findings in code. A rule is turned off only in `vite.config.ts`, with the reason.

### Comments

- A file comment only when it adds non-obvious context, in under 50 words.
- JSDoc where it helps a consumer in their editor; don't restate the signature. Keep what docgen needs (`@since`, runnable `@example`s).
- Inline comments only for what the code can't say: workarounds, performance, non-obvious decisions.
- Never cite issues, PRs or CI runs; stable links to external documentation are fine.

### READMEs

A package README says what the package is, how to install it, one minimal example, a table of its entry points, and links; nothing more. API detail goes in the export's doc comment, how-tos in a `docs/guides/` page. Links in a package README are absolute, since npm renders it without the repository.

### Tests

Tests sit beside the source (`Foo.test.ts`) and import from `vite-plus/test`, never `vitest`. Test logic that can break: error cases and the security properties (timing, entropy, expiry, replay). Don't test what the type system already checks. Storage adapters test against real engines in-process (PGlite, better-sqlite3).

## Dependencies

Dependabot ([dependabot.yml](../.github/dependabot.yml)) opens `@thomasfosterau/*` updates daily and every other update weekly, on Wednesday morning Melbourne time: the named runtime sets (`effect` and the like) each in one PR, and every other development dependency in the single `toolchain` group. Security updates skip the schedule and open as soon as an advisory lands, one PR each. Vite+ selects Node.js from `.node-version` and pnpm from `packageManager`; pnpm's own switching is off (`runtimeOnFail` / `pmOnFail`), so one version of each is installed and used.

Every external version lives in the `pnpm-workspace.yaml` catalog (`catalogMode: strict`); after editing it, run `vp install` and commit `pnpm-lock.yaml`. Dependabot groups the sets that must move together, but can't make these moves: make them in a PR from a new branch started from its PR's head (never push to a `dependabot/*` branch, which stops it rebasing), and Dependabot closes its own PR once yours merges.

- The npm aliases `vite` (equal to `vite-plus`), `typescript` and `@typescript/native`, and the devcontainer image tag (equal to `vite-plus`) with its digest.
- An `@effect/tsgo` whose `components` table covers the new oxlint and `@typescript/native`.
- `catalogs.peers`, `catalogs.alchemy-peers` and the advisory floors under `overrides`.

The published `effect` peer is `^4.0.0` unless a dependency or an Effect module first shipped in a later minor needs more; name the reason in the catalog comment. Raising it is a breaking change.

## Adding a package

Code that needs only `effect` (or a dependency the core already has) is a core subpath, not a package ([ADR-0022](adr/0022-package-boundaries.md)). A new package needs: a `vite.config.ts` using `packageTasks` (`vite.tasks.ts`), an `AGENTS.md` (boundary, invariants) with a one-line `CLAUDE.md` importing it, a row in the root README, its entries and zone in `.fallowrc.json`, its `#build` edge in the root `test:coverage` task, its `check:dist` target in `scripts/check-dist.ts`, and a changeset.

## Changesets

Every change to a published package's behaviour, or to a doc comment that reaches its `.d.ts`, needs a changeset (`vp exec changeset`) naming each package it touches. Docs-, CI- and tooling-only changes need none. Never version or publish by hand: the Release workflow opens the `chore: version packages` PR and the owner merges it ([PUBLISHING.md](PUBLISHING.md)).
