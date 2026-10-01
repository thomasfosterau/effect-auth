# AGENTS.md

Project conventions for agents and humans working in this repository. `CLAUDE.md` is a symlink to this file.

effect-auth is a **library monorepo**: authentication and authorization for [Effect](https://effect.website/) v4, published as thirteen `@thomasfosterau/effect-auth*` packages. It has no application, no deployment and no secrets — every gate runs offline against the lockfile.

## Read first

- **[docs/BOUNDARY.md](docs/BOUNDARY.md)** — what effect-auth is relative to effect-jsonapi and legation, and the dependency rules between the three. effect-auth may depend on effect-jsonapi; it may **never** depend on legation (not even as a dev dependency); importing the core package root must not pull the HTTP tier into a consumer's module graph (`ModuleGraph.test.ts` pins that).
- **[docs/adr/README.md](docs/adr/README.md)** — the ADR index. ADRs are historical records that predate the July 2026 restructure; superseded ones are marked there. For what the library is today read [ADR-0017](docs/adr/0017-batteries-included-auth-framework.md) (batteries-included, not headless) and [ADR-0018](docs/adr/0018-one-authorization-kernel.md) (one authorization kernel; RBAC is authoring sugar over it) before anything else in that directory. A new settled decision gets the next ADR number and a row in the index.
- **[docs/DESIGN.md](docs/DESIGN.md)** — the settled API conventions (naming, `Context.Service` classes, `make` / `layer` exports, store contracts, error taxonomy). **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the module map as it stands. **[docs/CONTEXT.md](docs/CONTEXT.md)** — the domain vocabulary (credential vs verification vs auth state).
- **[docs/SECURITY.md](docs/SECURITY.md)** — the security requirements every change is held to.

## Package archetypes

Every package lives under `packages/*`, publishes `dist/` (built by `tsc`, or Vite for the JSX / SFC bindings), and peers `effect` through `catalog:peers`. They fall into five archetypes, and the archetype decides what a package may import:

| Archetype              | Packages                                        | Rule                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core**               | `effect-auth` (`@thomasfosterau/effect-auth`)   | Depends on `effect` only. Flat root modules for the spine (sessions, users, the authorization kernel: `Policy`, `Condition`, `Entity`, `Authorizer`, `Rbac`, …) plus lowercase cluster directories (`email/`, `http/`, `oauth/`, `password/`, `plugins/`, `multifactor/`), each with a subpath export. The HTTP tier (`http/`) is opt-in and must stay unreachable from the root barrel. |
| **Storage adapters**   | `sql`, `drizzle`, `alchemy`                     | Implement the core's store contracts (`SessionStore`, `UserStore`, `ApiKeyStore`, …) over a database. The database library is a **peer**, never bundled.                                                                                                                                                                                                                                 |
| **Vendor adapters**    | `argon2`, `resend`, `twilio`, `saml`            | Implement one core seam (`PasswordHasher`, `EmailSender`, `SmsSender`, `SamlVerifier`) over one vendor. Plain `fetch` against the vendor's REST API rather than an SDK where possible; Workers-safe.                                                                                                                                                                                     |
| **Client**             | `client` (`@thomasfosterau/effect-auth-client`) | The typed browser client over the HTTP contract plus the observable session store; `./testing` publishes the in-memory server fixture.                                                                                                                                                                                                                                                   |
| **Framework bindings** | `react`, `svelte`, `solid`, `vue`               | Thin bindings over `client`. The framework is a peer.                                                                                                                                                                                                                                                                                                                                    |

A new package picks an archetype, gets a `vite.config.ts` that declares its tasks through `packageTasks` ([vite.tasks.ts](vite.tasks.ts)), and gets a changeset.

## Gates

`vp install` once (it also installs the Vite+ git hooks: pre-commit runs `vp staged`, i.e. format + lint on staged files). Then:

- `vp check` — format + lint (the built-in pass, oxfmt + oxlint).
- `vp run check` — every package's type gates: `tsc` over sources and tests (`vue-tsc` / `svelte-check` where relevant) plus `vp test --typecheck`. Each package's `build`, `check` and `test:unit` tasks first build the workspace packages it depends on (their `exports` point at the gitignored `dist/`), so this works on a fresh checkout with no manual build.
- `vp run -r test:unit` — every package's unit tests.
- `vp run build` — every package's `dist/`.
- `vp run check:dist` — the dist-level import smoke test: packs the built packages, installs them beside one exact `effect` (default the peer floor; `-- --effect catalog` for the version the workspace builds against, which also covers `alchemy`) and imports every entry point. **Run `vp run build` first**; CI runs it twice, after the build step.

`vp check` is the built-in; `vp run check` is this repo's task. They are different commands. CI runs all four on every PR ([.github/workflows/ci.yml](.github/workflows/ci.yml)); run them yourself before pushing — there is no pre-push hook.

## Dependencies: strict catalog

Every external version lives in [pnpm-workspace.yaml](pnpm-workspace.yaml). `package.json` files reference only `catalog:` (dev and runtime dependencies), `catalog:peers` (published peer ranges) or `workspace:*`. `catalogMode: strict` makes pnpm reject anything else. Add a dependency by adding it to the catalog first, then `vp install`, and commit the regenerated `pnpm-lock.yaml`. `effect` is a singleton pinned exactly (with an `overrides` entry); its published peer range is `>=4.0.0-rc.113` (the programme floor), proven at dist level by `vp run check:dist`, which installs the packed packages beside the floor version and imports every entry point.

## Changesets and releases

- **Every change to a published package carries a changeset** (`vp run changeset`, or write `.changeset/<slug>.md` by hand) naming each package it touches. Docs, CI and tooling-only changes need none.
- The default branch is **`trunk`**. Merging to `trunk` makes the Release workflow open or update the "Version Packages" PR; merging that PR publishes to npm via OIDC trusted publishing, with provenance, from the protected `release` environment. There is no `NPM_TOKEN`. See [PUBLISHING.md](PUBLISHING.md).
- **Agents never publish** and never merge the Version Packages PR — the owner does.

## Branches and PRs

Branch off `trunk`, open the PR against `trunk`, one issue per PR. Fill the PR body with what changed and why, which gates ran and their result, and the changesets added; keep it current as the branch moves. GitHub writes are scoped to this repository.

## Effect

**Consult effect-solutions before writing Effect code** — `vp exec effect-solutions list`, then `vp exec effect-solutions show <topic>…` (topics: quick-start, project-setup, tsconfig, basics, services-and-layers, data-modeling, error-handling, config, testing, cli). When the guides run out, read the Effect source itself in `node_modules/effect/src`. Never guess at an Effect pattern.

House style, enforced by review rather than lint: services are `Context.Service` classes with a static `layer`; errors are `Schema.TaggedError` classes (older modules still use `Data.TaggedError`); dependencies are resolved at layer construction so service methods carry `R = never`; HTTP is `effect/unstable/httpapi`.

## Claude Code sessions

[.claude/hooks/session-start.sh](.claude/hooks/session-start.sh) runs on every session start (and is what the devcontainer's `postCreateCommand` runs): it installs dependencies against the lockfile and links `vp` and `tsx` onto `PATH` for non-interactive shells. It hydrates no secrets; none are needed.
