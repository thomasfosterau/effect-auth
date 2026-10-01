# Contributing to effect-auth

effect-auth is a pnpm workspace of thirteen `@thomasfosterau/effect-auth*` packages under `packages/*`; the core library is `packages/effect-auth`. Read [AGENTS.md](AGENTS.md) first: it holds the conventions, the commands and the gate list, and this file doesn't restate them.

## Setup

You need Node.js `^20.19.0 || ^22.18.0 || >=24.11.0` and pnpm 11 (the `packageManager` field pins the exact version; Corepack resolves it).

```bash
git clone https://github.com/thomasfosterau/effect-auth.git
cd effect-auth
vp install
```

`vp install` also installs the Vite+ git hooks: pre-commit runs `vp staged` (format + lint on staged files). There is no pre-push hook.

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

4. Document the change in the affected package's `README.md`, and update [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) if the module map changes.
5. Add a changeset with `pnpm changeset` when the change affects a published package ([AGENTS.md](AGENTS.md#branches-and-pull-requests) says which changes need one).

### Security-sensitive code

- Compare secrets in constant time with `constantTimeHashEqual` / `timingSafeEqualBytes` (`src/TokenHash.ts`).
- Draw randomness from the `Crypto.Crypto` service (default `PlatformCrypto.layer`), never `Math.random`.
- Store bearer tokens as SHA-256 digests (`hashToken`), never raw.
- Never log passwords, tokens, API keys or secrets.

[docs/ARCHITECTURE.md → Security Considerations](docs/ARCHITECTURE.md#security-considerations) describes the model these rules protect.

## Before you open a pull request

Run the gates in [AGENTS.md → Verification](AGENTS.md#verification), in that order, and record each result in the PR body. The PR template ([.github/pull_request_template.md](.github/pull_request_template.md)) asks for the rest.

## Reporting a vulnerability

Don't open a public issue; follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE.md).
