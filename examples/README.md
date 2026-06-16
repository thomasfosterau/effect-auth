# Examples

Each example under this directory is its own workspace package. They fall
into two groups:

- **Snippets and demos** — focused, single-file examples that show one
  feature of `effect-auth` in isolation (password hashing, sessions,
  OAuth, WebAuthn, etc.), plus the larger Northwind Traders end-to-end
  app.
- **RealWorld apps** — full implementations of the
  [RealWorld / Conduit](https://github.com/gothinkster/realworld) spec
  (a Medium clone with auth, articles, comments, follows, favorites,
  tags, feeds) showing idiomatic `effect-auth` integration per
  framework.

Build the library first so its declaration files exist:

```bash
bun run build
```

## Snippets and demos

Run any snippet via its workspace name:

```bash
bun --filter @effect-auth-examples/basic-auth start
```

…or by entering the directory:

```bash
cd examples/basic-auth && bun run index.ts
```

| Package                                   | Path                 | Demonstrates                                                                                      |
| ----------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| `@effect-auth-examples/basic-auth`        | `basic-auth/`        | Password hashing, session create/validate/invalidate.                                             |
| `@effect-auth-examples/authorization`     | `authorization/`     | Role-based access control, `requirePermission`.                                                   |
| `@effect-auth-examples/oauth`             | `oauth/`             | OAuth 2.0 social-login flows.                                                                     |
| `@effect-auth-examples/workos`            | `workos/`            | WorkOS integration: AuthKit/SSO URLs, User Management, Directory Sync, webhooks (full SDK).       |
| `@effect-auth-examples/webauthn`          | `webauthn/`          | Passkey / WebAuthn flow.                                                                          |
| `@effect-auth-examples/multi-algorithm`   | `multi-algorithm/`   | Multi-algorithm password verification.                                                            |
| `@effect-auth-examples/northwind-traders` | `northwind-traders/` | End-to-end app: sign-up, email verification, sessions, RBAC, rate-limiting, OAuth URL generation. |

## RealWorld apps — full Conduit implementations per framework

Each subdirectory below is an end-to-end implementation of the Conduit
spec showing idiomatic `effect-auth` integration for that framework:

| Framework            | Path                                                      |
| -------------------- | --------------------------------------------------------- |
| SvelteKit            | [`realworld-sveltekit/`](./realworld-sveltekit)           |
| Next.js (App Router) | [`realworld-nextjs/`](./realworld-nextjs)                 |
| Nuxt                 | [`realworld-nuxt/`](./realworld-nuxt)                     |
| React Router 7       | [`realworld-react-router/`](./realworld-react-router)     |
| TanStack Start       | [`realworld-tanstack-start/`](./realworld-tanstack-start) |
| Hono                 | [`realworld-hono/`](./realworld-hono)                     |

Each app is fully self-contained — its own SQLite database, its own
`effect-auth` storage adapters, its own UI. This is intentional: pick
the framework you care about and read it top-to-bottom without jumping
into shared code.

All RealWorld apps share these conventions:

- **Database**: SQLite via [`better-sqlite3`](https://github.com/WiseLibs/better-sqlite3) and [Drizzle ORM](https://orm.drizzle.team).
- **Auth**: Email + password + opaque session cookies (no JWTs). Password hashing via `effect-auth`'s default PBKDF2-SHA256 hasher.
- **API contract**: Matches the canonical Conduit JSON spec, so you can point the [Conduit Postman collection](https://github.com/gothinkster/realworld/tree/main/api) at any of them.

See each app's `README.md` for run instructions and what's different
about that framework's integration.

## Creating Your Own Example

Each example is a standalone workspace package. To add one:

1. Create a new directory under `examples/` (e.g. `examples/my-feature/`).
2. Add a `package.json` with `"effect-auth": "workspace:*"` as a dependency and
   a `start` script that runs your entry file.
3. Add a `tsconfig.json` extending `../../tsconfig.base.json`.
4. Add a `project.json` if you want an nx target for typecheck (mirror the
   other examples).
5. Write your example as `index.ts` (or any other entry file referenced from
   your `start` script). Import `* as Auth from "effect-auth"`.
6. Run `bun install` at the repo root so the workspace is linked.

## Further reading

- [Effect Documentation](https://effect.website/)
- [Lucia Authentication](https://lucia-auth.com/)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo Library](https://github.com/pilcrowonpaper/oslo)
