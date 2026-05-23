# Examples

This directory contains runnable examples that demonstrate how to use
`effect-auth`. There are two kinds of examples:

## Snippets — short, single-file demos

[`snippets/`](./snippets) — focused scripts that show off individual
features of the library (password hashing, sessions, authorization, OAuth,
WebAuthn, multi-algorithm hashing).

Make sure you have built the package first:

```bash
bun run build
```

Then run any snippet directly:

```bash
bun run examples/snippets/basic-auth.ts
bun run examples/snippets/authorization.ts
bun run examples/snippets/oauth.ts
bun run examples/snippets/webauthn.ts
bun run examples/snippets/multi-algorithm.ts
```

## RealWorld apps — full Conduit implementations per framework

Each subdirectory below is an end-to-end implementation of the
[RealWorld / Conduit](https://github.com/gothinkster/realworld) spec
(a Medium clone — auth, articles, comments, favorites, follows, tags,
feeds) showing idiomatic `effect-auth` integration for that framework:

| Framework            | Path                                                      |
| -------------------- | --------------------------------------------------------- |
| SvelteKit            | [`realworld-sveltekit/`](./realworld-sveltekit)           |
| Next.js (App Router) | [`realworld-nextjs/`](./realworld-nextjs)                 |
| Nuxt                 | [`realworld-nuxt/`](./realworld-nuxt)                     |
| Remix                | [`realworld-remix/`](./realworld-remix)                   |
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

## Further reading

- [Effect Documentation](https://effect.website/)
- [Lucia Authentication](https://lucia-auth.com/)
- [The Copenhagen Book](https://lucia-auth.com/copenhagen)
- [Oslo Library](https://github.com/pilcrowonpaper/oslo)
