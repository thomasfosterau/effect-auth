# RealWorld × Nuxt × effect-auth

Conduit (Medium clone) on Nuxt 3 + Vue 3, integrating `effect-auth`
for password hashing and session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-nuxt dev
```

Open <http://localhost:3000>. SQLite DB is created at
`examples/realworld-nuxt/conduit.db` on first boot.

## What's specific to Nuxt here

- **`server/middleware/auth.ts`** — runs on every Nitro request,
  resolves the user from the session cookie or `Authorization: Token`
  header, and writes both onto `event.context` for downstream handlers.
- **`server/api/**`** — file-system routed JSON API matching the
Conduit spec. Method-specific files like `index.post.ts`and`[slug]/favorite.delete.ts` keep verbs explicit.
- **`plugins/user.server.ts`** — copies the SSR-resolved user into a
  Nuxt `useState('user')` so layouts and pages render the nav state
  correctly on the first paint and reuse the value on the client.
- **`nitro.externals`** in `nuxt.config.ts` keeps `better-sqlite3` and
  `effect-auth` as runtime requires.

## What's specific to `effect-auth` here

- `server/auth/adapters.ts` and `runtime.ts` — same shape as the other
  examples: `SessionStore` and `UserStore` backed by Drizzle, single
  shared `Context` value providing them plus `PasswordHasherLive`.

## Smoke test

Same as the other RealWorld examples — register two users, follow,
publish, comment, favorite, check personal feed.
