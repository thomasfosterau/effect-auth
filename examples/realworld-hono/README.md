# RealWorld × Hono × effect-auth

Conduit (Medium clone) on [Hono](https://hono.dev) with `hono/jsx` for
server-rendered pages, integrating `effect-auth` for password hashing
and session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-hono dev
```

Open <http://localhost:3004>. SQLite DB at `examples/realworld-hono/conduit.db`.

## What's specific to Hono here

- **`src/server.ts`** — one Hono app with a single `app.use("*", ...)`
  middleware that resolves the current user from cookies or
  `Authorization: Token` header and writes both to `c.var.user` and
  `c.var.sessionId`. Downstream handlers read them with `c.get(...)`.
- **`src/routes/api.ts`** — the Conduit JSON API. Matches the spec
  endpoint-for-endpoint, so the official Postman collection runs
  against `http://localhost:3004/api`.
- **`src/routes/ui.ts`** — server-rendered Conduit UI using `hono/jsx`.
  Every interactive control is a tiny `<form method="post">` — no
  client JS framework, no hydration. Hono's JSX renderer turns
  components into HTML strings on the fly.
- **`@hono/node-server`** runs the same Hono app under Node (or Bun).

## What's specific to `effect-auth` here

Same shape as the other examples — `SessionStore` and `UserStore`
adapters in `src/auth/adapters.ts` backed by Drizzle + SQLite, shared
`Context` value (`runtime.ts`) including `PasswordHasherLive`.

## Smoke test

```bash
curl -X POST http://localhost:3004/api/users -H "Content-Type: application/json" \
  -d '{"user":{"email":"a@example.com","username":"alice","password":"password123"}}'
```

Then visit <http://localhost:3004> in a browser, sign in, create an
article, follow another user, etc.
