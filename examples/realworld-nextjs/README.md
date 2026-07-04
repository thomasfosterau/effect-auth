# RealWorld × Next.js × effect-auth

Conduit (Medium clone) on Next.js 15 App Router + React 19, integrating
`effect-auth` for password hashing and session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-nextjs dev
```

Open <http://localhost:3000>. SQLite DB is created at
`examples/realworld-nextjs/conduit.db` on first boot (override with
`CONDUIT_DB`).

## What's specific to Next.js here

- **`lib/server/auth/session.ts`** — uses `next/headers` `cookies()` and
  the Request object to resolve the session. The Edge runtime cannot
  load `better-sqlite3`, so we _don't_ use `middleware.ts`; instead
  every Server Component / Route Handler that needs the user calls
  `getCurrentUser()`.
- **`next.config.ts`** marks `better-sqlite3` and `effect-auth` as
  `serverExternalPackages` so Next leaves them as runtime requires
  instead of trying to bundle the native binary / Effect runtime code.
- **`app/actions.ts`** — Server Actions for login, register, settings,
  editor, follow/favorite/comment. Client components call them via
  `useActionState` (form state) or directly inside `useTransition`
  (button actions).
- **`app/api/**`** — the Conduit JSON API as Route Handlers. They
accept either the session cookie or `Authorization: Token <sid>` for
  Postman conformance.

## What's specific to `effect-auth` here

- `lib/server/auth/adapters.ts` — `SessionStore` and `UserStore`
  backed by Drizzle + SQLite.
- `lib/server/auth/runtime.ts` — single `Context` value composing the
  stores and the default `PasswordHasher`, memoised on `globalThis` so Next's
  HMR doesn't tear it down.

## Smoke test

Same as the SvelteKit example — register two users, follow, publish,
comment, favorite, check personal feed, edit, delete, logout.

## Limitations

- Email + password + sessions only this pass.
- Session ID used directly as API token. Production should use a
  separate opaque token bound to the session (per the Copenhagen Book).
