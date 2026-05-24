# RealWorld × SvelteKit × effect-auth

A full implementation of the [RealWorld / Conduit](https://github.com/gothinkster/realworld)
spec (Medium clone — articles, comments, follows, favorites, tags, feeds)
showing idiomatic `effect-auth` integration with SvelteKit.

## Run

```bash
bun install            # from repo root
bun run dev            # in this directory, or:
bun run --cwd examples/realworld-sveltekit dev
```

Open <http://localhost:5173>.

The SQLite database is created on first boot at `examples/realworld-sveltekit/conduit.db`.
Set `CONDUIT_DB` to override the path. Delete the file to start fresh.

## What's specific to SvelteKit here

- **`src/hooks.server.ts`** — runs on every request. Reads the session
  cookie, calls `effect-auth`'s `SessionManager.validateSession`, and
  populates `event.locals.user`. This is the canonical place to wire
  session auth in SvelteKit. The session is also re-set on each response
  so its idle timeout is extended (sliding session).
- **`+page.server.ts` actions** — login, register, logout, article CRUD,
  follow/favorite/comment all go through SvelteKit form actions. They
  call `effect-auth` services and then return `redirect` / `fail`.
- **`src/routes/api/**`** — the Conduit JSON API. Endpoints accept the
session ID via `Authorization: Token <sid>`(matching the spec's`Authorization: Token <jwt>`header) or via the session cookie. Point
the [Conduit Postman collection](https://github.com/gothinkster/realworld/tree/main/api)
at`http://localhost:5173/api`and`APIURL=http://localhost:5173/api newman run ...`.

## What's specific to `effect-auth` here

- **`src/lib/server/auth/adapters.ts`** — `SessionStore` and `UserStore`
  implementations backed by Drizzle + SQLite. The shapes match the
  interfaces in `packages/effect-auth/src/Session.ts`.
- **`src/lib/server/auth/runtime.ts`** — a single `Context` value
  composing the stores and `PasswordHasherLive`. Memoised on
  `globalThis` so HMR doesn't tear it down on every reload.
- **`src/lib/server/auth/passwords.ts`** and **`sessions.ts`** —
  thin wrappers that pull the relevant service out of `effect-auth` and
  run it through the shared context. Calling code never touches
  `Effect.runPromise` directly.

## Tech stack

- SvelteKit 2 + Svelte 5 (runes)
- `@sveltejs/adapter-node` for production
- Drizzle ORM + `better-sqlite3`
- `effect-auth` (workspace dependency) for password hashing and sessions

## Smoke test

1. Sign up user A → publish an article with tags `effect, sveltekit` → comment on it → favorite it.
2. Open a private window, sign up user B → visit user A's profile → Follow → open `/?tab=your` → confirm the article appears.
3. Edit the article → delete it → confirm it vanishes from the global feed.
4. Sign out → confirm `/editor` and `/settings` redirect to `/login`.

## Limitations

- Auth surface intentionally limited to email + password + sessions. OAuth, WebAuthn, email verification, and password reset are demonstrated in `examples/snippets/`.
- The session ID is used as the API "token". Production should consider
  opaque tokens that are not equal to the cookie value (per [Copenhagen](https://thecopenhagenbook.com)).
