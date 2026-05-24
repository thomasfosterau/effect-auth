# RealWorld × Remix × effect-auth

Conduit (Medium clone) on Remix 2 (Vite preset), integrating
`effect-auth` for password hashing and session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-remix dev
```

Open <http://localhost:3002>. SQLite DB lives next to the workspace
in `examples/realworld-remix/conduit.db`.

## What's specific to Remix here

- **No global middleware** — every `loader` / `action` calls
  `getCurrentUser(request)` directly. The root loader exposes the
  user; nested routes read it via `useRouteLoaderData("root")`.
- **`createCookie` + `Set-Cookie` headers** — login / register / logout
  return a `Response` whose `headers` include `Set-Cookie` produced by
  `sessionCookie.serialize(...)`.
- **Flat route convention** — UI routes (`login.tsx`, `editor.$slug.tsx`)
  and JSON API resource routes (`api.users._index.tsx`,
  `api.articles.$slug.favorite.tsx`) live side by side in `app/routes/`.
  Resource routes have no default export, so Remix serves their
  `loader` / `action` as raw JSON for the Conduit Postman collection.
- **`_intent` form field** — article-page form actions disambiguate
  favorite / follow / comment / delete with a single `action` per route.

## What's specific to `effect-auth` here

Same shape as the other examples — `SessionStore` and `UserStore`
adapters in `app/server/auth/adapters.ts` backed by Drizzle, a single
shared `Context` value (`runtime.ts`) including `PasswordHasherLive`,
and thin `hashPassword` / `validateSession` wrappers.

## Known limitation: React 18 vs 19 in this monorepo

Remix 2.x has a `peerDependencies` of `react@^18.0.0`. Other apps in
this monorepo (Next.js 15) require React 19, and Bun hoists a single
React copy at the workspace root. Loading Remix's React-18-compiled
code against React 19 produces the "Objects are not valid as a React
child" SSR error because the element shapes differ (`_owner`/`_store`
removed in v19).

The **JSON API endpoints** under `app/routes/api.*` work end-to-end —
they don't render React, so the version collision doesn't affect them.
The Conduit Postman collection runs cleanly against
`http://localhost:3002/api`.

To use the UI standalone (outside this monorepo), copy
`examples/realworld-remix/` into its own directory and `bun install`;
without the React 19 hoisting from Next.js it will boot normally. The
type files include a `// @ts-nocheck` line at the top of each route
component to silence the same React 18/19 type incompatibility.
