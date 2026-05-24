# RealWorld × React Router × effect-auth

Conduit (Medium clone) on [React Router 7](https://reactrouter.com) in
framework mode (the post-merger Remix successor), integrating
`effect-auth` for password hashing and session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-react-router dev
```

Open <http://localhost:3002>. SQLite DB at `examples/realworld-react-router/conduit.db`.

## What's specific to React Router here

- **No global middleware** — every `loader` / `action` calls
  `getCurrentUser(request)` directly. The root loader exposes the
  user; nested routes read it via `useLoaderData` after the loader's
  data is plumbed through React Router's nested route data flow.
- **`createCookie` from `react-router`** — login / register / logout
  return a `Response` with `Set-Cookie` produced by
  `sessionCookie.serialize(...)`.
- **`app/routes.ts`** — explicit route config (the post-Remix-merger
  default) declares both UI routes and JSON API resource routes.
- **JSON API resource routes** (e.g. `api.users.tsx`,
  `api.articles.$slug.favorite.tsx`) have no default export, so
  React Router serves their loader/action output as raw `Response`
  for the Conduit Postman collection.
- **`_intent` form field** — article-page form actions disambiguate
  favorite / follow / comment / delete with a single `action` per route.

## Why React Router instead of Remix in this monorepo

Remix 2 hard-requires `react@^18` as a peer dep, but the monorepo's
Next.js workspace hoists React 19, producing an SSR element-shape
collision. React Router 7 supports React 19 natively, so we use it
here.

## `effect-auth` integration

Same shape as the other examples — `SessionStore` and `UserStore`
adapters in `app/server/auth/adapters.ts` backed by Drizzle, a single
shared `Context` value (`runtime.ts`) including `PasswordHasherLive`,
and thin `hashPassword` / `validateSession` wrappers.
