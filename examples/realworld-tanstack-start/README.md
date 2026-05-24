# RealWorld × TanStack Start × effect-auth

Conduit (Medium clone) on [TanStack Start](https://tanstack.com/start)
(React + Vinxi), integrating `effect-auth` for password hashing and
session management.

## Run

```bash
bun install
bun run --cwd examples/realworld-tanstack-start dev
```

Open <http://localhost:3003>. SQLite DB at `examples/realworld-tanstack-start/conduit.db`.

## What's specific to TanStack Start here

- **`app/routes/__root.tsx`** — `createRootRouteWithContext<{ user }>` +
  `beforeLoad` resolves the current user from cookies/headers once per
  navigation. Nested routes read it via `Route.useRouteContext()`.
- **`app/server/fns.ts`** — every server-side operation is a
  `createServerFn` (signup, login, articles CRUD, follow, favorite,
  comments). Components call them like RPC: `await login({ data: { ... } })`.
- **`app/server/auth/session.ts`** — cookies via `vinxi/http` helpers
  (`getCookie`, `setCookie`, `deleteCookie`).
- **`app.config.ts`** — Vinxi + `@tanstack/react-start/config` glue;
  `vite.ssr.external` keeps `better-sqlite3` out of the SSR bundle.

## Caveats

- **TanStack Start API churn**: the framework's surface has changed
  substantially between versions. This example targets the v1.92-era
  setup (Vinxi-based, `@tanstack/react-start/config`). Newer versions
  (1.168+) use plain Vite and drop the `/config` and `/router-manifest`
  entrypoints. Before running locally, pin TanStack Start to v1.92 or
  update `app.config.ts`, `app/client.tsx`, `app/ssr.tsx`, and
  `app/server/fns.ts` to current TanStack Start conventions. Route
  files carry `// @ts-nocheck` headers for the same reason; the
  `effect-auth` integration in `app/server/auth/**` is stable.
- **No JSON REST API**: this example uses server functions (RPC) instead
  of REST endpoints, so the Conduit Postman collection doesn't apply to
  this app the way it does to the others. The other 5 examples cover
  the REST contract.

## `effect-auth` integration

Same pattern as the other examples — `SessionStore` and `UserStore`
adapters in `app/server/auth/adapters.ts`, shared `Context` in
`runtime.ts` wiring them up with `PasswordHasherLive`.
