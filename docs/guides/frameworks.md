# effect-auth in Next.js, Nuxt, Astro, Hono and Express

The HTTP API is one Web handler, `(request: Request) => Promise<Response>`, so it runs under any
framework that can hand it a `Request`. Wiring it into an app takes three things:

1. **Mount the handler** on a catch-all route under its prefix (`/api/auth/*`).
2. **Resolve the session once per request**, at the app's edge, before any page or route reads it.
3. **Relay the cookies** the resolution asks for onto the app's response.

One shared module does the work; each framework section below is only the glue. SvelteKit has a
package of its own ([the SvelteKit guide](sveltekit.md)), and auth running as a separate service is
[its own guide](split-auth-service.md). The browser side is the same everywhere:
[the browser client](client.md).

## The shared module

```ts
// auth.server.ts
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";
import * as Sql from "@thomasfosterau/effect-auth/sql";
import { SqlClientLayer } from "./db"; // your effect/sql driver, e.g. @effect/sql-pg
import { sendResetEmail, sendVerificationEmail } from "./mail"; // (email, token) => Effect<void, …>

// The stores, and the root secret (`AUTH_SECRET`) the services key from. Run
// `Sql.migrate` once at deploy or startup.
const stores = Layer.merge(Sql.layer, Auth.RootSecret.RootSecret.layerConfig).pipe(
  Layer.provideMerge(SqlClientLayer),
);

// Each stage provides the next; `provideMerge` keeps every service in the output.
const base = Layer.mergeAll(
  Auth.Hooks.Hooks.Default, // no-op hooks; compose plugins here instead
  Auth.Password.PasswordHasher.layer(),
  Auth.RateLimit.RateLimiter.layer(), // the per-address limits the handler applies by default
).pipe(Layer.provideMerge(stores));
const sessionsAndUsers = Layer.mergeAll(
  Auth.SessionService.SessionService.layer({
    sessionExpiresIn: { activePeriod: 30 * 864e5, idlePeriod: 14 * 864e5 },
  }),
  Auth.User.UserService.layer(),
).pipe(Layer.provideMerge(base));
const signIn = Layer.mergeAll(
  Auth.Email.EmailPasswordService.layer(),
  Auth.Email.EmailVerificationService.layer({ sendEmail: sendVerificationEmail }),
  Auth.Password.PasswordResetService.layer({ sendResetPassword: sendResetEmail }),
).pipe(Layer.provideMerge(sessionsAndUsers));
const services = Auth.AuthLifecycle.AuthLifecycleService.layer().pipe(Layer.provideMerge(signIn));

export const prefix = "/api/auth";
const CLIENT_ADDRESS_HEADER = "x-client-address";
// `secure: false` in development over plain http. It changes the cookie's name
// (no `__Host-` prefix), so the session reader below gets the same setting.
const cookie = { secure: process.env.NODE_ENV === "production" };

const auth = Http.makeAsync({
  services,
  prefix,
  cookie,
  trustedOrigins: ["https://app.example.com"],
  // The rate limits key on the visitor's address, read only from this header.
  trustedProxy: Auth.ClientIP.ClientIP.trustedHeader(CLIENT_ADDRESS_HEADER),
});

// The header carries the address the framework saw, never one the browser sent.
const withClientAddress = (request: Request, clientAddress: string | undefined): Request => {
  const headers = new Headers(request.headers);
  headers.delete(CLIENT_ADDRESS_HEADER);
  if (clientAddress !== undefined) headers.set(CLIENT_ADDRESS_HEADER, clientAddress);
  return new Request(request, { headers });
};

/** Serve a request to the auth API. */
export const handleAuth = async (request: Request, clientAddress: string | undefined) =>
  (await auth).handler(withClientAddress(request, clientAddress));

// The app reads the session through the same handler, in process.
const sessions = Http.RemoteSession.make({
  fetcher: async (request) => (await auth).handler(request),
  prefix,
  credentials: cookie,
  clientAddressHeader: CLIENT_ADDRESS_HEADER,
});

/** The session for an app request, and the cookies to set on its response. */
export const getSession = (request: Request, clientAddress: string | undefined) =>
  Effect.runPromise(
    Http.RemoteSession.resolveAtEdgeFailOpen({
      client: sessions,
      request,
      ...(clientAddress !== undefined && { clientAddress }),
      onDegraded: (cause) => Effect.logError("session lookup degraded", cause),
    }),
  );
```

What it relies on:

- **`Http.makeAsync`** waits for `services` to build and rejects on a startup error (a missing
  `RateLimiter`, or no client address source for the per-address limits), so the app fails at its
  first request with the reason rather than serving broken auth. The module keeps the promise, so
  the handler is built once.
- **Never pass a framework's own context as the handler's second argument.** `handler` takes an
  optional Effect `Context` there. Next.js route handlers, Hono and others call a handler with a
  context of their own, so always wrap it: `(request) => handleAuth(request, address)`.
- **The client address.** The default per-address limits need the visitor's address, and a Web
  `Request` carries none. `withClientAddress` writes the address the framework knows (the socket,
  or the framework's own resolution of it) into one header, replacing anything the browser sent
  there, and the handler trusts only that header. Behind a platform that sets an address header the
  client cannot forge, trust that header instead and drop the rewrite: `Auth.ClientIP.ClientIP.cloudflare`
  behind Cloudflare.
- **`getSession`** answers `{ session, setCookie, outcome, credentialClass }`. `session` is an
  `Option` of `{ session, user }`. A request with no session cookie, bearer token or API key is
  answered without a call (`outcome: "skipped"`). `resolveAtEdgeFailOpen` treats a lookup fault as
  anonymous and reports it through `onDegraded`; that is safe only when anonymous is the
  lower-privilege outcome for your app. Use `resolveAtEdge` to fail closed instead.
  [The split-service guide](split-auth-service.md#resolving-the-session) covers the outcome, the
  credential class and API keys, which work the same in process.
- **`setCookie`** holds the `Set-Cookie` lines the session read produced: the signed cookie cache's
  refresh, when `cookie.cache` is on. Replay them on the app's response, or the cache stops
  refreshing after its first window. `Http.RemoteSession.withSetCookie(response, setCookie)` does
  it for a `Response` and marks it `Cache-Control: no-store`. It is empty for a request carrying an
  API key or a bearer token.
- **Origins.** Every state-changing request to the handler must come from an origin in
  `trustedOrigins`. List the app's own.

The browser client talks to the mounted route: `createAuthClient({ baseUrl: "/api/auth" })`.

## Next.js (App Router)

Mount the handler on a catch-all route handler:

```ts
// app/api/auth/[...all]/route.ts
import { handleAuth } from "@/auth.server";

const handler = (request: Request) => handleAuth(request, clientAddress(request));

export { handler as GET, handler as POST, handler as PATCH, handler as PUT, handler as DELETE };
```

Next.js puts no client address on a route handler's `Request`. `clientAddress` reads it from the
header your host sets and overwrites; if that header is one the client cannot forge, trust it
directly in `trustedProxy` instead of rewriting.

Read the session in a Server Component or a Server Action from the incoming headers:

```ts
// app/session.ts
import { headers } from "next/headers";
import * as Option from "effect/Option";
import { getSession } from "@/auth.server";

export const currentUser = async () => {
  const request = new Request("https://app.internal/", { headers: await headers() });
  const { session } = await getSession(request, undefined);
  return Option.getOrNull(session)?.user ?? null;
};
```

A Server Component cannot set cookies, so `setCookie` is dropped there. That is fine unless the
cookie cache is on; then also resolve the session in middleware (`middleware.ts`, renamed
`proxy.ts` in Next.js 16), which can set them, on the Node.js runtime:

```ts
// middleware.ts
import { NextResponse, type NextRequest } from "next/server";
import { getSession } from "@/auth.server";

export const config = { runtime: "nodejs", matcher: ["/((?!api/auth|_next/).*)"] };

export async function middleware(request: NextRequest) {
  const { setCookie } = await getSession(request, undefined);
  const response = NextResponse.next();
  for (const line of setCookie) response.headers.append("set-cookie", line);
  return response;
}
```

## Nuxt

Nuxt's server is Nitro on h3. Mount the handler on a catch-all server route; h3 sends a returned
`Response` as it is:

```ts
// server/api/auth/[...].ts
import { handleAuth } from "~/server/auth";

export default defineEventHandler((event) => handleAuth(toWebRequest(event), getRequestIP(event)));
```

Resolve the session in server middleware, which runs before every route, and put it on
`event.context`:

```ts
// server/middleware/auth.ts
import { getSession, prefix } from "~/server/auth";

export default defineEventHandler(async (event) => {
  if (event.path.startsWith(prefix)) return;
  // Headers only: the session read never needs the body, and reading it here
  // would leave none for the route.
  const request = new Request(getRequestURL(event), { headers: getRequestHeaders(event) });
  const edge = await getSession(request, getRequestIP(event));
  event.context.auth = edge;
  for (const line of edge.setCookie) appendResponseHeader(event, "set-cookie", line);
});
```

`getRequestIP(event)` is the socket address; behind your own proxy, pass `{ xForwardedFor: true }`
only if that proxy overwrites `x-forwarded-for`. Declare the type of `event.context.auth` in
`H3EventContext` (a `declare module "h3"` block). Pages read the session through a server route or
`useRequestEvent()` during server rendering, and the browser through the client.

## Astro

Astro needs an adapter that renders on demand (`output: "server"`, or `prerender = false` on the
routes that need it). Mount the handler on a catch-all endpoint:

```ts
// src/pages/api/auth/[...all].ts
import type { APIRoute } from "astro";
import { handleAuth } from "../../../auth.server";

export const prerender = false;

export const ALL: APIRoute = ({ request, clientAddress }) => handleAuth(request, clientAddress);
```

Resolve the session in middleware, put it on `locals`, and replay the cookies on the response:

```ts
// src/middleware.ts
import { defineMiddleware } from "astro:middleware";
import * as Http from "@thomasfosterau/effect-auth/http";
import { getSession, prefix } from "./auth.server";

export const onRequest = defineMiddleware(async (context, next) => {
  if (context.isPrerendered || context.url.pathname.startsWith(prefix)) return next();
  const edge = await getSession(context.request, context.clientAddress);
  context.locals.auth = edge;
  return Http.RemoteSession.withSetCookie(await next(), edge.setCookie);
});
```

Declare `auth` on `App.Locals` in `src/env.d.ts`. Pages read `Astro.locals.auth.session`.
`clientAddress` throws on a prerendered page, which the first line skips.

## Hono

Register the auth route before the session middleware, so a request to the auth API never pays for
a session read:

```ts
import { Hono } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo"; // your runtime's helper
import * as Option from "effect/Option";
import * as Http from "@thomasfosterau/effect-auth/http";
import { getSession, handleAuth } from "./auth.server";

type Edge = Awaited<ReturnType<typeof getSession>>;
const app = new Hono<{ Variables: { auth: Edge } }>();

app.on(["GET", "POST", "PATCH", "PUT", "DELETE"], "/api/auth/*", (c) =>
  handleAuth(c.req.raw, getConnInfo(c).remote.address),
);

app.use(async (c, next) => {
  const edge = await getSession(c.req.raw, getConnInfo(c).remote.address);
  c.set("auth", edge);
  await next();
  c.res = Http.RemoteSession.withSetCookie(c.res, edge.setCookie);
});

app.get("/me", (c) => c.json({ user: Option.getOrNull(c.get("auth").session)?.user ?? null }));
```

`getConnInfo` comes from the adapter for your runtime (`hono/bun`, `hono/deno`,
`@hono/node-server/conninfo`). On Cloudflare Workers, trust `Auth.ClientIP.ClientIP.cloudflare` in the
shared module and pass `undefined`.

## Express

Express speaks Node's request and response, so the glue converts between those and the Web types.
Mount the auth route before any body parser: `express.json()` would consume the body the handler
reads.

```ts
import express, { type Request as ExpressRequest, type Response as ExpressResponse } from "express";
import { Readable } from "node:stream";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import * as Option from "effect/Option";
import { getSession, handleAuth } from "./auth.server";

const toWebRequest = (req: ExpressRequest, withBody: boolean): Request => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
      headers.append(name, item);
    }
  }
  const url = new URL(req.originalUrl, `${req.protocol}://${req.get("host")}`);
  const hasBody = withBody && req.method !== "GET" && req.method !== "HEAD";
  return new Request(url, {
    method: req.method,
    headers,
    ...(hasBody && { body: Readable.toWeb(req) as ReadableStream, duplex: "half" }),
  });
};

const sendWebResponse = (res: ExpressResponse, response: Response): void => {
  res.status(response.status);
  response.headers.forEach((value, name) => {
    if (name !== "set-cookie") res.setHeader(name, value);
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader("set-cookie", cookies);
  if (response.body === null) res.end();
  else Readable.fromWeb(response.body as NodeReadableStream).pipe(res);
};

const app = express();

app.all("/api/auth/*splat", async (req, res) => {
  sendWebResponse(res, await handleAuth(toWebRequest(req, true), req.ip));
});

app.use(async (req, res, next) => {
  const edge = await getSession(toWebRequest(req, false), req.ip);
  res.locals.auth = edge;
  if (edge.setCookie.length > 0) res.append("set-cookie", [...edge.setCookie]);
  next();
});

app.use(express.json());
app.get("/me", (_req, res) => {
  res.json({ user: Option.getOrNull(res.locals.auth.session)?.user ?? null });
});
```

This is Express 5, which forwards a rejected handler to the error middleware and spells a wildcard
`*splat`; on Express 4 write `/api/auth/*` and catch the rejection yourself. `req.ip` is the socket
address. Behind your own proxy, set `app.set("trust proxy", …)` to the hops it adds so `req.ip`
reads the visitor's address, never the raw `x-forwarded-for`.
