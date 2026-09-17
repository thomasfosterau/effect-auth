# Auth as a separate service

effect-auth can be mounted in your app's own Worker, or deployed as its **own internal
service** that the app reaches over a binding. Both are supported. This guide covers the
split topology — what it buys, what it costs, and the two seams the library owns so your
app does not have to.

## Should you split?

Mounting `Http.make` directly in the app's Worker is simpler and should be the default:

```ts
const mount = Effect.gen(function* () {
  const { handler } = yield* Http.make({ prefix: "/api/auth" /* … */ });
  return handler; // mount it in your framework
});
```

One deployment, no transport, no relay, and the session is resolved in-process. Split when
you have a reason:

| Reason to split                                | What it buys                                         |
| ---------------------------------------------- | ---------------------------------------------------- |
| Several apps share one identity                | One session store, one config, one set of secrets    |
| The auth surface must not be publicly routable | An internal-only service has no public URL to attack |
| Auth deploys on its own cadence                | A password-policy change does not redeploy the app   |

And know the cost: **session resolution becomes a network call on the hot path of every
request**. Everything below exists to make that call cheap, safe when it fails, and
observable.

> An un-routed service is still a published service. If your platform can expose it by
> default (Cloudflare's `workers.dev`, for instance), turn that off explicitly and pin it
> with a test. "We never gave out the URL" is not access control.

## The transport

`Http.client(baseUrl)` needs an `HttpClient` in context and does not care where the bytes
go. `RemoteSession.layerFetcher` builds one from any fetch-alike — a Cloudflare service
binding, a `Http.make` handler mounted in-process, a test double:

```ts
import { Effect } from "effect";
import { Http } from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const client = yield* Http.client("https://auth.internal");
  return yield* client.auth.signIn({ payload: { email, password } });
}).pipe(Effect.provide(Http.RemoteSession.layerFetcher(env.AUTH)));
```

The typed client replaces the hand-written "POST to an auth route and classify the status
code into a tagged error" service that this topology otherwise grows: the contract already
carries `UnauthorizedError`, `EmailInUseError` and the rest as typed failures.

What it cannot carry is `Set-Cookie`. That is the next two sections.

## Resolving the session

```ts
const auth = Http.RemoteSession.make({ fetcher: env.AUTH, prefix: "/api/auth" });

const handle = (request: Request) =>
  Effect.gen(function* () {
    const { session, setCookie } = yield* Http.RemoteSession.resolveAtEdgeFailOpen({
      client: auth,
      request,
      onDegraded: (cause) => Effect.logError("auth service unreachable", cause),
    });

    // Run the rest of the request as this viewer.
    const response = yield* app(request).pipe(Effect.provide(SessionContext.layer(session)));

    // Replay the cookies the auth service asked for (see below).
    return Http.RemoteSession.withSetCookie(response, setCookie);
  });
```

Three things happen there that are worth naming.

### The cookieless skip

`resolveAtEdge*` checks for a credential before making the call. A request carrying no
session cookie, no bearer token and no API key provably cannot resolve, so it never
reaches the binding — reported as `skipped`, not folded into `anonymous`. On a hot path
this is the largest read-path win available.

The cookie name it looks for is _derived_, not configured: `SessionCookies.cookieNames`
runs the same `__Host-`-prefix rule that `resolveCookieConfig` does, so the predicate
cannot drift from what the middleware reads. Do not restate the name in your app.

### The fault posture

`resolveAtEdgeFailOpen` degrades an unreachable service to anonymous rather than failing
the request. That is usually right here — the read sits on _every_ request, so failing
closed turns one binding fault into a site-wide 500 — but it is only **safe** when
anonymous is the lower-privilege outcome for your app. `docs/SECURITY.md` states the
precondition and the shapes where fail-open is an escalation instead. `resolveAtEdge`
fails closed for those.

`onDegraded` is mandatory. A silently degrading auth service looks exactly like a site
where nobody happens to be signed in.

### Header forwarding is the library's job

The forwarded set is an **allow-list**: the credential (`cookie`, `authorization`,
`x-api-key`), the caller's identity (`cf-connecting-ip`, `x-forwarded-for`,
`accept-language`, `user-agent`) and the CSRF inputs (`origin`, `referer`).

`content-type` and `content-length` are deliberately _not_ on it. Forwarding an inbound
request's content headers onto a bodyless `GET` makes a router believe the request has a
body; its content-type allow-list then runs against whatever your app's own dispatch uses
— `application/vnd.api+json`, say — and rejects it with 415. The session fails to resolve,
the request degrades to anonymous, and every gated route answers 401. An allow-list makes
that failure unreachable rather than something you remember to strip.

Extend it with `headers: { also: [...] }` rather than replacing it.

### CSRF across a server-to-server hop

effect-auth's trusted-origin guard checks `Origin`, falls back to `Referer`, and allows a
request that carries neither — a server-to-server call is not a CSRF vector. So a binding
transport does **not** need to synthesise an `Origin`.

It does need to forward the browser's, which the default policy does. That means the
browser's origin must be in the auth service's `trustedOrigins` — the app's public origin,
not the auth service's internal one.

## The `Set-Cookie` relay

Establishing or clearing a session means getting `Set-Cookie` to the browser, and that
header has no representation in a typed JSON success value. Sign-in, sign-up and sign-out
therefore need a raw passthrough:

```ts
// POST /session/sign-in on the app's Worker
const signIn = (request: Request) => auth.relay(request, "/sign-in");
```

`relay` forwards the request and returns the upstream response verbatim — status, body and
`Set-Cookie` intact.

### Session _reads_ need the relay too

When the signed session-data cookie cache is on, a session read refreshes it with a
`Set-Cookie` on the response. Drop that header and the cache stops refreshing after its
first window — quietly, with every subsequent request paying a store read. That is why
`RemoteSessionResult` carries `setCookie` and why the snippet above ends with
`withSetCookie`.

### Never relay a cookie to a machine caller

A request bearing an API key is not a browser. Handing it a `Set-Cookie` plants session
state in whatever cookie jar its HTTP client happens to keep, for no benefit — the key,
not a session, is its credential.

`relay` drops `Set-Cookie` unless the **inbound** request carried a browser session cookie
and no machine credential. The mixed case, a request carrying both, is excluded too. A
bearer-only native client gets nothing either; `bearerMode`'s `set-auth-token` header is
the channel for that.

If you relay through your own code path, apply the same rule with
`RemoteSession.relayResponse(upstream, credential)`.

### Bypassing your own dispatch

These routes bypass the negotiated dispatch that would otherwise have applied your app's
cross-origin guard. Apply one to them explicitly. Nothing in this library does it for you,
because the guard is your app's, not the auth service's.

## Putting it together

```ts
import { Effect } from "effect";
import { Http, SessionContext } from "@thomasfosterau/effect-auth";

const auth = Http.RemoteSession.make({ fetcher: env.AUTH });

const handle = (request: Request) =>
  Effect.gen(function* () {
    // Credential mutation: raw passthrough, Set-Cookie relayed.
    const url = new URL(request.url);
    if (url.pathname.startsWith("/session/")) {
      return yield* auth.relay(request, url.pathname.replace("/session", ""));
    }

    // Everything else: resolve, run, replay.
    const { session, setCookie } = yield* Http.RemoteSession.resolveAtEdgeFailOpen({
      client: auth,
      request,
      onDegraded: (cause) => Effect.logError("auth service unreachable", cause),
    });

    const response = yield* app(request).pipe(Effect.provide(SessionContext.layer(session)));
    return Http.RemoteSession.withSetCookie(response, setCookie);
  });
```

## What to watch

`effect-auth.session_resolutions.total` is tagged with the four outcomes, and the
`effect-auth.resolve-session` span carries the same value as `auth.outcome`:

- `skipped` climbing is the fast path working.
- `anonymous` climbing relative to `resolved` means stale credentials — check the session
  and cache lifetimes.
- `degraded` above zero means the auth service is faulting and users are silently signing
  out. Alert on it.

See `docs/OBSERVABILITY.md`.
