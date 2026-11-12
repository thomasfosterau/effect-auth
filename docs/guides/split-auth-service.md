# Auth as a separate service

effect-auth can be mounted in your app's own Worker, or deployed as its **own internal
service** that the app reaches over a binding. Both are supported. This guide covers the
split topology — what it buys, what it costs, and the two seams the library owns so your
app does not have to.

## Should you split?

Mounting `Http.makeAsync` directly in the app's Worker is simpler and should be the default:

```ts
const { handler } = await Http.makeAsync({
  services, // with a RateLimiter: the per-address limits are on by default
  prefix: "/api/auth",
  trustedProxy: Auth.ClientIP.cloudflare,
  /* … */
});
// Mount `handler` in your framework.
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
>
> On Alchemy, that is `workersDev: false` on the auth Worker: see
> [Auth as an internal Worker on Alchemy](alchemy-internal-worker.md#2-the-auth-worker-is-internal-only-because-it-declares-workersdev-false).

## The transport

`Http.client(baseUrl)` needs an `HttpClient` in context and does not care where the bytes
go. `RemoteSession.layerFetcher` builds one from any fetch-alike — a Cloudflare service
binding, a `Http.make` handler mounted in-process, a test double:

```ts
import { Effect } from "effect";
import * as Http from "@thomasfosterau/effect-auth/http";

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
    const { session, setCookie, credentialClass } = yield* Http.RemoteSession.resolveAtEdgeFailOpen(
      {
        client: auth,
        request,
        onDegraded: (cause) => Effect.logError("auth service unreachable", cause),
      },
    );

    // Run the rest of the request as this viewer.
    const response = yield* app(request).pipe(
      Effect.provide(
        Option.isSome(session)
          ? SessionContext.authenticatedLayer(session.value, { credentialClass })
          : SessionContext.anonymousLayer,
      ),
    );

    // Replay the cookies the auth service asked for (see below).
    return Http.RemoteSession.withSetCookie(response, setCookie);
  });
```

Four things happen there that are worth naming.

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
anonymous is the lower-privilege outcome for your app. [ARCHITECTURE.md](../ARCHITECTURE.md#fail-open-vs-fail-closed-session-resolution) states the
precondition and the shapes where fail-open is an escalation instead. `resolveAtEdge`
fails closed for those.

`onDegraded` is mandatory. A silently degrading auth service looks exactly like a site
where nobody happens to be signed in.

### The credential class travels with the session

`credentialClass` says _how_ the caller got in — `"machine"` for an API key or bearer token,
`"interactive"` for a cookie. Pass it to `SessionContext.authenticatedLayer` so the policy
kernel sees the same value the HTTP middleware would have provided.

It matters because a key and a cookie can resolve to the _same user_: a credential changes who
the request is, never what it may do. Without it, a key-bearing request reads as an interactive
session and a policy like "an API key may act as this user, but may not mint another API key"
silently stops holding at your edge.

### An API key resolves to its user, not to a session

A request carrying an API key (`x-api-key`, or the headers in `credentials.apiKeyHeaders`)
is resolved through the auth service's `GET /api-keys/current` (#730), not the session
read. The result is `{ session: None, user, apiKey, credentialClass: "machine" }`:
`apiKey` holds the key's public fields (id, name, permissions, expiry, `remaining`,
metadata, enabled, never its hash), and `user` is who it acts as. The key wins over a
cookie the request also carries: the cookie is not forwarded on that call, so it can never
answer for the key. A `401` (an unknown, disabled, expired or exhausted key, all answered
alike) is anonymous. Any other answer, the `404` of an auth service with no `ApiKeyService`
in its `services` included, fails `resolveAtEdge` closed and degrades
`resolveAtEdgeFailOpen` to anonymous; neither falls back to the cookie.

**Each resolution consumes one use of the key**: it is a verification, so `remaining`
decrements and `lastUsedAt` moves, once per request you resolve. A key with
`remaining: 100` serves 100 resolved requests. A non-consuming check is
[#645](https://github.com/thomasfosterau/effect-auth/issues/645). The key's own
`rateLimit` applies too: over it, the auth service answers `429` with `Retry-After`, which
reaches you as a `RemoteSessionError` with `status: 429`.

The endpoint checks no permissions; check the key's `permissions` through the policy
kernel. Configure the header once and pass it to both sides: `cookie.apiKeyHeaders` on the
auth service's `Http.make`, `credentials.apiKeyHeaders` on `RemoteSession.make`.

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
// POST /auth/sessions on the app's Worker: the browser posts a JSON:API
// `sessions` document, which the auth service answers at `POST /sessions`.
const signIn = (request: Request) => auth.relay(request, "/sessions");
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
import { SessionContext } from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";

const auth = Http.RemoteSession.make({ fetcher: env.AUTH });

const handle = (request: Request) =>
  Effect.gen(function* () {
    // Credential mutation: raw passthrough, Set-Cookie relayed.
    const url = new URL(request.url);
    // `/auth/sessions` on the app relays to the auth service's `/sessions`.
    if (url.pathname.startsWith("/auth/")) {
      return yield* auth.relay(request, url.pathname.slice("/auth".length) + url.search);
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

`effect_auth_session_resolutions_total` is tagged with the four outcomes, and the
`effect-auth.resolve-session` span carries the same value as `auth.outcome`:

- `skipped` climbing is the fast path working.
- `anonymous` climbing relative to `resolved` means stale credentials — check the session
  and cache lifetimes.
- `degraded` above zero means the auth service is faulting and users are silently signing
  out. Alert on it.

See `docs/OBSERVABILITY.md`.
