# A SvelteKit server adapter, as a server binding

[`docs/better-auth-parity.md` §2.4](../better-auth-parity.md#24-deliberate-deferrals-door-open-not-closed)
deferred framework adapters: "the Web-standard handler plus `HttpApiMiddleware` already mount
everywhere … framework support is a docs/examples problem". That argument covers _mounting_ the
handler. #200 found that it doesn't cover what an app needs _around_ the mount point:

- Three applications on one shape (SvelteKit on Cloudflare Workers, Effect v4, auth in its own
  internal Worker) each wrote about 170 lines of `hooks.server.ts`. Every copy resolved the session
  before `load`, chose a fail-open policy, and recorded the outcome.
- The order inside that hook matters. Cache-control has to run after authentication so that it
  sees the resolved user and forces `private, no-store`. A hook that gets the order wrong caches an
  admin-rendered page and serves it to anonymous visitors.
- Each app mapped sign-in failures into its form's own shape. A `401` became "invalid email or
  password", and a `429` mapped to nothing, so a throttled sign-in read as "the form did nothing".
- All three carried their own `safeRedirect(target, fallback)`.

A docs page can describe these. It cannot keep three copies from drifting, and the failures above
come from drift.

## Decision

The deferral is reversed for SvelteKit (the owner's decision on #200, 2026-10-09).

- **A new server binding, `@thomasfosterau/effect-auth-sveltekit`** (`packages/sveltekit`). It
  depends on the core only, through its session-resolution seam (`SessionResolution`, which already
  reads a SvelteKit cookie jar). It is typed against the parts of SvelteKit's `RequestEvent` it uses,
  and it takes kit's `redirect` and `fail` as arguments, so it carries no dependency on
  `@sveltejs/kit`. A kit release that changes those shapes shows up in the consumer's type-check. It
  provides:
  - a `handle` hook that resolves the session once, before `load`, with `SessionResolution`'s
    cookieless skip and an explicit fail-open or fail-closed choice. It puts the result on
    `event.locals`, and its cache-control step runs after authentication: a response rendered
    for a signed-in viewer is forced to `private, no-store`;
  - form-action helpers for the credential flows. They relay `Set-Cookie` onto the redirect,
    redirect only to a validated target, and map `401` and `429` into distinguishable failures
    of the form's shape.
- **`safeRedirect(target, fallback)` lives in core**, not in the adapter. It isn't
  framework-specific, and the OAuth, SSO and OIDC flows need it too.
- Other frameworks stay deferred. §2.4's reasoning still holds for them until an application
  shows the same drift.

## Consequences

- `AGENTS.md` gains a **server binding** archetype, with its own fallow zone (`server-bindings`, which
  may import `core`). The existing framework bindings (`react`, `svelte`, `solid`, `vue`) are
  client-side, over `client`. This one is server-side, over the core.
- The SvelteKit guide (`docs/guides/sveltekit.md`) documents the hook and the helpers, and the
  Better-Auth-on-Workers sections of `docs/guides/better-auth-migration.md` point to it.
- §2.4 of the parity document records the reversal and links here.
