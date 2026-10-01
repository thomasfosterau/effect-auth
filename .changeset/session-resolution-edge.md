---
"@thomasfosterau/effect-auth": minor
---

Session resolution at an application's own edge: credential-presence predicates over a raw
request, a stated fault posture, and one auth-outcome signal (#186).

An app that resolves the session before any effect-auth handler runs — a SvelteKit
`hooks.server.ts`, a Worker calling an auth service binding — had to answer three questions the
library gave it no help with, and answered all three by hand.

**Does this request carry a credential at all?** New `SessionResolution.detectCredential` /
`hasSessionCredential` answer it from a plain `Headers`, a header record, or a cookie jar, with
no Effect runtime involved. The cookie names they look for come from the new `SessionCookies`
module, which `http/HttpServer.ts`'s `resolveCookieConfig` now also calls — so the effective
name, including the computed `__Host-` prefix, has exactly one derivation. Changing `name`,
`secure` or `hostPrefix` cannot desynchronise an app's fast-path predicate from what the
middleware reads, because there is nothing left to keep in sync. `extractApiKey` and
`extractSessionToken` back both the predicate and the credential read, so a gate and the thing
behind it cannot disagree about what a credential is.

**What happens when resolution faults?** `SessionResolution.resolve` fails closed;
`resolveFailOpen` degrades the request to anonymous and reports it. Neither is a default.
`resolveFailOpen` takes a _mandatory_ `onDegraded` callback — fail-open's failure mode is
silence, and there is deliberately no overload that omits it. It catches defects as well as
typed failures, since an unreachable binding usually arrives as a thrown `TypeError`.
`docs/ARCHITECTURE.md` ("Fail-open vs fail-closed session resolution") states the precondition that makes fail-open safe (anonymous must be the
lower-privilege outcome) and the shapes where it is an escalation instead.

**What just happened?** One `AuthOutcome` — `skipped` | `resolved` | `anonymous` | `degraded` —
derived in one place and reported by the resolver itself, on a new
`effect_auth_session_resolutions_total` counter and as an `auth.outcome` attribute on the
`effect-auth.resolve-session` span. Callers do not derive it and do not wire it up. The four
states stay distinct: `anonymous` paid the round trip that `skipped` did not, so folding them
corrupts the duration bucket, and `degraded` means something broke rather than that nobody was
signed in.
