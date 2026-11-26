# Rate limiting and abuse protection

Rate limits, client addresses behind a proxy, the per-endpoint IP limit, account lockout, captcha and the send caps.

## Rate limiting

```typescript
import { Clock, Effect, Layer, Option, Result } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// An in-process store: one instance only. Use a shared store (`/sql`, Redis)
// when you run more than one, where `increment` must be one atomic statement.
const counts = new Map<string, Auth.RateLimit.RateLimitEntry>();
const rateLimitStore: typeof Auth.RateLimit.RateLimitStore.Service = {
  get: (key) => Effect.sync(() => Option.fromUndefinedOr(counts.get(key))),
  set: (key, entry, _ttl) => Effect.sync(() => void counts.set(key, entry)),
  // Count one request, opening a new window when there is none or it has ended.
  increment: (key, ttlSeconds) =>
    Effect.map(Clock.currentTimeMillis, (now) => {
      const entry = counts.get(key);
      const next =
        entry === undefined || now >= entry.resetAt
          ? { key, count: 1, resetAt: now + ttlSeconds * 1000 }
          : { ...entry, count: entry.count + 1 };
      counts.set(key, next);
      return next.count;
    }),
  delete: (key) => Effect.sync(() => void counts.delete(key)),
};

const RateLimiterLive = Auth.RateLimit.RateLimiter.layer().pipe(
  Layer.provide(Layer.succeed(Auth.RateLimit.RateLimitStore)(rateLimitStore)),
);

// Fails with `RateLimitError` once the key is over its limit.
const guardSignIn = (ip: string) =>
  Effect.gen(function* () {
    const limiter = yield* Auth.RateLimit.RateLimiter;
    yield* limiter.consumeToken(`sign-in:${ip}`, Auth.RateLimit.RateLimitPresets.login);
  });

// Presets: login 5 per 15 min · passwordReset 3 per hour · emailVerification
// 3 per 10 min · registration 3 per hour · oauth 10 per 5 min ·
// totpVerification 5 per 5 min. Or write your own:
const strict: Auth.RateLimit.RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60 * 1000, // 1 minute
  blockDurationMs: 5 * 60 * 1000, // then block for 5 minutes
};

// Five sign-ins from one address pass; the sixth is refused.
const attempts = await Effect.runPromise(
  Effect.forEach(Array.from({ length: 6 }), () => Effect.result(guardSignIn("192.0.2.1"))).pipe(
    Effect.provide(RateLimiterLive),
  ),
);
console.log(attempts.map(Result.isSuccess)); // [true, true, true, true, true, false]
export { strict };
```

### Client IP behind Cloudflare

Per-IP rate limits (and any hook of your own that reads `ClientIP`) need the visitor's address. Behind Cloudflare the socket address is Cloudflare's, so tell the handler which single header carries the visitor's address:

```typescript
import { Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";

// `services` is the layer graph from the sections above, with a `RateLimiter`
// (`RateLimiterLive` above) merged in.
const { handler } = Http.make({
  services: Layer.merge(services, RateLimiterLive),
  trustedProxy: Auth.ClientIP.ClientIP.cloudflare, // trusts CF-Connecting-IP alone
});

// Behind another edge, name its header instead: Auth.ClientIP.ClientIP.trustedHeader("x-real-ip").
```

This is correct only when the app is reachable solely through Cloudflare. A request that bypasses the edge can set `CF-Connecting-IP` to any value and choose its own key. Only that one header is read; `X-Forwarded-For` and the rest are ignored. A value is taken only when it is exactly one IPv4 or IPv6 address. A missing, empty or malformed value, or a comma-separated list, falls back to the socket address. The first entry of a list is never used. Behind Cloudflare that fallback is an edge address shared by many visitors, so it is a fallback, not a per-visitor key. Under `Http.make` serving Web `Request`s (Workers, for example) there is no socket address. So the IP limit, which is on unless `ipRateLimit: false`, needs a `trustedProxy`: without one no request has an address, the limit would refuse every request, and `Http.make` throws `ClientAddressConfigError` at build instead. When the header is unusable, the request resolves no address, and a request to a rate-limited endpoint is refused with `429`. It is never let through unlimited and never counted under a bucket shared with other callers. An accepted IPv6 address is canonicalised (RFC 5952), and an IPv4-mapped address becomes dotted IPv4, so one visitor has one key. The limits then key an IPv6 visitor on its /64, the block one customer is usually given, so rotating through the addresses of one block earns no fresh budget; `ipRateLimit: { ipv6PrefixLength }` (and the same option on `IPRateLimitPlugin`) changes the length, from 1 to 128, where `128` keys each address on its own.

Behind proxies of your own that append to `X-Forwarded-For`, pass `trustedProxy: { hopCount: n }` (the number of proxies in front of the app) or `trustedProxy: { trustedProxyCidrs: [...] }` (their address ranges). With `hopCount`, a request with a socket address (Node, Bun) treats the socket peer as the nearest proxy and takes the entry `n` positions from the right of `[...X-Forwarded-For, socket]`; a Web `Request`, which is what `Http.make` handles, has no socket address, so the client is the `n`-th header entry from the right, the one the outermost trusted proxy wrote. Entries to its left come from the client and never change the result, so prepending values to the header does not earn a fresh bucket. `trustedProxyCidrs` walks the same chain right to left and takes the first entry outside the ranges. In both forms an entry is used only when it is one IPv4 or IPv6 literal: when the selected entry, or one a trusted proxy wrote, is anything else, the request resolves no address and a rate-limited endpoint answers `429`. `hopCount: 0` under `Http.make` trusts no header entry and so resolves no address.

Without `trustedProxy`, forwarded headers are ignored and the socket address is used as-is. Under `Http.make` there is no socket address, so the IP limit without `trustedProxy` is a build error; `ipRateLimit: false` is the only way to serve without the limit. Dynamic client registration is keyed the same way, by the address this `trustedProxy` resolves: with registration enabled and no `trustedProxy`, `Http.make` fails at startup with `ClientAddressConfigError`.

**`IPRateLimitPlugin` refuses every request without a client address.** The plugin limits authentication attempts (every `beforeAuthenticate`: one `signin` bucket for the first-factor methods, a `second-factor` bucket for second-factor redemptions), sign-up and password-reset requests per address. A request it cannot key is refused with `RateLimitError` (`429` over HTTP), never let through: a request whose address cannot be resolved, and any hook run with no `ClientIP` service in scope, such as a direct `EmailPasswordService.signIn` call from server code. So under `Http.make` the plugin needs `trustedProxy`. When the `Hooks` in `services` include it and `make` has no `trustedProxy`, `make` throws `ClientAddressConfigError`: without a proxy every sign-in, sign-up and password-reset request would be refused with `429`, so the handler refuses to start instead.

The limits also need a `RateLimiter` in the handler's `services`: the IP limit (unless `ipRateLimit: false`), the dynamic registration limit and the device user-code limit (10 lookups and decisions per signed-in caller per 15 minutes). The device limit counts as configured whenever a `DeviceAuthorizationService` is in `services`; build it with `allowMissingRateLimiter: true` to run lookups and decisions without the limit instead. Without a `RateLimiter`, `Http.make` throws `RateLimiterConfigError`, so the app fails to start rather than run a limit as a no-op. `make` builds `services` once to check this and the handler reuses that build. Any other failure of the `services` build also makes `make` throw (the OIDC layer's `ClientAddressConfigError`, for example). Before it throws, `make` releases what the build acquired: a finalizer that does asynchronous work finishes after `make` has thrown, and a finalizer that fails is logged as an error. `make` waits for the build only. A fiber the build forks with `Effect.forkChild` is interrupted when the layer that forks it finishes building. Under `Layer.merge` or `Layer.mergeAll` that is the merged layer's own build, which can end ahead of the whole `services` build, so a fiber that has not started by then never runs. One forked into the layer's scope (`Effect.forkScoped`) keeps running after `make` returns and stops on `dispose`; one forked with `Effect.forkDetach` keeps running, and `dispose` does not stop it. Outside `Http.make`, the exported group layers (`Http.groupLayers`, or a group such as `Http.authGroupLayer` on its own) answer `429` when a configured limit finds no `RateLimiter` in scope.

### Per-endpoint IP limits: `ipRateLimit`, on by default

`Http.make` and `Http.makeAsync` limit every sensitive endpoint per client address before any auth logic runs: the `defaultEndpointRules`, which cover sign-in, sign-up, every send (OTP, magic link, password reset, email verification), every redemption, second-factor verification, the authenticated endpoints that hash a password or check a second factor (change password, MFA enrolment and removal, backup-code regeneration), the One Tap nonce, the device grant, SSO sign-in and its callbacks, `POST /oauth2/token` and `POST /register`. A request over a limit is answered `429` with `Retry-After`. The limit is on whenever `ipRateLimit` is omitted, so the handler refuses to start without what it needs: a `RateLimiter` in `services` (`RateLimiterConfigError`) and a client address source, `trustedProxy` (`ClientAddressConfigError`).

- `ipRateLimit: { rules: [...] }` replaces the defaults with your own rules. A rule names an endpoint by its path template as the OpenAPI document writes it (`"/sessions"`, `"/sso/saml/acs/{providerId}"`), or by a `RegExp` tested against that template, and optionally by its `methods`. The first rule that matches wins, so to change one endpoint's limit and keep the rest, put your rule ahead of `...Http.defaultEndpointRules` (below).
- `ipRateLimit: false` turns the limit off, and is the only way to. Use it when something in front of the handler (an edge rate limiter, a WAF rule) already limits per address, or in tests.
- `ipRateLimit: { onStoreError: "fail-open" }` serves a request unlimited, with a logged warning, when the `RateLimitStore` errors. The default, `"fail-closed"`, refuses it with a logged `500`, so a limiter outage, or one an attacker can induce, never removes the limits silently. This matches `AccountLockoutPlugin`'s `onStoreError`.

Rules are matched against the endpoint the router matched, never the raw request path. The router is case-insensitive and ignores trailing and duplicate slashes and percent-encoding, so `/Sessions/`, `//sessions` and `/%73essions` all reach `POST /sessions`, and all count in its bucket.

The defaults are judgement calls, and some deployments outgrow one. A confidential client's backend that calls `POST /oauth2/token` from one address, for example, can reach its 60 requests a minute. Override that endpoint and keep every other default:

```typescript
import * as Auth from "@thomasfosterau/effect-auth";
import * as Http from "@thomasfosterau/effect-auth/http";

// The token endpoint gets a limit of its own; the first matching rule wins,
// so every other endpoint keeps its default.
const { handler } = Http.make({
  services,
  trustedProxy: Auth.ClientIP.ClientIP.cloudflare,
  ipRateLimit: {
    rules: [
      { path: "/oauth2/token", methods: ["POST"], maxRequests: 600, windowMs: 60_000 },
      ...Http.defaultEndpointRules,
    ],
  },
});
```

```typescript
import * as Http from "@thomasfosterau/effect-auth/http";

// A handler behind an edge that already limits per address, and nothing else.
const { handler } = Http.make({ services, ipRateLimit: false });
```

## Abuse protection

`CaptchaPlugin` and `HaveIBeenPwnedPlugin` are hooks plugins composed with `composePlugins`. Both use `effect/http`'s `HttpClient`, so provide `FetchHttpClient.layer` (or a stub in tests).

```typescript
import { Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";

// Reject compromised passwords (k-anonymity range query) and require a captcha
// token on sign-up, password sign-in and every code or link send. Array order
// is execution order.
const plugins = Auth.Hooks.composePlugins([
  Auth.Password.HaveIBeenPwnedPlugin({ threshold: 1 }),
  Auth.Plugins.CaptchaPlugin({
    provider: "cloudflare-turnstile",
    secretKey: Redacted.make(process.env["TURNSTILE_SECRET"] ?? ""),
    endpoints: ["signUp", "signIn", "sendCode"], // the default
    // Optional: refuse a token solved on another site sharing the key.
    expectedHostname: "app.example.com",
  }),
]);

// The plugin stack requires `Hooks.Default` and an `HttpClient`.
export const HooksLive = plugins.pipe(
  Layer.provide(Auth.Hooks.Hooks.Default),
  Layer.provide(FetchHttpClient.layer),
);
```

The captcha token is read from the optional `captchaToken` field on the sign-up input, on the email and username sign-in inputs, and on the send options of `EmailOtpService.send`, `PhoneOtpService.send`, `MagicLinkService.send` and `PasswordResetService.requestPasswordReset` (over HTTP: the `SignUpPayload` schema, the `password` and `username` sign-in credentials, and the `POST /otp-challenges` and `POST /password-resets` attributes; in the client, `magicLink.send`, `emailOtp.send`, `phoneOtp.send` and `passwordResetRequest`).

`success: true` only says a token is genuine. `expectedHostname` (one or several) refuses a token solved on another site that shares the key, `expectedAction` (one for every endpoint, or one per endpoint) a token minted for another action, and `minScore` (0 to 1) a token whose `score` is lower or missing. reCAPTCHA v3 answers `success: true` for every genuine token, bots included, so `recaptchaVersion: 3` without `minScore` fails at layer build with `CaptchaConfigError`, and a token that carries a `score` no `minScore` judges is refused. The client address goes to the provider as `remoteip` when the request has one. Have I Been Pwned checks every new password (sign-up, reset, change and set, through `beforeSignUp`, `beforeResetPassword`, `beforeChangePassword` and `beforeSetPassword`) and asks for padded responses. It fails open by default (`failClosed: false`) when the API cannot answer: a network error, a non-2xx status such as a `429`, or no answer within `timeout` (default 5 seconds).

### The `beforeAuthenticate` hook

Every flow that verifies a credential fires `beforeAuthenticate` before it checks the credential and before it spends or creates anything: email and password, username and password, email OTP (sign-in, and `EmailOtpService.check` for every purpose), phone OTP, magic link, passkey (`WebAuthnService.verifyAuthentication`, which now needs `Hooks`), and second-factor redemption (TOTP, backup code, OTP second factor). Its input is `{ method, identifier?: { type, value }, userId?, captchaToken? }`: the method (`AuthenticationMethod`), the handle the attempt names (normalized; a second-factor redemption names its challenge's user and a passkey its credential's, `type: "user"`), the user the handle resolves to when one does, and the captcha token for the two password methods. A plugin denies the attempt by failing. The flows read nothing back; `beforeSignIn` stays the place to rewrite an email and password sign-in's input (`NormalizeEmailPlugin`).

An attempt that names no account is **unkeyed**: an unknown or expired second-factor challenge, magic-link token or passkey challenge, or an unknown passkey credential, fires the hook with no `identifier` and no `userId`, then fails. `authenticationSubject` answers `undefined` for it, so the per-account plugins let it through, while `IPRateLimitPlugin` draws it from the address's bucket like any other attempt, so guessing tokens spends the guesser's budget.

`AccountLockoutPlugin`, `CaptchaPlugin`, `RateLimitPlugin` and `IPRateLimitPlugin` guard it:

- **`AccountLockoutPlugin`** counts every password and second-factor attempt per account (`authenticationSubject`: `user:<id>` for a resolved handle, so an account's email, username and phone share one count, else the handle itself, so an unknown handle locks like a known one) and locks after `maxAttempts` for `lockoutDurationMs`. It counts each attempt atomically before the credential is checked and acts on the count the store returns, so a burst of parallel attempts gets `maxAttempts` guesses, not one per request. The counts clear only when the user earns a session (`afterCreateSession`): never on a correct password that earned only a second-factor challenge, and never on an admin impersonation (`isImpersonationSession`). Second-factor redemptions have a per-user count of their own (`maxSecondFactorAttempts`, default 5) that runs across challenges, so fresh challenges buy no fresh guesses; only someone past the first factor can drive it. Anyone who knows a handle can lock the password methods for `lockoutDurationMs`: pair it with `IPRateLimitPlugin` or a captcha.
- **Magic link and one-time codes are exempt from the lock** (`isPossessionMethod`): an email or phone OTP and a magic link are neither refused by it nor counted toward it, so a locked-out owner can still recover by proving they hold the address, and a session that proof earns clears the lock. The exemption opens no brute-force path: a code accepts `maxAttempts` wrong guesses, the address's wrong codes put its sends into the backoff below, which no resend resets, a magic-link token is 256 random bits and an unknown one is an unkeyed attempt the per-IP limit counts, and `RateLimitPlugin` and `IPRateLimitPlugin` count every attempt.
- **Passkeys are exempt from the lock too**: a WebAuthn assertion is a signature nobody can guess, and a credential id is not secret, so counting passkey attempts would let anyone who holds one lock the account. Passkey verification still counts against `IPRateLimitPlugin` and `RateLimitPlugin`.
- **`CaptchaPlugin`** with the `"signIn"` endpoint verifies the token on the two password methods; verifying a code or a link, a passkey and a second factor carry no token.
- **`RateLimitPlugin`** draws first-factor attempts from one bucket per account (`RateLimitPresets.login`) and second-factor redemptions from another (`RateLimitPresets.totpVerification`).

### The `beforeSendCode` hook

Every send of a one-time code or a magic link (`EmailOtpService.send`, `PhoneOtpService.send`, `MagicLinkService.send`) fires `beforeSendCode` with `{ method, purpose, address, captchaToken? }` before it looks the address up, stores or sends anything, so it answers alike for an address with and without an account. A plugin refuses the send by failing; over HTTP `POST /otp-challenges` answers `400` for a `CaptchaError`. `CaptchaPlugin`'s `"sendCode"` endpoint (on by default) guards it: a send is the step that costs money, so it is where the captcha guards the passwordless flows.

### One-time code guessing

Email and phone OTP sign-in (`EmailOtpService`, `PhoneOtpService`) bound the wrong codes an address accepts across resends, not only per code. `maxAttempts` (default 3) limits one code, and every attempt is counted atomically before the code is compared, so a burst of parallel guesses gets `maxAttempts` comparisons, not one per request (the same holds for `OtpSecondFactorService`'s `maxAttempts` and `MultiFactorService`'s `maxFailedAttempts`); every wrong code is also counted against the address and purpose in the store's failure budget, which a resend, an expiry or the attempt limit never resets. Once the count reaches `backoff.freeFailures` (default 5), `send` answers `ResendTooSoonError` (`429` with `Retry-After` over HTTP) until `backoff.baseDelay` (default one minute), doubled for each further wrong code and capped at `backoff.maxDelay` (default one day), has passed since the latest one. A successful verification resets the count.

There is no lockout: once the delay has passed a send goes through, so an attacker can slow an address's owner down but never lock them out. Under the defaults, an attacker gets 18 guesses at a six-digit code in the first day and 3 a day after that. `resendCooldown` (default 60 s; `0` turns it off) still spaces sends of an outstanding code. The magic link (`MagicLinkConfig.resendCooldown`) and the email-verification resend have the same 60 s default. Both apply alike to an address with and without an account, so neither reveals which addresses are registered. The code length stays 6 digits by default (`otpLength`).

### Per-recipient send caps

The IP limit bounds what one client sends; the per-recipient cap bounds what one address or phone number receives from all of them, against email bombing and SMS toll fraud. `EmailOtpService.send`, `PhoneOtpService.send`, `MagicLinkService.send`, `PasswordResetService.requestPasswordReset` and `EmailVerificationService.resendVerification` each allow 5 sends per recipient and purpose an hour by default, on top of the cooldowns. `recipientSendLimit: { max, windowMs }` on the service's config changes that, and `false` turns it off. A send past it fails with `RateLimitError` (`429` over HTTP). The cap counts a request whether or not the address has an account, so the refusal is the same for both; `POST /email-verifications` and the `AuthLifecycleService` resends answer a capped resend like any other. The counts live in the `RateLimitStore`, which these services now need in their context (`./sql`, `layerKVSingleProcess` and `Testing.memoryStores` provide one; `layerKV` does not), keyed on the SHA-256 digest of the normalized address, never the address itself. Anyone can spend an address's cap, which holds its owner's sends back until the window ends: keep `max` above what one person needs in `windowMs`.
