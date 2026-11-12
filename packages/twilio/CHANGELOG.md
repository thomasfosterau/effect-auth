# @thomasfosterau/effect-auth-twilio

## 0.1.2

### Patch Changes

- 9b63f86: **Security hardening (#631):** every adapter now depends on `@thomasfosterau/effect-auth` through a caret range (`^0.x.y`) instead of an exact pin. A consumer who upgrades the core within a minor (say, for a security patch) gets one copy of it, and no adapter keeps running a nested, unpatched core of its own. Under 0.x a caret range covers one minor, so the adapters are released with every core minor.
  
  **effect-auth-drizzle (#635):** the `drizzle-orm` peer range is bounded to the tested lines, `>=0.44.0 <0.46.0 || >=1.0.0-rc.5 <2`, and a new drizzle minor joins it once CI has run against it. The unused optional `@types/pg` peer is dropped.
- f49ee5d: Drop redundant default type arguments from the published declarations (`Redacted.Redacted<string>` is now written `Redacted.Redacted`, `Effect.Effect<A, E, never>` is `Effect.Effect<A, E>`, and so on); every type is unchanged (#503). Values that were stringified with `String(…)` are now converted explicitly: an OAuth profile id that is neither a string nor a number becomes `""` rather than `"[object Object]"`, the unsupported `id_token` algorithm error formats the header value (`"HS256"`), and a Twilio error body whose `code` or `message` is not a string is rendered as JSON.
- cc2bac6: Import Effect's helper modules (`Array`, `Option`, `Predicate`, `Record`, `Schema`, `String`) from their own entry points (`effect/Array`, …) rather than the `effect` barrel. The emitted `dist/` and `.d.ts` change their import specifiers only; no API or behaviour changes.
- Updated dependencies [8d7fe03]
- Updated dependencies [c80f91c]
- Updated dependencies [fd32f3f]
- Updated dependencies [eafa773]
- Updated dependencies [701eebc]
- Updated dependencies [fe036f1]
- Updated dependencies [de98263]
- Updated dependencies [3829977]
- Updated dependencies [4037bcf]
- Updated dependencies [9598882]
- Updated dependencies [dd8715a]
- Updated dependencies [ea7f4ea]
- Updated dependencies [325f231]
- Updated dependencies [4649a7b]
- Updated dependencies [d66403e]
- Updated dependencies [f49ee5d]
- Updated dependencies [cf1e3c9]
- Updated dependencies [7a651a3]
- Updated dependencies [cc2bac6]
- Updated dependencies [1e7d8f4]
- Updated dependencies [8b65156]
- Updated dependencies [2096e2a]
- Updated dependencies [efba66d]
- Updated dependencies [7d9579e]
- Updated dependencies [4037bcf]
- Updated dependencies [e2ff7f7]
- Updated dependencies [6d33e11]
- Updated dependencies [b386606]
- Updated dependencies [32ebf2d]
- Updated dependencies [a2624ea]
- Updated dependencies [211f399]
- Updated dependencies [93685f4]
- Updated dependencies [f43b53d]
- Updated dependencies [7f3ab3d]
- Updated dependencies [68faced]
- Updated dependencies [b96f201]
- Updated dependencies [c50edb9]
- Updated dependencies [63e45ac]
- Updated dependencies [e57ea3c]
- Updated dependencies [e1770e3]
- Updated dependencies [88cd0a1]
  - @thomasfosterau/effect-auth@0.3.0

## 0.1.1

### Patch Changes

- 3c140a6: Ship `CHANGELOG.md` in the published tarball, so the release notes can be read from `node_modules` (#545).
- Updated dependencies [55637b0]
- Updated dependencies [3c140a6]
- Updated dependencies [1cacf66]
- Updated dependencies [e52a95d]
- Updated dependencies [7f12561]
- Updated dependencies [47534bb]
- Updated dependencies [4c48eb4]
  - @thomasfosterau/effect-auth@0.2.0

## 0.1.0

### Minor Changes

- 51edf74: Built for Effect `4.1` (#501, #499).
  
  **Breaking peer ranges:** every package above now requires `effect ^4.1.0`, and the Alchemy packages require `alchemy` `2.0.0-beta.85` (effect-auth-alchemy-postgres also `@effect/sql-pg ^4.1.0`). Effect 4.1 removed the root `Crypto` module in favour of `effect/crypto`; alchemy beta.84 and earlier import that removed module, and beta.85 peers on `effect ^4.1.0` itself.
  
  **Breaking — randomness and digests come from `effect/crypto`.** Services that yielded `Crypto.Crypto` now yield `SecureRandom.SecureRandom`, and the ones that hash (OAuth PKCE, the OIDC provider, WebAuthn, `HaveIBeenPwnedPlugin`) also yield `Digest.Digest`. Every `static layer` still provides both through `PlatformCrypto.layer`, so only code that builds a service from its raw `make` changes: provide `SecureRandom.layerWebCrypto` and `Digest.layerWebCrypto` (or your own implementations) where it provided `Crypto.Crypto`. The OTP primitives that took a `Crypto` instance (`generateBase32Secret` and friends) take a `SecureRandom` service instead. `OAuthProvider.generateAuthorizationUrl`, `generatePKCE` and `SsoService.signIn` add `Digest.Digest` to their requirements.
  
  `layerMemoryKeyValueStore` implements `KeyValueStore.keys`, which Effect 4.1 added to the interface. effect-auth-alchemy-cloudflare's `D1Client` names its driver (`SqlClient.driver` is `"d1"`).
- 8d904a6: Built for Effect `4.0.0-rc.118`.
  
  Every package above requires `effect >=4.0.0-rc.118`. The published `dist/` imports rc.118's module paths (`effect/http-api`, `effect/http`, `effect/sql`, `effect/persistence`, `effect/process`, and so on), which earlier Effect releases don't have, so install `effect` and any `@effect/*` companion at rc.118 or later.
  
  - **An empty encryption secret is a configuration error.** The stock config providers read an empty environment variable as absent, which would silently turn encryption at rest off. So `JWT_ENCRYPT_PRIVATE_KEY_SECRET=""`, `OAUTH_ENCRYPT_TOKENS_SECRET=""` and `TWO_FACTOR_ENCRYPT_SECRET=""` fail `jwtServiceConfig`, `oauthServiceOptionsConfig` and `multiFactorConfig` at startup with a `ConfigError` naming the variable ("set but empty"). An **unset** variable means encryption is off. Unset or fix any such variable that your templating or secrets manager renders as `""`. Empty `JWT_ISSUER` and `TRUSTED_DEVICE_SECRET` fail as missing, and an empty `TRUSTED_DEVICE_MAX_AGE_MS` uses its default (#252).

### Patch Changes

- 89802ec: Built and tested against Effect `4.0.0`. The `effect` peer floor is unchanged (`>=4.0.0-rc.118`), so consumers still on `4.0.0-rc.118` keep working; `@effect/*` companions such as `@effect/sql-pg` should match whichever `effect` you install.
- dcffe28: Internal refactor for the Effect lint presets, with these observable edges:
  
  - `SessionService.createSession` / `setSessionAttributes`, `UserService.updateUserAttributes`, the `Username` sign-up and sign-in inputs and `ScimUserStore.create` take `Types.Attributes` (the readonly form of `Record<string, unknown>`); existing callers still type-check.
  - OAuth userinfo, OIDC discovery, JWKS and id_token segments that are not JSON objects now fail with `OAuthProviderError`, and a malformed JWKS document fails with `JwtError("Failed to fetch JWKS")`, instead of a defect or a confusing later error.
  - A CAPTCHA verification body of `null` now counts as a failed verification (`CaptchaError`) instead of a defect.
  - The sql stores decode their JSON columns with Schema, so a malformed stored value fails with the same `AuthError` instead of passing through unchecked; `readRbacPolicies` (drizzle) may return policies in a different order (decisions are unchanged).
  - Several thrown plain `Error`s (invalid header names, reserved principal types, malformed permissions, OTP URI and COSE key errors, session-cache config) are now tagged error classes with the same message; they are still `Error` instances.
  - resend and twilio wrap a failed non-2xx body read in a private tagged defect; saml reads non-object attribute bags as empty.
  - Effect handlers that became `Effect.fn` (auth middleware schemes, `requireScim`, JWT key rotation, decoy hashing) now emit a tracing span.
- 0def0c5: The `effect` peer range is now `^4.1.0` (was `>=4.1.0`), and effect-auth-alchemy-postgres's `@effect/sql-pg` peer is `^4.1.0` too. The floor is unchanged: the packages need `effect/crypto`, which first shipped in Effect 4.1. The caret form stops the range from claiming a future Effect 5 it was never tested against.
- 78dac5f: Widen the optional option fields to `?: T | undefined` so callers under `exactOptionalPropertyTypes` can forward their own optional values: `AuthClientOptions` (`fetch`, `headers`, `refresh`) and `RefreshOptions` (`intervalMs`, `onFocus`, `crossTab`) in the client, and the `render` / `baseUrl` / `fetch` fields of `ResendEmailSenderConfig` and `TwilioSmsSenderConfig`.
- 78dac5f: Build the Basic auth header with `btoa` instead of the Node `Buffer` global, so the sender runs on Workers without `nodejs_compat`.
- 02df078: Publish from the library tooling standard (#222). Every package now takes its dependency versions
  from the workspace's strict pnpm catalog and its published peer ranges from `catalog:peers`, so the
  ranges consumers see are declared once; the published ranges themselves are unchanged. Releases are
  published by `pnpm publish` through npm OIDC trusted publishing (provenance is left to npm, never forced). The packages' `build` / `test` / `typecheck` scripts moved into Vite+ tasks
  (`build`, `test:unit`, `check`), so the published manifests no longer carry them.
- Updated dependencies [84c9180]
- Updated dependencies [8ebcb4a]
- Updated dependencies [a1b01ae]
- Updated dependencies [b9a8437]
- Updated dependencies [68709bf]
- Updated dependencies [b2e7fd4]
- Updated dependencies [bbb24fe]
- Updated dependencies [106bb64]
- Updated dependencies [95f9ba6]
- Updated dependencies [ca3abfb]
- Updated dependencies [7f5206e]
- Updated dependencies [29d011c]
- Updated dependencies [afd57ae]
- Updated dependencies [20cde53]
- Updated dependencies [c1b0737]
- Updated dependencies [416fc73]
- Updated dependencies [2d26680]
- Updated dependencies [aa7b6e6]
- Updated dependencies [048e031]
- Updated dependencies [69b1d18]
- Updated dependencies [6d6bf02]
- Updated dependencies [61847b0]
- Updated dependencies [89802ec]
- Updated dependencies [51edf74]
- Updated dependencies [dcffe28]
- Updated dependencies [0def0c5]
- Updated dependencies [8d904a6]
- Updated dependencies [03bdfea]
- Updated dependencies [42d0f03]
- Updated dependencies [b165354]
- Updated dependencies [cc67083]
- Updated dependencies [fa438cf]
- Updated dependencies [5ab2078]
- Updated dependencies [9ff7ded]
- Updated dependencies [78dac5f]
- Updated dependencies [78dac5f]
- Updated dependencies [41ce19d]
- Updated dependencies [b1fbf57]
- Updated dependencies [ce56aeb]
- Updated dependencies [e03530e]
- Updated dependencies [4c70cd2]
- Updated dependencies [c1ba5f6]
- Updated dependencies [02df078]
- Updated dependencies [4e6293b]
- Updated dependencies [2484af6]
- Updated dependencies [6bee50c]
- Updated dependencies [90d7a79]
- Updated dependencies [d767491]
- Updated dependencies [7f5206e]
- Updated dependencies [e6c3a64]
- Updated dependencies [39654ad]
- Updated dependencies [f4f6606]
- Updated dependencies [624a9b5]
- Updated dependencies [373bb87]
- Updated dependencies [ec17f5d]
- Updated dependencies [8e5fc41]
- Updated dependencies [504ae0d]
- Updated dependencies [c99689b]
- Updated dependencies [1d47091]
- Updated dependencies [3de5d6a]
- Updated dependencies [a108a36]
- Updated dependencies [624f356]
- Updated dependencies [ef58828]
- Updated dependencies [00aa6e9]
- Updated dependencies [8213f5b]
- Updated dependencies [d2d8163]
- Updated dependencies [856d6fe]
- Updated dependencies [8235dad]
- Updated dependencies [5a48055]
- Updated dependencies [89749b6]
- Updated dependencies [213497b]
- Updated dependencies [5ab875a]
- Updated dependencies [f5bf843]
- Updated dependencies [8fce539]
- Updated dependencies [a517a32]
- Updated dependencies [5e1d6ce]
- Updated dependencies [311e9cb]
- Updated dependencies [a81a752]
- Updated dependencies [50a4084]
- Updated dependencies [36788a7]
- Updated dependencies [68e339a]
- Updated dependencies [2ba63b6]
- Updated dependencies [408285d]
- Updated dependencies [a3131b6]
- Updated dependencies [f87095c]
- Updated dependencies [2510ce4]
- Updated dependencies [45e863a]
- Updated dependencies [fed9d0c]
- Updated dependencies [03a3219]
- Updated dependencies [ca3abfb]
- Updated dependencies [9ff7ded]
- Updated dependencies [cbeda0d]
- Updated dependencies [8f78034]
- Updated dependencies [f7bafc0]
- Updated dependencies [c092987]
- Updated dependencies [ef0207d]
- Updated dependencies [bfa558e]
- Updated dependencies [3875062]
- Updated dependencies [1031ed5]
- Updated dependencies [5ab2078]
- Updated dependencies [9b1fe6f]
  - @thomasfosterau/effect-auth@0.1.0
