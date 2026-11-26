# Testing an app

The `@thomasfosterau/effect-auth/testing` subpath: fixture principals, guard assertions, in-memory stores and the store conformance suites.

`@thomasfosterau/effect-auth/testing` runs an Effect as a fixture principal in one call, so an app tests its own guards and policies without HTTP. It is not re-exported from the package root and does not load the HTTP tier.

```ts
import { Effect } from "effect";
import * as Testing from "@thomasfosterau/effect-auth/testing";

// As this library's User: the session context the required-auth middleware provides
// (CurrentSession, CurrentUser, MaybeCurrentSession, CurrentPrincipal, CurrentCredential).
await Effect.runPromise(program.pipe(Testing.runAs(ada)));
await Effect.runPromise(program.pipe(Testing.runAs(ada, { credentialClass: "machine" })));
// Anonymous: MaybeCurrentSession as none, and nothing else.
await Effect.runPromise(program.pipe(Testing.runAs(null)));

// As the app's own viewer (the service handed to Guard.make), plus the same session context.
await Effect.runPromise(
  requireModerator.pipe(Testing.runAsViewer(CurrentViewer, { id: "u-1", role: "moderator" })),
);
```

`layerAs` / `viewerLayerAs` return the same context as a `Layer`. The fixture session is minted from the `Clock` and expires 24 hours later.

`fixtureUsers()` gives the canonical trio (`admin`, `member`, `otherMember` for cross-author checks) with fixed UUID ids (`fixtureUserIds`), so apps whose tables reference `users.id` as `uuid` can insert them as real rows; `fixtureUser({ role, name, id })` makes one more with a fresh random UUID. Roles live in `attributes.role`, where `isAdmin` and `SessionContext.withRole` read them; ids, roles and timestamps are overridable.

The guard-negative helpers make the 401 / 403 / 404 mapping testable in one line. `expectGuarded` runs an operation anonymously, one rung below its minimum, at the minimum and (optionally) as the owner, and fails with `GuardExpectationError` listing every case that came out wrong:

```ts
await Effect.runPromise(
  Testing.expectGuarded(editPost, CurrentViewer, {
    ladder: Roles,
    min: Axes.moderate,
    viewerAt: (role) => ({ id: `u-${role}`, role }),
    owner: author, // held below the minimum: admitted by ownership alone
    // access: "read" expects the app's NotFound for both refusals instead of Unauthorized / Forbidden
  }),
);
```

`expectRefusesAnonymous`, `expectRefusesBelow` and `expectAllowsOwner` check one case each.

The store-contract conformance suites (`sessionStoreConformance`, `userStoreConformance`, `identifierStoreConformance`, `apiKeyStoreConformance`, `challengeStoreConformance` for the WebAuthn `ChallengeStore` (each challenge keeps its ceremony), `emailOtpStoreConformance` and `phoneOtpStoreConformance` (the OTP records and their failure budget), the per-user deletes account deletion calls (a case in `apiKeyStoreConformance` and `sessionStoreConformance`, and `oauthAccountStoreConformance`, `credentialStoreConformance`, `multiFactorStoreConformance`, `trustedDeviceStoreConformance`, `oidcTokenStoreConformance`, `oidcConsentStoreConformance`, `emailVerificationStoreConformance`, `passwordResetStoreConformance` and `accountManagementStoreConformance`), and `organizationStoreConformance` for the `OrganizationStore` records the HTTP API addresses by id: memberships, team memberships and custom roles) check a bring-your-own store against the semantics its contract states. Each suite is a list of cases, and each case is an `Effect` that fails with `ConformanceError` on a mismatch. The suites import no test runner. Register the cases with your own, as the [bring-your-own-store guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/byo-stores.md#7-check-your-store-against-the-contract) shows.

`memoryStores` is a layer of in-memory reference stores: sessions, users (one table shared by `UserStore`, `UserServiceStore`, `EmailPasswordStore`, `OAuthUserStore` and `OAuthAccountStore.hasPassword`), identifiers, TOTP and OTP second factors, passkeys (`memoryCredentialStore`), trusted devices, JWT keys, OAuth accounts, the four OIDC provider stores, pending account-management tokens (`memoryAccountManagementStore`), and the `KeyValueStore`-backed token stores over an in-memory `KeyValueStore`, which it also provides with its `KeyValueStoreKeys` listing so `purgeExpiredKV` runs against it. Each build starts empty. It lets a test or a demo build `SessionService`, `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService` or `OidcProviderService` with no database. Each store is also exported on its own (`memorySessionStore()`, `memoryUserStore(table)`, …). `memoryPhoneOtpStore()` is a `PhoneOtpStore` outside the layer, `memoryDeviceAuthorizationStore()` a `DeviceAuthorizationStore`, and `memoryOtpFailures()` the failure-budget half of either OTP store, to spread into one of your own.

`sessionServiceLayer({ users, config? })` provides `SessionService` (plus its `SessionStore` and `UserStore`) over a `UserStore` seeded with `users` (any iterable of `User`, e.g. `fixtureUser()`s), an empty session store and `Hooks.Default`. `config` defaults to `defaultSessionConfig`: a 24 hour `activePeriod` and a 1 hour `idlePeriod`. `apiKeyServiceLayer({ keys?, users?, config? })` provides `ApiKeyService` (plus its `ApiKeyStore`, `UserStore` and `RateLimitStore`) over a `memoryApiKeyStore` seeded with `keys`, a `UserStore` seeded with `users` (a key verifies only while its owner exists, so seed the owners of the keys a test verifies) and an in-memory `RateLimiter`, so `verifyWithRateLimit` works; `config` is `ApiKeyService.layer`'s own. Each build starts from fresh state, and `memoryApiKeyStore(keys?)` is also exported on its own (and part of `memoryStores`).

```ts
const program = Effect.gen(function* () {
  const sessions = yield* Auth.SessionService;
  const { token } = yield* sessions.createSession(ada.id);
  yield* sessions.validateSession(token);
  yield* sessions.invalidateSession(token); // validateSession now fails
});
await Effect.runPromise(
  program.pipe(Effect.provide(Testing.sessionServiceLayer({ users: [ada] }))),
);
```
