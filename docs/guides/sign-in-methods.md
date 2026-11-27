# Sign-in methods

Passwords, multi-factor, passkeys, OAuth, managed users, Cloudflare Access, email verification and message delivery.

## Passwords

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

const program = Effect.gen(function* () {
  const hasher = yield* Auth.Password.PasswordHasher;
  const hashed = yield* hasher.hash("correct horse battery staple");
  return yield* hasher.verify("correct horse battery staple", hashed.hash);
});

// The default hasher is PBKDF2-SHA256 with 600,000 iterations; pass
// `{ iterations }` to `layer` to change the count.
console.log(await Effect.runPromise(Effect.provide(program, Auth.Password.PasswordHasher.layer())));
```

## Multi-factor authentication

TOTP (RFC 6238):

```typescript
import { Effect, Option } from "effect";
import { SecureRandom } from "effect/crypto";
import * as Auth from "@thomasfosterau/effect-auth";

// The OTP primitives take Effect's `SecureRandom` service directly;
// `SecureRandom.layerWebCrypto` draws from the platform's Web Crypto API.
const program = Effect.gen(function* () {
  const crypto = yield* SecureRandom.SecureRandom;
  // 20 bytes = 160 bits, the RFC 4226 recommendation.
  const secret = yield* Auth.MultiFactor.generateBase32Secret(crypto, 20);

  // Encode this URI as a QR code for the user's authenticator app.
  const uri = Auth.MultiFactor.generateOtpUri({
    type: "totp",
    label: "user@example.com",
    issuer: "MyApp",
    secret,
  });

  // Later, verify the code the user typed (accepts ±1 time step by default).
  // The result is the matched time step, or `None` for a wrong code: persist
  // it and reject a later code with the same or a lower step (replay).
  const code = yield* Auth.MultiFactor.generateTotp(secret);
  const step = yield* Auth.MultiFactor.verifyTotp(code, secret);
  return { uri, valid: Option.isSome(step) };
});

console.log(await Effect.runPromise(Effect.provide(program, SecureRandom.layerWebCrypto)));
```

HOTP (RFC 4226) and custom configuration:

```typescript
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// HOTP is counter-based: store the counter per user and advance it only after
// a successful verification.
const verifyHotpCode = (code: string, secret: string, counter: number) =>
  Effect.gen(function* () {
    const valid = yield* Auth.MultiFactor.verifyHotp(code, secret, counter);
    return { valid, nextCounter: valid ? counter + 1 : counter };
  });

// Both TOTP and HOTP take an optional config; pass the same one to generate and verify.
const totpConfig: Auth.MultiFactor.TotpConfig = {
  period: 60, // seconds per step (default 30)
  digits: 8, // default 6
  algorithm: "sha256", // default "sha1"
  window: 2, // accept ±2 steps (default 1)
};
const hotpConfig: Auth.MultiFactor.HotpConfig = { digits: 8, algorithm: "sha512" };

const example = (secret: string) =>
  Effect.gen(function* () {
    const totp = yield* Auth.MultiFactor.generateTotp(secret, totpConfig);
    const step = yield* Auth.MultiFactor.verifyTotp(totp, secret, totpConfig);
    const hotp = yield* Auth.MultiFactor.generateHotp(secret, 0, hotpConfig);
    const hotpValid = yield* Auth.MultiFactor.verifyHotp(hotp, secret, 0, hotpConfig);
    const counter = yield* verifyHotpCode(
      yield* Auth.MultiFactor.generateHotp(secret, 0),
      secret,
      0,
    );
    return { step, hotpValid, counter };
  });

console.log(await Effect.runPromise(example("JBSWY3DPEHPK3PXP")));
```

## Passkeys (WebAuthn)

```typescript
import { Effect, Layer, Option } from "effect";
import { Base64 } from "effect/encoding";
import * as Auth from "@thomasfosterau/effect-auth";

// Challenges are short-lived (an in-memory or Redis store is fine); credentials
// are persistent. Lookups return `Option.none()` on a miss.
// Challenges are raw bytes; key them by their base64 form.
const key = (challenge: Uint8Array) => Base64.encode(challenge);
const challenges = new Map<string, Auth.MultiFactor.WebAuthnChallenge>();
const challengeStore: typeof Auth.MultiFactor.ChallengeStore.Service = {
  create: (c) => Effect.sync(() => (challenges.set(key(c.challenge), c), c)),
  get: (challenge) => Effect.sync(() => Option.fromUndefinedOr(challenges.get(key(challenge)))),
  delete: (challenge) => Effect.sync(() => void challenges.delete(key(challenge))),
};
const credentials = new Map<string, Auth.MultiFactor.WebAuthnCredential>();
const credentialStore: typeof Auth.MultiFactor.CredentialStore.Service = {
  create: (c) => Effect.sync(() => (credentials.set(c.id, c), c)),
  get: (id) => Effect.sync(() => Option.fromUndefinedOr(credentials.get(id))),
  // Resolves by the raw credential id, for the discoverable (usernameless) login path.
  getByCredentialId: (credentialId) =>
    Effect.sync(() => Option.fromUndefinedOr(credentials.get(credentialId))),
  update: (c) => Effect.sync(() => (credentials.set(c.id, c), c)),
  delete: (id) => Effect.sync(() => void credentials.delete(id)),
  listByUserId: (userId) =>
    Effect.sync(() => [...credentials.values()].filter((c) => c.userId === userId)),
  // Deleting the user deletes their passkeys.
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, c] of credentials) if (c.userId === userId) credentials.delete(id);
    }),
};

const WebAuthnLive = Auth.MultiFactor.WebAuthnService.layer({
  relyingPartyId: "example.com",
  relyingPartyName: "Example Corp",
  expectedOrigin: "https://example.com",
  challengeExpiresIn: 5 * 60 * 1000, // 5 minutes
}).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.MultiFactor.ChallengeStore)(challengeStore),
      Layer.succeed(Auth.MultiFactor.CredentialStore)(credentialStore),
      // Passkey sign-in fires `beforeAuthenticate`; no plugins here.
      Auth.Hooks.Hooks.Default,
    ),
  ),
);

// Registration: send `challenge` to the browser, which calls
// `navigator.credentials.create()` and returns the attestation.
const beginRegistration = Effect.gen(function* () {
  const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
  return yield* webAuthn.generateRegistrationChallenge({
    id: "user-123",
    name: "user@example.com",
    displayName: "User Name",
  });
});
// `userId` is the signed-in user, from the session, never from the request: the
// challenge must be a registration challenge issued to that same user, so an
// authentication challenge, or another user's, is refused.
const finishRegistration = (
  userId: string,
  challenge: Uint8Array,
  response: Auth.MultiFactor.RegistrationResponse,
) =>
  Effect.gen(function* () {
    const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
    const { credential } = yield* webAuthn.verifyRegistration(userId, challenge, response);
    return credential; // stored under the attested credential id, usable for sign-in
  });

// Authentication: the browser signs the challenge with `navigator.credentials.get()`.
const finishAuthentication = (
  challenge: Uint8Array,
  response: Auth.MultiFactor.AuthenticationResponse,
) =>
  Effect.gen(function* () {
    const webAuthn = yield* Auth.MultiFactor.WebAuthnService;
    // `userVerified` is the UV flag (a PIN or biometric, not only presence);
    // `backupEligible` / `backupState` say whether this is a synced passkey.
    const { credential, userVerified } = yield* webAuthn.verifyAuthentication(challenge, response);
    return { userId: credential.userId, userVerified }; // create a session for this user
  });

const { challenge } = await Effect.runPromise(Effect.provide(beginRegistration, WebAuthnLive));
export { challenge, finishRegistration, finishAuthentication };
```

What the service enforces:

- **A challenge is bound to its ceremony.** Each stored `WebAuthnChallenge` carries `ceremony: "registration" | "authentication"`; `verifyRegistration` refuses an authentication challenge and `verifyAuthentication` a registration one, leaving it in place. A registration challenge is also bound to the user it was issued to, which must be the `userId` passed to `verifyRegistration`. A `ChallengeStore` must persist the ceremony; a stored challenge without a known one reads as `null` (`Testing.challengeStoreConformance` pins the contract).
- **`userVerification: "required"` is enforced**, not only advertised: a registration or assertion without the UV flag is refused. Under `"preferred"` (the default) or `"discouraged"`, both results report `userVerified`, with the backup flags `backupEligible` and `backupState`, for the host to act on (for example, to require a second factor when `userVerified` is `false`).
- **The backup flags and AAGUID are stored.** A registered `WebAuthnCredential` carries `backupEligible` (BE), `backupState` (BS) and the authenticator's `aaguid` (a lowercase hyphenated UUID; under `none` attestation it is the authenticator's claim). BE never changes for a credential (WebAuthn Level 3 §6.1.3), so an assertion reporting another BE is refused; each sign-in records BS. A credential stored before the flags were has them absent, and its next sign-in records them. A `CredentialStore` must persist all three (`Testing.credentialStoreConformance` pins it).
- **Only `none` attestation is supported.** The attestation object is parsed for the credential, but its attestation statement (`packed`, `tpm`, `fido-u2f`, …) is never verified, so a registration says nothing about the authenticator's make or model. The registration options always carry `attestation: "none"`, and a `WebAuthnConfig` asking for `"indirect"`, `"direct"` or `"enterprise"` makes the layer build die with `WebAuthnConfigError`.
- **The stored credential is the attested one.** Its id is the credential id inside the attestation, which must equal `response.credentialId`; an id already registered, to any user, is refused rather than overwritten. ES256 keys must be on P-256, and a `clientDataJSON` with `crossOrigin: true` is refused.

## OAuth 2.0 social login

```typescript
import { Effect, Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";

const providers = {
  google: Auth.OAuth.GoogleProvider({
    clientId: process.env["GOOGLE_CLIENT_ID"] ?? "",
    clientSecret: Redacted.make(process.env["GOOGLE_CLIENT_SECRET"] ?? ""),
    redirectUri: "https://example.com/auth/google/callback",
  }),
  github: Auth.OAuth.GitHubProvider({
    clientId: process.env["GITHUB_CLIENT_ID"] ?? "",
    clientSecret: Redacted.make(process.env["GITHUB_CLIENT_SECRET"] ?? ""),
    redirectUri: "https://example.com/auth/github/callback",
  }),
};

// Requires OAuthStateStore (temporary, about 10 minutes), OAuthAccountStore,
// OAuthUserStore, IdentifierStore, UserStore, EmailPasswordStore (to clear an
// unproven sign-up's password), SessionService and RootSecret (which seals the
// provider tokens and derives the PKCE verifier); a storage adapter such as
// @thomasfosterau/effect-auth/sql provides the stores. The token, userinfo and
// JWKS requests go through effect/http's HttpClient.
const OAuthLive = Auth.OAuth.OAuthService.layer(providers).pipe(
  Layer.provide(FetchHttpClient.layer),
);

// Step 1: redirect the user to the provider (PKCE and `state` are handled for you).
const begin = Effect.gen(function* () {
  const oauth = yield* Auth.OAuth.OAuthService;
  const { url } = yield* oauth.generateAuthorizationUrl("google", {
    scopes: ["email", "profile"],
    returnTo: "/dashboard",
  });
  return url;
});

// Step 2: the provider redirects back with `code` and `state`. This resolves or
// creates the user, links the account and issues a session. A first sign-in
// whose email matches an existing user auto-links only when the provider
// verified the address; an unverified local address is proven first,
// clearing the earlier sign-up's password and sessions. Otherwise it
// fails with `EmailInUseError`.
const callback = (state: string, code: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    const { user, token } = yield* oauth.signInWithCallback(state, code);
    return { userId: user.id, sessionToken: token };
  });

// Link another provider to a signed-in user, or refresh a stored access token.
const link = (userId: string, code: string, state: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    return yield* oauth.linkAccount(userId, "github", code, state);
  });
const refresh = (userId: string) =>
  Effect.gen(function* () {
    const oauth = yield* Auth.OAuth.OAuthService;
    return yield* oauth.refreshAccessToken(userId, "google");
  });

export { OAuthLive, begin, callback, link, refresh };
```

**What the presets read.**

- Google's verification arrives as `verified_email` and is read as `email_verified`.
- Microsoft's address is Graph's `mail`, or else the sign-in name when that is an address. Graph doesn't say whether it is verified, so a Microsoft sign-in never auto-links.
- GitHub takes the primary address from `/user/emails`, private ones included, with GitHub's verification.
- Apple's `email_verified` may arrive as the string `"true"`, which is read as `true`.

A profile with no account id fails with `OAuthProviderError`; it never becomes an account under an empty id.

An `id_token` must:

- carry a numeric `exp`;
- match the configured `issuer`, which a provider with `getUserInfoFromIdToken` must set;
- be verified with a key of the header's algorithm (an `RSA` key for RS256, `EC` P-256 for ES256, `OKP` Ed25519 for EdDSA).

**Link-only providers.** `TwitterProvider`, `RedditProvider`, `TikTokProvider` and `RobloxProvider` return no email address, so they can't create an account or sign in someone new: `signInWithCallback` fails with `OAuthMissingEmailError`. Link one to the signed-in user with `linkAccount`. After that, it signs that user in.
**Bind the `state` to the browser.** `OAuthService` has no HTTP endpoints, so `begin` and `callback` above are yours to serve: set the `state` in a short-lived `HttpOnly` cookie when you redirect to the provider, and refuse a callback whose `state` is not the one in the cookie. Without it, an attacker can start a sign-in, finish the provider's leg as themselves and have a victim's browser complete the callback, signing the victim in to the attacker's account (login CSRF). The SSO endpoints do this for you: `POST /sso-authorizations` sets a pre-login cookie (`<name>_sso_state`, `SameSite=None; Secure`, ten minutes) that `POST /sso/callback` and the SAML ACS require.

**The callback `state` is single-use**. `handleCallback`, `signInWithCallback`, `linkAccount` and the OIDC SSO callback (`SsoService.handleCallback`, `POST /sso/callback`) spend it with `OAuthStateStore.consume`, an atomic get-and-delete, before they exchange the code. A replayed callback fails with `OAuthStateNotFoundError` (an `SsoError` for SSO, `400` over HTTP), whether the first use succeeded or failed, and of two concurrent callbacks carrying the same state only one gets past it. A store you write yourself must implement `consume` as one atomic operation (`DELETE … RETURNING`, a compare-and-swap, Redis `GETDEL`); `/sql`'s store is one `DELETE … RETURNING`. `OAuthStateStoreKV` serializes `consume` within its process only, since a `KeyValueStore` has no get-and-delete: behind several instances sharing one backend, provide a `KeyValueStoreTake` ([`KeyValueStore` stores](./storage.md#keyvaluestore-stores)) or use `/sql`. The SAML `RelayState` is single-use the same way: it lives only on its `AuthnRequest` record, which `SamlReplayStore.consume` spends.

**Every single-use token is spent atomically**. Magic links, password-reset and email-verification tokens, one-time tokens, OIDC authorization codes and consent requests, OIDC refresh tokens (on rotation) and pending second-factor challenges are each spent with their store's `consume`, an atomic get-and-delete, so of concurrent redemptions of one token only one succeeds: one session, one password write, one token set, no forked refresh family. A TOTP code and a backup code are spent with `MultiFactorStore.useTotpCounter` / `useBackupCode`, compare-and-sets that accept each time step and each code once across every challenge and never recreate an enrolment a concurrent `disable` removed. `consume` is a required member of `EmailVerificationStore`, `PasswordResetStore`, `MagicLinkStore`, `OneTimeTokenStore`, `OidcCodeStore`, `OidcTokenStore` and `PendingMultiFactorStore`, and the two spends of `MultiFactorStore`; a store you write must make each one indivisible ([bring your own store](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/byo-stores.md#2-atomicity-what-must-be-a-single-indivisible-operation)). The `KeyValueStore` stores serialize `consume` within their process only, unless a `KeyValueStoreTake` is provided ([`KeyValueStore` stores](./storage.md#keyvaluestore-stores)). `Testing.magicLinkStoreConformance`, `oneTimeTokenStoreConformance`, `oidcCodeStoreConformance` and the email-verification, password-reset, OIDC-token, pending-multi-factor and multi-factor suites each run a concurrent-redemption case.

Account linking on `signInWithCallback`: when a provider identity is new and its email matches an existing user, the account is linked to that user only if the provider reports `email_verified: true` and auto-linking applies to the provider (`autoLinkByVerifiedEmail`, default `true`, or the provider is in `trustedProviders`, which auto-link even with `autoLinkByVerifiedEmail: false`). Every other match (an unverified provider email, auto-linking off for the provider) fails with `EmailInUseError` and changes nothing. When the local email identifier is still unverified, someone may have signed up with the address and a password before its holder did, so the provider's verification is the address's first proof, as in Google One Tap and SSO: the account's password and other credentials are cleared and its sessions revoked, the address is marked verified, and then the provider is linked and the holder's session issued. A provider that does not report the email verified never takes over an address.

## Managed users: what SSO and SCIM may reach

An organization manages a user when one of its connections created the user (SSO and SCIM stamp the users they create with `Auth.ManagedUser.PROVISIONED_BY_ATTRIBUTE`), or when the user's primary email is on one of the organization's verified domain claims. `Auth.ManagedUser.isManagedUser(stores, organizationId, user)` answers it; `isManagedBy` is the same rule over data you already hold.

An SSO connection signs in only an address its organization manages: one on the organization's verified domains, or one held by a user the organization provisioned. Anything else fails with `SsoError` before any account is created, proved or signed in, so a tenant's IdP can't assert its way into another tenant's user or the platform admin. A connection registered without an organization is bound to its own `domain` and to the users it created. Domain claims are only as good as their proof, which is DNS or the operator's attestation (`POST /admin/organization-domains`), never a tenant's say-so. An OIDC profile must carry `email_verified: true`; for an IdP that never sends the claim, register the connection with `requireEmailVerified: false` (an explicit `false` is still refused).

A SCIM connection reads every member of its organization but writes only to the users it manages, and claims or unclaims only addresses on the verified domains (`400 invalidValue` otherwise). For any other member only `active` changes (`400 mutability` for the rest), and `active: false` deactivates the membership alone, never the account. The [SCIM guide](https://github.com/thomasfosterau/effect-auth/blob/trunk/docs/guides/scim.md#5-managed-users) has the details.

## Cloudflare Access

An application behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/) can trust the identity Access signs in at the edge instead of running a sign-in of its own. `CloudflareAccess.CloudflareAccessVerifier` verifies the application token Access forwards: RS256 only, a `kid` naming a key from the team's own key set (`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`, never a URL the token names), `iss` equal to the team domain, `aud` containing the application's AUD tag, `exp` required, and `exp` / `nbf` within a clock tolerance (60 s by default). The key set is cached in memory for an hour and refetched early when a token names a `kid` it does not hold (key rotation), at most once every 30 seconds, so a forged `kid` cannot turn each request into a fetch; a failed refresh keeps serving the keys already fetched. Build the layer once per process (a Worker isolate), since it holds that cache.

```typescript
import { Effect, Layer, Option } from "effect";
import { FetchHttpClient } from "effect/http";
import { CloudflareAccess, SessionResolution } from "@thomasfosterau/effect-auth";

const AccessLive = CloudflareAccess.CloudflareAccessVerifier.layer({
  teamDomain: "example-team.cloudflareaccess.com",
  audience: "<the Access application's AUD tag>",
  // Read the browser cookie too, for pages Access does not gate.
  sources: ["header", "cookie"],
}).pipe(Layer.provide(FetchHttpClient.layer));

// Per request: the identity, if any, and the effect-auth user it belongs to.
const viewer = (request: Request) =>
  Effect.gen(function* () {
    const access = yield* CloudflareAccess.CloudflareAccessVerifier;
    const identity = yield* access.verifyRequest(SessionResolution.fromRequest(request));
    if (Option.isNone(identity)) return Option.none();
    const user = yield* CloudflareAccess.findUser(identity.value);
    return Option.map(user, (user) => ({ identity: identity.value, user }));
  });

// Run gated code as that user: `CurrentUser`, `CurrentPrincipal` and
// `CurrentCredential` (a service token is "machine").
// effect.pipe(Effect.provide(CloudflareAccess.userContextLayer(identity, user)))
```

`verifyRequest` answers `Option.none()` when the request carries no token and fails with a `CloudflareAccessError` (its `reason` says which check refused it) when the token is invalid; it never reads an invalid token as anonymous. `sources` defaults to `["header"]`, which Cloudflare recommends since Access adds the header to every request it forwards. Add `"cookie"` when the identity is read on paths Access does not gate, such as an edit control on a page readers also see. The cookie is an ambient credential, so a state-changing request authenticated by it needs a CSRF defence (the trusted-origin check, a `SameSite` cookie), as a session cookie does.

The identity is a `"user"` (with `email`, `subject` = Access's `sub`, `country`, `identityNonce`) or a `"service-token"` (`commonName` = its client id). `findUser` maps a user identity to the owner of a **verified** email identifier with that address, and answers `Option.none()` for a service token, an unknown or unverified address, or a banned or SCIM-deactivated user. It never creates a user or a session and never promotes an unverified address. `userContextLayer(identity, user)` provides the user through `SessionContext.userLayer`; Access issued no effect-auth session, so `CurrentSession` is not provided.

## Email verification

```typescript
import { Effect, Layer } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// Stand-in for your mail client.
declare const sendMail: (message: { to: string; subject: string; html: string }) => Promise<void>;

const emailVerificationStore: typeof Auth.Email.EmailVerificationStore.Service = {
  create: (verification) => Effect.succeed(verification),
  get: (_token) => Effect.succeedNone, // None when unknown
  consume: (_token) => Effect.succeedNone, // atomic get-and-delete
  delete: (_token) => Effect.void,
  deleteByUserId: (_userId) => Effect.void,
  getLatestByUserId: (_userId) => Effect.succeedNone, // the newest by createdAt, for the resend cooldown
};

const EmailVerificationLive = Auth.Email.EmailVerificationService.layer({
  expiresIn: 24 * 60 * 60 * 1000, // 24 hours
  sendEmail: (to, token) =>
    Effect.tryPromise({
      try: () =>
        sendMail({
          to,
          subject: "Verify your email",
          html: `Verify: https://example.com/verify?token=${token}`,
        }),
      catch: (cause) =>
        new Auth.Errors.EmailVerificationError({ message: "Failed to send email", cause }),
    }),
}).pipe(
  Layer.provide(
    Layer.mergeAll(
      Layer.succeed(Auth.Email.EmailVerificationStore)(emailVerificationStore),
      Auth.Hooks.Hooks.Default,
    ),
  ),
);

// Tokens are single-use and stored as SHA-256 digests.
const sendVerification = (userId: string, email: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;
    return yield* service.createVerification(userId, email);
  });

const verifyEmail = (token: string) =>
  Effect.gen(function* () {
    const service = yield* Auth.Email.EmailVerificationService;
    const result = yield* service.verifyToken(token);
    return result.verified ? result.userId : undefined;
  });

export { EmailVerificationLive, sendVerification, verifyEmail };
```

`resendVerification` (the resend `POST /email-verifications` and the `AuthLifecycleService` sign-in and sign-up flows use) waits out `resendCooldown`, 60 s by default from the user's newest token, as the OTPs and the magic link do; `0` turns it off. Inside it, the call fails with `ResendTooSoonError` and the outstanding link stays usable. The HTTP tier and `AuthLifecycleService` answer such a resend as they answer any other, so the refusal never tells an unverified account from an unknown address. A custom `EmailVerificationStore` implements `getLatestByUserId`, which the cooldown reads: the user's verification with the greatest `createdAt`, or `null`.

The first proof of an unverified address (`AuthLifecycleService.verifyEmail`, a magic link, an email OTP, an invitation token, or a provider-verified email through OAuth, Google One Tap or SSO) hands the account to whoever proved it, since anyone could have signed up with the address first: the password is cleared, the account's unverified phone numbers are removed, its linked OAuth accounts, passkeys, API keys, multi-factor enrolment, trusted devices, the access and refresh tokens the OIDC provider issued it (`OidcTokenStore`) and the consents it gave OIDC clients (`OidcConsentStore`) are deleted (each through its store, when the layer's context provides it), and its sessions are revoked. A phone number the account already verified stays, since its holder proved it. JWTs already issued (`Jwt`) can't be revoked and expire on their own. The prover enrols their own. An address already verified keeps everything.

## Delivery

Any [effect-connect](https://github.com/thomasfosterau/effect-connect) provider backs `EmailSender` / `SmsSender` through `EmailSender.layerConnect` / `SmsSender.layerConnect` (or implement either seam yourself), and `emailCallbacks` / `smsCallbacks` derive every feature's send callback from it. Each derived callback awaits its send. A flow that hides whether an account exists hands its send to the host's `DeliveryScheduler` instead, whichever callback it was given. In that flow only a known address gets a message, so an inline send would answer that address later than an unknown one, and answer a vendor failure with an error the unknown address never sees.

```ts
import { Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/http";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Resend from "@thomasfosterau/effect-connect-resend";
import * as Twilio from "@thomasfosterau/effect-connect-twilio";

// `render` (optional) turns a purpose and its params into your own templates.
const Email = Auth.Delivery.EmailSender.layerConnect({
  from: { email: "noreply@example.com", name: "App" },
}).pipe(Layer.provide(Resend.layer({ apiKey: Redacted.make("re_…") })));
const Sms = Auth.Delivery.SmsSender.layerConnect().pipe(
  Layer.provide(
    Twilio.layer({ accountSid: "AC…", authToken: Redacted.make("…"), from: "+61400000000" }),
  ),
);
const Delivery = Layer.mergeAll(Email, Sms).pipe(Layer.provide(FetchHttpClient.layer));
```

| Flow                                                                      | Send                  | Why                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-up: verification email and existing-account notice                   | off the response path | Under `antiEnumeration` a fresh address gets the verification email and a held one the notice (or nothing), so neither answer may wait on the vendor. The send is advisory: a lost one is resent through `POST /email-verifications`. |
| Magic link with `disableSignUp`                                           | off the response path | Only a known address gets the link.                                                                                                                                                                                                   |
| Email OTP `sign-in` with `disableSignUp`, and `forget-password`           | off the response path | Only a known address gets the code.                                                                                                                                                                                                   |
| Phone OTP `sign-in` with `disableSignUp`                                  | off the response path | Only a known number gets the code.                                                                                                                                                                                                    |
| Password reset request                                                    | off the response path | Only a known address gets the link.                                                                                                                                                                                                   |
| Magic link and OTP sign-in with sign-up enabled, OTP `email-verification` | inline                | Every address gets the message, and the user is waiting on it: a failed send is answered, not dropped.                                                                                                                                |
| Verification resend (`POST /email-verifications`)                         | off the response path | Only an unverified account gets the message.                                                                                                                                                                                          |
| Verification email sent directly (`createVerification`)                   | inline                | No account is being hidden.                                                                                                                                                                                                           |
| Change email, delete account, second-factor OTP, organization invitations | inline                | The caller is signed in; nothing is hidden.                                                                                                                                                                                           |

A send off the response path never fails the request. Its failure is logged, counted on `effect_auth_delivery_sends_total` (by purpose and outcome) and passed to the `afterDeliveryFailure` hook, which `AuditPlugin` logs as `auth.deliveryFailure`. The message's parameters (its token or code) are in none of them.

Without a `DeliveryScheduler`, those sends run on a detached fiber, which a long-lived server runs to completion. Workers can drop that fiber once the response is returned, so on Workers provide `DeliveryScheduler.waitUntil` per request:

```ts
import { Effect } from "effect";
import * as Auth from "@thomasfosterau/effect-auth";

// `ctx` is the Worker's ExecutionContext; the scheduler is read per call, so
// providing it per request is enough even when the services are built once.
declare const ctx: { waitUntil(promise: Promise<unknown>): void };
declare const handle: Effect.Effect<Response>;

const response = handle.pipe(
  Effect.provide(
    Auth.DeliveryScheduler.DeliveryScheduler.waitUntil((promise) => ctx.waitUntil(promise)),
  ),
);
```

Detaching does not make the two sign-up answers identical: the fresh branch still writes a verification record that the duplicate branch does not.

**No-op transports.** `EmailSender.logging` and `SmsSender.logging` send nothing and log each message's recipient and purpose. They are for development only, and you opt into them explicitly. Behind them, every flow that waits on a message (magic link, OTP, password reset) is a lockout. The sign-up verification email tolerates being dropped only while verification is advisory, that is, while `requireEmailVerification` does not gate sign-in. effect-connect-resend's `layerConfig` fails at boot when its key is missing rather than falling back to one.
