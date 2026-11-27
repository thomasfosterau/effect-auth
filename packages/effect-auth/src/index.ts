/**
 * effect-auth's public API: one PascalCase namespace per module
 * (`Auth.SessionService.SessionService`, `Auth.Policy.permit`), each also
 * importable on its own subpath (`@thomasfosterau/effect-auth/SessionService`).
 *
 * @module effect-auth
 */

// =============================================================================
// Core primitives
// =============================================================================

/** The core records: users, sessions, attributes and JSON values. */
export * as Types from "./Types.ts";
/** The domain errors, each a `Schema.TaggedError` with a stable `code`. */
export * as Errors from "./Errors.ts";
/** A typed plugin system over fixed points in the auth lifecycle. */
export * as Hooks from "./Hooks.ts";
/** Bearer secrets stored and looked up as their SHA-256 digest. */
export * as TokenHash from "./TokenHash.ts";
/** A user's email, username and phone claims, apart from the `User` record. */
export * as Identifier from "./Identifier.ts";
/** The AEAD cipher, keyed HMAC and signature primitives over `effect/crypto`. */
export * as Cipher from "./Cipher.ts";
/** The platform's crypto seam. */
export * as PlatformCrypto from "./PlatformCrypto.ts";
/** The root secret every derived key comes from. */
export * as RootSecret from "./RootSecret.ts";
/** The email and SMS delivery seams. */
export * as Delivery from "./Delivery.ts";
/** The host scheduler for sends that must not sit on the response path. */
export * as DeliveryScheduler from "./DeliveryScheduler.ts";
/** Domain error codes resolved to localised text. */
export * as Messages from "./Messages.ts";
/** The comparison forms of a domain, an email address and a username. */
export * as Normalize from "./Normalize.ts";

// =============================================================================
// Sessions and users
// =============================================================================

/** The session service: create, resolve, refresh and revoke sessions. */
export * as SessionService from "./SessionService.ts";
/** The session store contract. */
export * as SessionStore from "./SessionStore.ts";
/** The user store contract. */
export * as UserStore from "./UserStore.ts";
/** Trusted devices that skip the second factor. */
export * as TrustedDevice from "./TrustedDevice.ts";
/** The user service: profile updates, attribute protection and deletion. */
export * as User from "./User.ts";
/** Which organization's SSO and SCIM may act on a user. */
export * as ManagedUser from "./ManagedUser.ts";
/** Layer constructors and accessors for an already-resolved session. */
export * as SessionContext from "./SessionContext.ts";
/** The guards that keep an administrator's impersonation from changing the account's credentials. */
export * as Impersonation from "./Impersonation.ts";
/**
 * Session resolution at an application's own edge: credential-presence
 * predicates over a raw `Request`, fail-open and fail-closed resolution, and
 * one `AuthOutcome` the resolver reports itself.
 */
export * as SessionResolution from "./SessionResolution.ts";
/**
 * Cookie naming, shared by the middleware and the app-edge predicates so the
 * computed `__Host-` name has exactly one derivation.
 */
export * as SessionCookies from "./SessionCookies.ts";
/** A signed, optionally encrypted snapshot of the session in a cookie. */
export * as SessionCookieCache from "./SessionCookieCache.ts";
/** Trusted-proxy aware client IP resolution. */
export * as ClientIP from "./ClientIP.ts";

// =============================================================================
// Rate limiting and storage
// =============================================================================

/** The rate limiter facade, its store and presets. */
export * as RateLimit from "./RateLimit.ts";
/** A rate limiter over `effect/persistence`, in memory or on Redis. */
export * as RateLimitPersistence from "./RateLimitPersistence.ts";
/** `KeyValueStore` implementations of the ephemeral stores. */
export * as KeyValueStores from "./KeyValueStores.ts";

// =============================================================================
// Sign-in methods and account features
// =============================================================================

/** Phone sign-in and verification by SMS one-time code. */
export * as PhoneOtp from "./PhoneOtp.ts";
/** Magic link sign-in. */
export * as MagicLink from "./MagicLink.ts";
/** Username sign-in. */
export * as Username from "./Username.ts";
/** Long-lived API keys verified by their digest. */
export * as ApiKey from "./ApiKey.ts";
/** Short-lived, asymmetrically signed JWTs and the published JWKS. */
export * as Jwt from "./Jwt.ts";
/** Enterprise SSO: an OIDC and SAML 2.0 relying party. */
export * as Sso from "./Sso.ts";
/** SCIM 2.0 provisioning. */
export * as Scim from "./Scim.ts";
/** The SAML 2.0 contracts that `@thomasfosterau/effect-auth/saml` implements. */
export * as Saml from "./Saml.ts";
/** Google One Tap sign-in. */
export * as GoogleOneTap from "./GoogleOneTap.ts";
/** Cloudflare Access sign-in. */
export * as CloudflareAccess from "./CloudflareAccess.ts";
/** The bounds on every outbound request (timeout, body cap) and their override. */
export * as OutboundHttp from "./OutboundHttp.ts";
/** Anonymous (guest) sign-in. */
export * as Anonymous from "./Anonymous.ts";
/** Administration: users, roles, bans, sessions and impersonation. */
export * as Admin from "./Admin.ts";
/** Organizations: members, invitations, teams, roles and domains. */
export * as Organization from "./Organization.ts";
/** Verification-gated email change and self-service account deletion. */
export * as AccountManagement from "./AccountManagement.ts";
/** The account-deletion seam that `UserService.deleteUser` delegates to. */
export * as AccountDeletion from "./AccountDeletion.ts";
/** The device authorization grant (RFC 8628). */
export * as DeviceAuthorization from "./DeviceAuthorization.ts";
/** The lifecycle callbacks around sign-up, sign-in and sign-out. */
export * as AuthLifecycle from "./AuthLifecycle.ts";
/** An OIDC provider with PKCE, consent and dynamic client registration. */
export * as OidcProvider from "./OidcProvider.ts";
/** General single-use, expiring tokens. */
export * as OneTimeToken from "./OneTimeToken.ts";
/** Tracing spans and metric counters for the auth operations. */
export * as Observability from "./Observability.ts";
/**
 * `safeRedirect(target, fallback)`: follow a client-supplied post-sign-in
 * redirect only when it is a same-origin path (`/login?redirect=…`).
 */
export * as Redirect from "./Redirect.ts";

// =============================================================================
// Authorization
// =============================================================================

/** Entities and their slices (`Auth.Entity.ref`). */
export * as Entity from "./Entity.ts";
/** Policy conditions (`Auth.Condition.eq`). */
export * as Condition from "./Condition.ts";
/** The pure policy kernel (`Auth.Policy.permit`, `Auth.Policy.decide`). */
export * as Policy from "./Policy.ts";
/** The authorization model: entity types, actions and their schemas. */
export * as AuthorizationModel from "./AuthorizationModel.ts";
/**
 * Non-human principals (`Auth.System.provide("billing-cron")`, `Auth.System.grant`):
 * the reserved `System::"<name>"` entity type, denied by default and allowed
 * only what an explicit policy grants.
 */
export * as System from "./System.ts";
/** The policy store. */
export * as PolicyStore from "./PolicyStore.ts";
/** The organization to entity-graph bridge. */
export * as OrganizationEntities from "./OrganizationEntities.ts";
/**
 * RBAC as authoring sugar over the kernel (`Auth.Rbac.layer`,
 * `Auth.Rbac.policies`): a flat role/permission configuration compiles to
 * declarative policies plus the principal-to-role entity fragment. There is no
 * second evaluation path behind it (ADR 0018).
 */
export * as Rbac from "./Rbac.ts";
/** The `"resource:action"` permission vocabulary the RBAC sugar is authored in. */
export * as Permission from "./Permission.ts";
/**
 * The ordered role ladder (`Auth.Ladder.make([...rungs])`): rank, the one
 * "at least this rung" comparison, and named capability axes. It imports only
 * `effect/Option`, so browser UX gates can load it on its own.
 */
export * as Ladder from "./Ladder.ts";
/** The ladder's rungs as a `Schema` (`Auth.LadderSchema.rung(Roles)`). */
export * as LadderSchema from "./LadderSchema.ts";
/**
 * Zero-IO guards over an already-resolved viewer (`Auth.Guard.make({ ladder,
 * viewer })`): gates failing `Unauthorized` / `Forbidden`, never-failing
 * predicates, and per-viewer capability hooks, all decided by the kernel over
 * a slice built from facts the caller holds.
 */
export * as Guard from "./Guard.ts";
/**
 * Owned-material read access (`Auth.OwnedAccess.make({ guards, viewPrivate })`):
 * four-state visibility (`public | followers | group | private`) narrowed by
 * the draft and moderation axes, the fail-closed `IsFollower` and `IsMember`
 * seams, the per-row `canView` predicate and the per-request `readScope` a
 * list renders.
 */
export * as OwnedAccess from "./OwnedAccess.ts";
/**
 * Reference-material read access (`Auth.ReferenceAccess.make({ guards,
 * viewPrivate })`): ownerless corpus rows on the same visibility axis, read by
 * a followers-of account and its followers or a group's members, with the
 * owned read scope's shape.
 */
export * as ReferenceAccess from "./ReferenceAccess.ts";
/**
 * The read scope (ADR-0020): a declarative policy set compiled over an unbound
 * row into `AllowAll | Deny | Filter(predicate)`, a bound-scalar predicate a
 * LIST renders as its `WHERE`, exact or flagged `Inexact`, with relationships
 * as named sets.
 */
export * as ReadScope from "./ReadScope.ts";
/**
 * Viewer-less cache questions, kept apart: may this representation be served
 * to anyone (`publiclyServeable`), and must this viewer bypass the cache for
 * freshness (`bypassesForFreshness`)?
 */
export * as Cacheability from "./Cacheability.ts";
/** Schema-level field protection. */
export * as Protected from "./Protected.ts";
/** The `Authorizer` service: principal context and entity-slice resolution. */
export * as Authorizer from "./Authorizer.ts";

// =============================================================================
// Feature clusters
// =============================================================================

/** Email and password, email OTP and email verification. */
export * as Email from "./email/index.ts";
/** OAuth 2.0 and OIDC social sign-in. */
export * as OAuth from "./oauth/index.ts";
/** Password hashing, policy and reset. */
export * as Password from "./password/index.ts";
/** The bundled hook plugins. */
export * as Plugins from "./plugins/index.ts";
/** Multi-factor: TOTP, OTP, backup codes and passkeys. */
export * as MultiFactor from "./multifactor/index.ts";
