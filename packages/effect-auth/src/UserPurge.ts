/**
 * Deleting a user deletes what they hold (#601).
 *
 * Every path that deletes a user (`AccountManagementService`'s confirmed
 * deletion, `AdminService.removeUser`, `AnonymousService` once an anonymous
 * user is linked) goes through {@link purgeUser}, which removes the user's
 * credentials and tokens through each store's per-user delete, then their
 * sessions, then their identifiers, and only then the user row. The stores
 * keep no foreign keys, so nothing else removes those rows.
 *
 * The credential stores are optional, as in the first proof of an address
 * (`FirstProof.ts`, which sweeps a subset of the same stores through
 * {@link deleteCredentials}): a caller resolves them once with
 * {@link userCredentialStores} where it resolves its other stores, and an app
 * without a store holds no credential of that kind.
 *
 * @internal
 */
import { Effect } from "effect";
import * as Option from "effect/Option";
import { ApiKeyStore } from "./ApiKey.ts";
import type * as Errors from "./Errors.ts";
import type { IdentifierStore } from "./Identifier.ts";
import { EmailVerificationStore } from "./email/EmailVerification.ts";
import { MultiFactorStore } from "./multifactor/MultiFactor.ts";
import { CredentialStore } from "./multifactor/WebAuthn.ts";
import { OAuthAccountStore } from "./oauth/OAuthAccount.ts";
import { OidcConsentStore, OidcTokenStore } from "./OidcProvider.ts";
import { PasswordResetStore } from "./password/PasswordReset.ts";
import { TrustedDeviceStore } from "./TrustedDevice.ts";

/** A store's per-user delete. */
interface PerUser {
  readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * The user-keyed credential and token stores, each `undefined` when the app
 * provides none. `multiFactor` is keyed by user id, so its `delete` is the
 * per-user delete.
 */
export interface UserCredentialStores {
  readonly oauthAccounts?: PerUser | undefined;
  readonly passkeys?: PerUser | undefined;
  readonly apiKeys?: PerUser | undefined;
  readonly multiFactor?: Pick<typeof MultiFactorStore.Service, "delete"> | undefined;
  readonly trustedDevices?: PerUser | undefined;
  /** The access and refresh tokens the core's OIDC provider issued. */
  readonly oidcTokens?: PerUser | undefined;
  /** The consents the user granted the OIDC provider's clients. */
  readonly oidcConsents?: PerUser | undefined;
  readonly passwordResets?: PerUser | undefined;
  readonly emailVerifications?: PerUser | undefined;
  /**
   * `AccountManagementStore`'s pending email-change and deletion tokens. Not
   * resolved by {@link userCredentialStores} (`AccountManagement.ts` imports
   * this module); a caller that has the store passes it.
   */
  readonly accountTokens?: PerUser | undefined;
}

/**
 * The {@link UserCredentialStores} present in the context. Resolve it where
 * the other stores are resolved (at layer construction), so service methods
 * keep `R = never`.
 */
export const userCredentialStores: Effect.Effect<UserCredentialStores> = Effect.map(
  Effect.all(
    {
      oauthAccounts: Effect.serviceOption(OAuthAccountStore),
      passkeys: Effect.serviceOption(CredentialStore),
      apiKeys: Effect.serviceOption(ApiKeyStore),
      multiFactor: Effect.serviceOption(MultiFactorStore),
      trustedDevices: Effect.serviceOption(TrustedDeviceStore),
      oidcTokens: Effect.serviceOption(OidcTokenStore),
      oidcConsents: Effect.serviceOption(OidcConsentStore),
      passwordResets: Effect.serviceOption(PasswordResetStore),
      emailVerifications: Effect.serviceOption(EmailVerificationStore),
    },
    { concurrency: 1 },
  ),
  (found) => ({
    oauthAccounts: Option.getOrUndefined(found.oauthAccounts),
    passkeys: Option.getOrUndefined(found.passkeys),
    apiKeys: Option.getOrUndefined(found.apiKeys),
    multiFactor: Option.getOrUndefined(found.multiFactor),
    trustedDevices: Option.getOrUndefined(found.trustedDevices),
    oidcTokens: Option.getOrUndefined(found.oidcTokens),
    oidcConsents: Option.getOrUndefined(found.oidcConsents),
    passwordResets: Option.getOrUndefined(found.passwordResets),
    emailVerifications: Option.getOrUndefined(found.emailVerifications),
  }),
);

const perUser = (
  store: PerUser | undefined,
  userId: string,
): Effect.Effect<void, Errors.AuthError> =>
  store === undefined ? Effect.void : store.deleteByUserId(userId);

/**
 * Delete everything `userId` holds in `stores`, one store after another. Each
 * per-user delete is idempotent, so a run that fails part-way can be retried.
 */
export const deleteCredentials = (
  stores: UserCredentialStores,
  userId: string,
): Effect.Effect<void, Errors.AuthError> =>
  Effect.all(
    [
      perUser(stores.oauthAccounts, userId),
      perUser(stores.passkeys, userId),
      perUser(stores.apiKeys, userId),
      stores.multiFactor === undefined ? Effect.void : stores.multiFactor.delete(userId),
      perUser(stores.trustedDevices, userId),
      perUser(stores.oidcTokens, userId),
      perUser(stores.oidcConsents, userId),
      perUser(stores.passwordResets, userId),
      perUser(stores.emailVerifications, userId),
      perUser(stores.accountTokens, userId),
    ],
    { concurrency: 1, discard: true },
  );

/** What {@link purgeUser} writes through. */
export interface UserPurgeServices extends UserCredentialStores {
  /** `undefined` only where users hold no identifiers (anonymous users). */
  readonly identifiers: Pick<typeof IdentifierStore.Service, "deleteByUser"> | undefined;
  /** Revoke every session of the user (`SessionService.invalidateUserSessions`). */
  readonly revokeSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  /** Delete the user row. */
  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Delete `userId` and everything the account holds: its credentials and
 * tokens ({@link deleteCredentials}), then its sessions, then its
 * identifiers (releasing its addresses and handles), and the user row last.
 *
 * The steps run in order in the caller's fiber, so the user row goes only
 * once everything else has: a failure part-way leaves the user (with part of
 * what it held removed), never rows that name a user who no longer exists,
 * and the call can be retried, since every step is idempotent. The stores
 * see no transaction of their own; an app whose stores share one
 * (`effect/sql`'s `sql.withTransaction`, a drizzle Effect driver's
 * `db.transaction`) wraps the deleting call in it to make the purge atomic.
 */
export const purgeUser = (
  services: UserPurgeServices,
  userId: string,
): Effect.Effect<void, Errors.AuthError> =>
  Effect.gen(function* () {
    yield* deleteCredentials(services, userId);
    yield* services.revokeSessions(userId);
    if (services.identifiers !== undefined) yield* services.identifiers.deleteByUser(userId);
    yield* services.deleteUser(userId);
  });
