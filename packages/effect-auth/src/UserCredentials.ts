/**
 * The user-keyed credential and token stores and their per-user deletes:
 * `UserPurge.ts` clears all of them, `FirstProof.ts` a subset. The stores are
 * optional; {@link userCredentialStores} resolves them once.
 *
 * @internal
 */
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import { ApiKeyStore } from "./ApiKey.ts";
import { definedKeys } from "./DefinedKeys.ts";
import type * as Errors from "./Errors.ts";
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
  readonly oauthAccounts?: PerUser;
  readonly passkeys?: PerUser;
  readonly apiKeys?: PerUser;
  readonly multiFactor?: Pick<typeof MultiFactorStore.Service, "delete">;
  readonly trustedDevices?: PerUser;
  /** The access and refresh tokens the core's OIDC provider issued. */
  readonly oidcTokens?: PerUser;
  /** The consents the user granted the OIDC provider's clients. */
  readonly oidcConsents?: PerUser;
  readonly passwordResets?: PerUser;
  readonly emailVerifications?: PerUser;
  /**
   * `AccountManagementStore`'s pending email-change and deletion tokens. Not
   * resolved by {@link userCredentialStores} (`AccountManagement.ts` imports
   * the purge); a caller that has the store passes it.
   */
  readonly accountTokens?: PerUser;
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
  (found) =>
    definedKeys({
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

/**
 * Revoke the bearer access `userId` holds outside a session: their API keys
 * and the OIDC provider's access and refresh tokens and consents. A ban and a
 * SCIM deactivation run it after revoking the sessions, so nothing the user
 * held before keeps working once the flag is lifted. JWTs already issued
 * cannot be revoked and are left to expire.
 */
export const revokeStandingAccess = (
  stores: UserCredentialStores,
  userId: string,
): Effect.Effect<void, Errors.AuthError> =>
  Effect.all(
    [
      perUser(stores.apiKeys, userId),
      perUser(stores.oidcTokens, userId),
      perUser(stores.oidcConsents, userId),
    ],
    { concurrency: 1, discard: true },
  );
