/**
 * The first proof of an address (#425, #440, #671, #694).
 *
 * An email identifier is created unverified only by a sign-up that proved
 * nothing about the address, so every credential on its account may belong to
 * whoever signed up with it first, not to the address's holder. Every flow
 * that promotes such an identifier to verified on the strength of a proof (a
 * verification link, a magic link, an email OTP, an invitation, an IdP's
 * verified email claim through OAuth, Google One Tap or SSO) first clears the
 * account's password, removes its other credentials (linked OAuth accounts,
 * passkeys, API keys, multi-factor enrolment and trusted devices) and revokes
 * its sessions, so the prover is left the only one holding the account and
 * enrols their own credentials.
 *
 * @internal
 */
import { DateTime, Effect } from "effect";
import * as Option from "effect/Option";
import { ApiKeyStore } from "./ApiKey.ts";
import type * as Errors from "./Errors.ts";
import type { Identifier, IdentifierStore } from "./Identifier.ts";
import type { EmailPasswordStore } from "./email/EmailPassword.ts";
import { MultiFactorStore } from "./multifactor/MultiFactor.ts";
import { CredentialStore } from "./multifactor/WebAuthn.ts";
import { OAuthAccountStore } from "./oauth/OAuthAccount.ts";
import type { SessionService } from "./SessionService.ts";
import { TrustedDeviceStore } from "./TrustedDevice.ts";

/**
 * The credential stores {@link proveAddress} sweeps on a first proof. Each is
 * optional: an app without passkeys provides no `CredentialStore`, and its
 * absence means the account cannot hold that kind of credential.
 */
export interface FirstProofCredentials {
  readonly oauthAccounts?:
    | Pick<typeof OAuthAccountStore.Service, "getByUserId" | "delete">
    | undefined;
  readonly passkeys?: Pick<typeof CredentialStore.Service, "listByUserId" | "delete"> | undefined;
  readonly apiKeys?: Pick<typeof ApiKeyStore.Service, "listByUserId" | "delete"> | undefined;
  readonly multiFactor?: Pick<typeof MultiFactorStore.Service, "delete"> | undefined;
  readonly trustedDevices?: Pick<typeof TrustedDeviceStore.Service, "deleteByUserId"> | undefined;
}

/** The services {@link proveAddress} writes through, resolved by the caller. */
export interface FirstProofServices extends FirstProofCredentials {
  readonly identifiers: typeof IdentifierStore.Service;
  readonly passwords: Pick<typeof EmailPasswordStore.Service, "clearPasswordHash">;
  readonly sessions: Pick<
    typeof SessionService.Service,
    "invalidateUserSessions" | "revokeOtherSessions"
  >;
}

/** The credential stores present in the context, each `undefined` when absent. */
const firstProofCredentials: Effect.Effect<FirstProofCredentials> = Effect.map(
  Effect.all(
    {
      oauthAccounts: Effect.serviceOption(OAuthAccountStore),
      passkeys: Effect.serviceOption(CredentialStore),
      apiKeys: Effect.serviceOption(ApiKeyStore),
      multiFactor: Effect.serviceOption(MultiFactorStore),
      trustedDevices: Effect.serviceOption(TrustedDeviceStore),
    },
    { concurrency: 1 },
  ),
  (found) => ({
    oauthAccounts: Option.getOrUndefined(found.oauthAccounts),
    passkeys: Option.getOrUndefined(found.passkeys),
    apiKeys: Option.getOrUndefined(found.apiKeys),
    multiFactor: Option.getOrUndefined(found.multiFactor),
    trustedDevices: Option.getOrUndefined(found.trustedDevices),
  }),
);

/**
 * The {@link FirstProofServices} over the caller's `base` services and the
 * credential stores present in the context. A caller resolves it where it
 * resolves its other stores (at layer construction) and passes it to every
 * {@link proveAddress} it makes.
 */
export const firstProofServices = (
  base: Omit<FirstProofServices, keyof FirstProofCredentials>,
): Effect.Effect<FirstProofServices> =>
  Effect.map(firstProofCredentials, (credentials) => ({ ...base, ...credentials }));

/** Run `sweep` over `store` when the app provides it. */
const ifPresent = <S>(
  store: S | undefined,
  sweep: (store: S) => Effect.Effect<void, Errors.AuthError>,
): Effect.Effect<void, Errors.AuthError> => (store === undefined ? Effect.void : sweep(store));

/** Remove every credential `userId` holds other than its password and sessions. */
const removeCredentials = (credentials: FirstProofCredentials, userId: string) =>
  Effect.all(
    [
      ifPresent(credentials.oauthAccounts, (store) =>
        Effect.flatMap(store.getByUserId(userId), (links) =>
          Effect.forEach(links, (link) => store.delete(link.provider, link.providerId), {
            concurrency: 1,
            discard: true,
          }),
        ),
      ),
      ifPresent(credentials.passkeys, (store) =>
        Effect.flatMap(store.listByUserId(userId), (passkeys) =>
          Effect.forEach(passkeys, (passkey) => store.delete(passkey.id), {
            concurrency: 1,
            discard: true,
          }),
        ),
      ),
      ifPresent(credentials.apiKeys, (store) =>
        Effect.flatMap(store.listByUserId(userId), (keys) =>
          Effect.forEach(keys, (key) => store.delete(key.id), { concurrency: 1, discard: true }),
        ),
      ),
      ifPresent(credentials.multiFactor, (store) => store.delete(userId)),
      ifPresent(credentials.trustedDevices, (store) => store.deleteByUserId(userId)),
    ],
    { concurrency: 1, discard: true },
  );

/**
 * Promote `identifier` to verified. When it is not verified yet, first clear
 * its account's password, remove the account's other credentials (the
 * {@link FirstProofCredentials} the caller passes) and revoke its sessions,
 * last, so a session minted with a credential before its removal goes too;
 * the caller mints the prover's session (and, for OAuth, creates the link
 * being made now) afterwards. A prover who presented the proof over one of
 * the account's sessions (an invitation accepted while signed in) passes that
 * session's stored id (the token's digest, as `validateSession` answers it) as
 * `proverSessionId`, and it alone survives. An identifier that is already
 * verified is promoted with nothing removed. Returns what `setVerified`
 * returns (`null` when the identifier was deleted meanwhile).
 */
export const proveAddress = (
  services: FirstProofServices,
  identifier: Identifier,
  proverSessionId?: string,
): Effect.Effect<Identifier | null, Errors.AuthError> =>
  Effect.gen(function* () {
    if (!identifier.verified) {
      yield* services.passwords.clearPasswordHash(identifier.userId);
      yield* removeCredentials(services, identifier.userId);
      yield* proverSessionId === undefined
        ? services.sessions.invalidateUserSessions(identifier.userId)
        : services.sessions.revokeOtherSessions(identifier.userId, proverSessionId);
    }
    return yield* services.identifiers.setVerified(identifier.id, yield* DateTime.nowAsDate);
  });
