/**
 * The first proof of an address (#425, #440, #671, #694, #704).
 *
 * An email identifier is created unverified only by a sign-up that proved
 * nothing about the address, so every credential on its account may belong to
 * whoever signed up with it first, not to the address's holder. Every flow
 * that promotes such an identifier to verified on the strength of a proof (a
 * verification link, a magic link, an email OTP, an invitation, an IdP's
 * verified email claim through OAuth, Google One Tap or SSO) first clears the
 * account's password, removes its other credentials (unverified phone
 * numbers, linked OAuth accounts, passkeys, API keys, multi-factor enrolment,
 * trusted devices and the tokens the core's OIDC provider issued) and revokes
 * its sessions, so the prover is left the only one holding the account and
 * enrols their own credentials. A phone number the account already verified
 * stays: its holder proved it with a code sent to it, so it is not the
 * earlier holder's to keep or lose. JWTs already issued (`Jwt`) cannot be
 * revoked; they expire on their own.
 *
 * @internal
 */
import { DateTime, Effect } from "effect";
import type * as Errors from "./Errors.ts";
import type { Identifier, IdentifierStore } from "./Identifier.ts";
import type { EmailPasswordStore } from "./email/EmailPassword.ts";
import type { SessionService } from "./SessionService.ts";
import {
  deleteCredentials,
  type UserCredentialStores,
  userCredentialStores,
} from "./UserCredentials.ts";

/**
 * The credential stores {@link proveAddress} sweeps on a first proof, each
 * through its per-user delete (`UserCredentials.ts`, which deleting a user shares).
 * Each is optional: an app without passkeys provides no `CredentialStore`,
 * and its absence means the account cannot hold that kind of credential.
 */
export type FirstProofCredentials = Pick<
  UserCredentialStores,
  "oauthAccounts" | "passkeys" | "apiKeys" | "multiFactor" | "trustedDevices" | "oidcTokens"
>;

/** The services {@link proveAddress} writes through, resolved by the caller. */
export interface FirstProofServices extends FirstProofCredentials {
  readonly identifiers: typeof IdentifierStore.Service;
  readonly passwords: Pick<typeof EmailPasswordStore.Service, "clearPasswordHash">;
  readonly sessions: Pick<
    typeof SessionService.Service,
    "invalidateUserSessions" | "revokeOtherSessions"
  >;
}

/**
 * The {@link FirstProofServices} over the caller's `base` services and the
 * credential stores present in the context. A caller resolves it where it
 * resolves its other stores (at layer construction) and passes it to every
 * {@link proveAddress} it makes.
 */
export const firstProofServices = (
  base: Omit<FirstProofServices, keyof FirstProofCredentials>,
): Effect.Effect<FirstProofServices> =>
  Effect.map(userCredentialStores, (stores) => ({
    ...base,
    oauthAccounts: stores.oauthAccounts,
    passkeys: stores.passkeys,
    apiKeys: stores.apiKeys,
    multiFactor: stores.multiFactor,
    trustedDevices: stores.trustedDevices,
    oidcTokens: stores.oidcTokens,
  }));

/**
 * Remove the phone identifiers `userId` never verified (#704): whoever added
 * one could sign in by phone code. A verified one was proven by its holder.
 */
const removeUnverifiedPhones = (
  identifiers: typeof IdentifierStore.Service,
  userId: string,
): Effect.Effect<void, Errors.AuthError> =>
  Effect.flatMap(identifiers.listByUser(userId), (held) =>
    Effect.forEach(
      held.filter((identifier) => identifier.type === "phone" && !identifier.verified),
      (phone) => identifiers.delete(phone.id),
      { concurrency: 1, discard: true },
    ),
  );

/** Remove every credential `userId` holds other than its password, phone identifiers and sessions. */
const removeCredentials = (credentials: FirstProofCredentials, userId: string) =>
  deleteCredentials(
    {
      oauthAccounts: credentials.oauthAccounts,
      passkeys: credentials.passkeys,
      apiKeys: credentials.apiKeys,
      multiFactor: credentials.multiFactor,
      trustedDevices: credentials.trustedDevices,
      oidcTokens: credentials.oidcTokens,
    },
    userId,
  );

/**
 * Promote `identifier` to verified. When it is not verified yet, first clear
 * its account's password, remove its unverified phone identifiers and its
 * other credentials (the {@link FirstProofCredentials} the caller passes,
 * OIDC-provider tokens included) and revoke its sessions,
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
      yield* removeUnverifiedPhones(services.identifiers, identifier.userId);
      yield* removeCredentials(services, identifier.userId);
      yield* proverSessionId === undefined
        ? services.sessions.invalidateUserSessions(identifier.userId)
        : services.sessions.revokeOtherSessions(identifier.userId, proverSessionId);
    }
    return yield* services.identifiers.setVerified(identifier.id, yield* DateTime.nowAsDate);
  });
