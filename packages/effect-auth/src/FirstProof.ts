/**
 * The first proof of an address: before a flow verifies an unverified email
 * identifier on a proof, it clears the account's password and other credentials
 * and revokes its sessions, so the prover alone holds the account. A verified
 * phone stays, and issued JWTs expire on their own.
 *
 * @internal
 */
import { DateTime, Effect } from "effect";
import * as Option from "effect/Option";
import type * as Errors from "./Errors.ts";
import type { Identifier, IdentifierStore } from "./Identifier.ts";
import type { EmailPasswordStore } from "./email/EmailPassword.ts";
import type { SessionService } from "./SessionService.ts";
import type * as Types from "./Types.ts";
import {
  type CreateUserResult,
  createUserWithIdentifier,
  type NewUserIdentifier,
} from "./UserStore.ts";
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
  | "oauthAccounts"
  | "passkeys"
  | "apiKeys"
  | "multiFactor"
  | "trustedDevices"
  | "oidcTokens"
  | "oidcConsents"
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
    oidcConsents: stores.oidcConsents,
  }));

/**
 * Remove the phone identifiers `userId` never verified: whoever added
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
      oidcConsents: credentials.oidcConsents,
    },
    userId,
  );

/**
 * Promote `identifier` to verified. When it is not verified yet, first clear
 * its account's password, remove its unverified phone identifiers and its
 * other credentials (the {@link FirstProofCredentials} the caller passes,
 * OIDC-provider tokens and consents included) and revoke its sessions,
 * last, so a session minted with a credential before its removal goes too;
 * the caller mints the prover's session (and, for OAuth, creates the link
 * being made now) afterwards. A prover who presented the proof over one of
 * the account's sessions (an invitation accepted while signed in) passes that
 * session's stored id (the token's digest, as `validateSession` answers it) as
 * `proverSessionId`, and it alone survives. An identifier that is already
 * verified is promoted with nothing removed. Returns what `setVerified`
 * returns (`None` when the identifier was deleted meanwhile).
 */
export const proveAddress = (
  services: FirstProofServices,
  identifier: Identifier,
  proverSessionId?: string,
): Effect.Effect<Option.Option<Identifier>, Errors.AuthError> =>
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

/**
 * The user a proof of `email` signs in, given what `findIdentifierOwner`
 * found for it. An owner is returned, its address first promoted through
 * {@link proveAddress} when it is unverified. With no owner, `create` makes a
 * user holding the address already verified, and `taken` is the flow's error
 * when another user claims the address meanwhile.
 */
export const userForProvenEmail = <E, R, E2>(
  services: FirstProofServices,
  found: Option.Option<{ readonly identifier: Identifier; readonly user: Types.User }>,
  email: string,
  create: (identifier: NewUserIdentifier) => Effect.Effect<CreateUserResult, E, R>,
  taken: () => E2,
): Effect.Effect<Types.User, E | E2 | Errors.AuthError, R> =>
  Effect.gen(function* () {
    if (Option.isSome(found)) {
      const { identifier, user } = found.value;
      if (!identifier.verified) yield* proveAddress(services, identifier);
      return user;
    }
    const verifiedAt = yield* DateTime.nowAsDate;
    const created = yield* createUserWithIdentifier(
      services.identifiers,
      { type: "email", value: email, verified: true, verifiedAt },
      create,
    ).pipe(Effect.catchTag("IdentifierTakenError", () => Effect.fail(taken())));
    return created.user;
  });
