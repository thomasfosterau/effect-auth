/**
 * Deleting a user deletes what they hold (#601).
 *
 * Every path that deletes a user (`AccountManagementService`'s confirmed
 * deletion, `AdminService.removeUser`, `AnonymousService` once an anonymous
 * user is linked, and `UserService.deleteUser` through the `AccountDeletion`
 * service) goes through {@link purgeUser}. It removes the user's credentials
 * and tokens through each store's per-user delete (`UserCredentials.ts`), the
 * unspent magic links and one-time codes sent to the user's addresses, then
 * the sessions, then the identifiers, and only then the user row. The stores
 * keep no foreign keys, so nothing else removes those rows.
 *
 * The stores are optional: a caller resolves them once with
 * {@link userPurgeStores} where it resolves its other stores, and an app
 * without a store holds nothing of that kind.
 *
 * @internal
 */
import { Effect } from "effect";
import * as Option from "effect/Option";
import * as R from "effect/Record";
import { type EmailOtpPurpose, EmailOtpStore } from "./email/EmailOtp.ts";
import type * as Errors from "./Errors.ts";
import type { Identifier, IdentifierStore } from "./Identifier.ts";
import { MagicLinkStore } from "./MagicLink.ts";
import { type PhoneOtpPurpose, PhoneOtpStore } from "./PhoneOtp.ts";
import {
  deleteCredentials,
  type UserCredentialStores,
  userCredentialStores,
} from "./UserCredentials.ts";

/**
 * The stores that key a pending sign-in proof by address rather than by user:
 * a magic link or a one-time code sent to an address the deleted user held.
 * Left in place, it would still be redeemable once the address is claimed
 * again, and sign its holder into the new account.
 */
export interface AddressProofStores {
  readonly magicLinks?: Pick<typeof MagicLinkStore.Service, "deleteByEmail"> | undefined;
  readonly emailOtps?: Pick<typeof EmailOtpStore.Service, "delete"> | undefined;
  readonly phoneOtps?: Pick<typeof PhoneOtpStore.Service, "delete"> | undefined;
}

/** Every stored purpose of a code, so the purge leaves none behind. */
const emailOtpPurposes = R.keys({
  "sign-in": true,
  "email-verification": true,
  "forget-password": true,
} satisfies Record<EmailOtpPurpose, true>);
const phoneOtpPurposes = R.keys({
  "sign-in": true,
  "phone-verification": true,
} satisfies Record<PhoneOtpPurpose, true>);

/** The stores {@link purgeUser} clears that are present in the context. */
export type UserPurgeStores = UserCredentialStores & AddressProofStores;

/**
 * The {@link UserPurgeStores} present in the context. Resolve it where the
 * other stores are resolved (at layer construction), so service methods keep
 * `R = never`.
 */
export const userPurgeStores: Effect.Effect<UserPurgeStores> = Effect.map(
  Effect.all(
    {
      credentials: userCredentialStores,
      magicLinks: Effect.serviceOption(MagicLinkStore),
      emailOtps: Effect.serviceOption(EmailOtpStore),
      phoneOtps: Effect.serviceOption(PhoneOtpStore),
    },
    { concurrency: 1 },
  ),
  (found) => ({
    ...found.credentials,
    magicLinks: Option.getOrUndefined(found.magicLinks),
    emailOtps: Option.getOrUndefined(found.emailOtps),
    phoneOtps: Option.getOrUndefined(found.phoneOtps),
  }),
);

/**
 * Delete the unspent magic links and one-time codes sent to `identifier`'s
 * address. The codes' failure budgets (#590) stay: they belong to the
 * address, not to the account, and a deletion must not reset them.
 */
const deleteAddressProofs = (
  stores: AddressProofStores,
  identifier: Identifier,
): Effect.Effect<void, Errors.AuthError> => {
  const { magicLinks, emailOtps, phoneOtps } = stores;
  if (identifier.type === "email") {
    return Effect.all(
      [
        magicLinks === undefined ? Effect.void : magicLinks.deleteByEmail(identifier.value),
        emailOtps === undefined
          ? Effect.void
          : Effect.forEach(
              emailOtpPurposes,
              (purpose) => emailOtps.delete(identifier.value, purpose),
              {
                concurrency: 1,
                discard: true,
              },
            ),
      ],
      { concurrency: 1, discard: true },
    );
  }
  if (identifier.type === "phone" && phoneOtps !== undefined) {
    return Effect.forEach(
      phoneOtpPurposes,
      (purpose) => phoneOtps.delete(identifier.value, purpose),
      {
        concurrency: 1,
        discard: true,
      },
    );
  }
  return Effect.void;
};

/** What {@link purgeUser} writes through. */
export interface UserPurgeServices extends UserPurgeStores {
  /** `undefined` only where users hold no identifiers (anonymous users). */
  readonly identifiers:
    | Pick<typeof IdentifierStore.Service, "listByUser" | "deleteByUser">
    | undefined;
  /** Revoke every session of the user (`SessionService.invalidateUserSessions`). */
  readonly revokeSessions: (userId: string) => Effect.Effect<void, Errors.AuthError>;
  /** Delete the user row. */
  readonly deleteUser: (userId: string) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * Delete `userId` and everything the account holds: its credentials and
 * tokens (`deleteCredentials`), the unspent magic links and one-time codes
 * sent to its addresses, then its sessions, then its identifiers (releasing
 * its addresses and handles), and the user row last.
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
    const { identifiers } = services;
    if (identifiers !== undefined) {
      yield* Effect.forEach(
        yield* identifiers.listByUser(userId),
        (identifier) => deleteAddressProofs(services, identifier),
        { concurrency: 1, discard: true },
      );
    }
    yield* services.revokeSessions(userId);
    if (identifiers !== undefined) yield* identifiers.deleteByUser(userId);
    yield* services.deleteUser(userId);
  });
