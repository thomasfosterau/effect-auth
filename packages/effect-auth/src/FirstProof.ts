/**
 * The first proof of an address (#425, #440).
 *
 * An email identifier is created unverified only by a sign-up that proved
 * nothing about the address, so the password and sessions on its account may
 * belong to whoever signed up with it first, not to the address's holder. Every
 * flow that promotes such an identifier to verified on the strength of a
 * proof (a verification link, a magic link, an email OTP, an IdP's verified
 * email claim) first clears the account's password and revokes its sessions,
 * so the prover is left the only one holding the account.
 *
 * @internal
 */
import { Effect } from "effect";
import type * as Errors from "./Errors.ts";
import type { Identifier, IdentifierStore } from "./Identifier.ts";
import type { EmailPasswordStore } from "./email/EmailPassword.ts";
import type { SessionService } from "./SessionService.ts";

/** The services {@link proveAddress} writes through, resolved by the caller. */
export interface FirstProofServices {
  readonly identifiers: typeof IdentifierStore.Service;
  readonly passwords: Pick<typeof EmailPasswordStore.Service, "clearPasswordHash">;
  readonly sessions: Pick<typeof SessionService.Service, "invalidateUserSessions">;
}

/**
 * Promote `identifier` to verified. When it is not verified yet, first clear
 * its account's password and revoke all of the account's sessions; the
 * caller mints the prover's session afterwards. Returns what `setVerified`
 * returns (`null` when the identifier was deleted meanwhile).
 */
export const proveAddress = (
  services: FirstProofServices,
  identifier: Identifier,
): Effect.Effect<Identifier | null, Errors.AuthError> =>
  Effect.gen(function* () {
    if (!identifier.verified) {
      yield* services.passwords.clearPasswordHash(identifier.userId);
      yield* services.sessions.invalidateUserSessions(identifier.userId);
    }
    return yield* services.identifiers.setVerified(identifier.id, new Date());
  });
