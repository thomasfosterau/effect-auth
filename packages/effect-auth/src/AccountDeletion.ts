/**
 * The account-deletion seam that `UserService.deleteUser` delegates to. It
 * holds only the tag and imports no store, so `User.ts` imports it without a
 * cycle; the layer is `AccountManagement.ts`'s `accountDeletionLayer`.
 *
 * @module AccountDeletion
 * @since 0.5.0
 */
import * as Context from "effect/Context";
import type * as Effect from "effect/Effect";
import type { AuthError } from "./Errors.ts";

/**
 * Deletes a user and everything the account holds: the credentials and
 * tokens in every user-keyed store present where its layer is built, the
 * unspent magic links and one-time codes sent to the user's addresses, the
 * sessions, the identifiers, and the user row last. A failure part-way leaves
 * the user row, and calling it again finishes the deletion. Deleting a user
 * that does not exist is a no-op.
 *
 * Provide it with `accountDeletionLayer`.
 *
 * @since 0.5.0
 * @category services
 */
export class AccountDeletion extends Context.Service<
  AccountDeletion,
  {
    readonly deleteUser: (userId: string) => Effect.Effect<void, AuthError>;
  }
>()("@effect-auth/AccountDeletion") {}
