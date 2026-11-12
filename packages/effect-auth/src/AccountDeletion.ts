/**
 * The account-deletion seam (#601): delete a user and everything the account
 * holds. `UserService.deleteUser` delegates to it through the context.
 *
 * This module holds the service's tag only, and imports no store, so
 * `User.ts` can depend on it: the stores the deletion clears live in modules
 * that import `User.ts` themselves. Its layer, which resolves those stores,
 * is `AccountManagement.ts`'s `accountDeletionLayer`.
 *
 * @module AccountDeletion
 * @since 0.5.0
 */
import { Context, type Effect } from "effect";
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
