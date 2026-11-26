/**
 * The OAuth account link and its store, apart from the OAuth flows so that
 * modules the flows import (the first proof of an address) can reach
 * the store without an import cycle. `OAuth.ts` re-exports both.
 */
import * as Context from "effect/Context";
import type * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import type { AuthError } from "../Errors.ts";

/**
 * OAuth account linking to user
 */
export interface OAuthAccount {
  readonly id: string;
  readonly userId: string;
  readonly provider: string;
  readonly providerId: string;
  readonly email?: string;
  readonly name?: string;
  readonly picture?: string;
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresAt?: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * Storage interface for OAuth accounts (persistent, database)
 */
export class OAuthAccountStore extends Context.Service<
  OAuthAccountStore,
  {
    /**
     * Insert a new provider link. A plain insert, never an upsert: when
     * `(provider, providerId)` is already linked, fail with `AuthError` (a
     * unique index's refusal) and leave the stored link as it is. The
     * service re-reads the pair and reports `OAuthAccountConflictError`, so
     * two concurrent first sign-ins with one provider account cannot both
     * win, and a link cannot silently move to another user.
     */
    readonly create: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
    readonly get: (
      provider: string,
      providerId: string,
    ) => Effect.Effect<Option.Option<OAuthAccount>, AuthError>;
    readonly getByUserId: (userId: string) => Effect.Effect<readonly OAuthAccount[], AuthError>;
    /**
     * Refresh the tokens and profile fields (`email`, `name`, `picture`,
     * `accessToken`, `refreshToken`, `expiresAt`, `updatedAt`) of the link
     * whose `id` is `account.id`. It never changes `userId`, `provider` or
     * `providerId`, and never creates a link: it returns the link as stored
     * afterwards, or `None` when no link has that id (unlinked meanwhile).
     */
    readonly update: (
      account: OAuthAccount,
    ) => Effect.Effect<Option.Option<OAuthAccount>, AuthError>;
    /**
     * Point the existing link for `(account.provider, account.providerId)` at
     * `userId`; a no-op when there is none. The one method that changes a
     * link's `userId`: the caller links an account `OAuthService.handleCallback`
     * created unlinked, after creating the user. Only an unlinked link (empty
     * `userId`) or one `userId` already holds may move; when another user
     * holds the link it fails with `AuthError` and leaves the link as it is.
     */
    readonly linkToUser: (userId: string, account: OAuthAccount) => Effect.Effect<void, AuthError>;
    readonly unlinkFromUser: (userId: string, provider: string) => Effect.Effect<void, AuthError>;
    readonly delete: (provider: string, providerId: string) => Effect.Effect<void, AuthError>;
    /**
     * Delete every provider link `userId` holds (their provider tokens with
     * them); a no-op when they hold none. Deleting a user calls it before the
     * user row goes, and the first proof of an address calls it too.
     */
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, AuthError>;
    /**
     * Optional: report whether the user has a password hash set. Consulted by
     * {@link OAuthService.unlinkAccount}'s last-credential lockout guard to
     * decide whether the account being unlinked is the user's only sign-in
     * credential.
     *
     * When this capability is **absent** the guard **fails open**: it assumes
     * the user retains another credential and permits the unlink, rather than
     * blocking on incomplete information. Implement it to enable the lockout
     * check.
     */
    readonly hasPassword?: (userId: string) => Effect.Effect<boolean, AuthError>;
  }
>()("@effect-auth/OAuthAccountStore") {}
