/**
 * The OAuth account link and its store, apart from the OAuth flows so that
 * modules the flows import (the first proof of an address, #694) can reach
 * the store without an import cycle. `OAuth.ts` re-exports both.
 */
import { Context, type Effect } from "effect";
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
    readonly create: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
    readonly get: (
      provider: string,
      providerId: string,
    ) => Effect.Effect<OAuthAccount | null, AuthError>;
    readonly getByUserId: (userId: string) => Effect.Effect<readonly OAuthAccount[], AuthError>;
    readonly update: (account: OAuthAccount) => Effect.Effect<OAuthAccount, AuthError>;
    readonly linkToUser: (userId: string, account: OAuthAccount) => Effect.Effect<void, AuthError>;
    readonly unlinkFromUser: (userId: string, provider: string) => Effect.Effect<void, AuthError>;
    readonly delete: (provider: string, providerId: string) => Effect.Effect<void, AuthError>;
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
