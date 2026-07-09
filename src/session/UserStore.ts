import { Context, Effect } from "effect";
import type * as Types from "../Types.ts";
import * as Errors from "../Errors.ts";

/**
 * User store interface for managing user persistence
 * Users should implement this interface with their preferred storage backend
 */
export interface UserStore {
  /**
   * Get a user by ID, or `null` when no such user exists.
   */
  readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;

  /**
   * Get user credentials (hashed password), or `null` when the user does not
   * exist or has no password set.
   */
  readonly getCredentials: (userId: string) => Effect.Effect<string | null, Errors.AuthError>;
}

/**
 * Tag for UserStore service
 */
export const UserStore: Context.Service<UserStore, UserStore> =
  Context.Service("@effect-auth/UserStore");
