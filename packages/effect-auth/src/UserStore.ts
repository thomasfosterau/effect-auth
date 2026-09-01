import { Context, Effect } from "effect";
import type * as Types from "./Types.ts";
import * as Errors from "./Errors.ts";

/**
 * User store interface for managing user persistence
 * Users should implement this interface with their preferred storage backend
 */
export class UserStore extends Context.Service<
  UserStore,
  {
    /**
     * Get a user by ID, or `null` when no such user exists.
     */
    readonly get: (userId: string) => Effect.Effect<Types.User | null, Errors.AuthError>;
  }
>()("@effect-auth/UserStore") {}
