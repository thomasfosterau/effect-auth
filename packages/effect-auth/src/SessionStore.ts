import { Context, Effect } from "effect";
import type * as Types from "./Types.ts";
import * as Errors from "./Errors.ts";

/**
 * Tag for SessionStore service
 *
 * Session store interface for managing session persistence.
 *
 * **All `session.id` values and `sessionId` parameters at this layer are
 * SHA-256 hex digests** (produced by `hashToken` from `effect-auth`). The raw
 * bearer token is never persisted; only its hash is stored so that a stolen
 * database cannot be used to replay sessions.
 *
 * Users should implement this interface with their preferred storage backend
 * (e.g., Redis, PostgreSQL, MongoDB, etc.)
 */
export class SessionStore extends Context.Service<
  SessionStore,
  {
    /**
     * Create a new session. `session.id` must be the SHA-256 hash of the raw
     * bearer token.
     */
    readonly create: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

    /**
     * Get a session by its token hash, or `null` when no such session exists.
     */
    readonly get: (sessionId: string) => Effect.Effect<Types.Session | null, Errors.AuthError>;

    /**
     * Update a session
     */
    readonly update: (session: Types.Session) => Effect.Effect<Types.Session, Errors.AuthError>;

    /**
     * Delete a session
     */
    readonly delete: (sessionId: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * Delete all sessions for a user
     */
    readonly deleteByUserId: (userId: string) => Effect.Effect<void, Errors.AuthError>;

    /**
     * List all sessions for a user
     */
    readonly listByUserId: (
      userId: string,
    ) => Effect.Effect<ReadonlyArray<Types.Session>, Errors.AuthError>;
  }
>()("@effect-auth/SessionStore") {}
