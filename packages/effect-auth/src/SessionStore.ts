import { Context, Effect } from "effect";
import type * as Types from "./Types.ts";
import * as Errors from "./Errors.ts";

/**
 * The columns a sliding refresh moves: {@link SessionStore}'s `touch`.
 */
export interface SessionTouch {
  /** The refresh's own time, also the instant the session must outlive. */
  readonly lastActivityAt: Date;
  readonly expiresAt: Date;
}

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
     * Slide a session's expiry in one atomic step: set `lastActivityAt` and
     * `expiresAt`, and nothing else, on the session with this id whose
     * `expiresAt` is not before `touch.lastActivityAt`. Returns the session as
     * stored afterwards, or `null` when no session matched (revoked or expired
     * meanwhile). It never creates a session, and never writes `attributes`, so
     * a concurrent `update` is not undone by a stale read.
     */
    readonly touch: (
      sessionId: string,
      touch: SessionTouch,
    ) => Effect.Effect<Types.Session | null, Errors.AuthError>;

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
