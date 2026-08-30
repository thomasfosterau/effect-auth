/**
 * Core types for the Effect Auth library.
 *
 * The central domain records (`User`, `Session`, `SessionWithUser`) are
 * defined as `Schema` structs so a single definition provides the TypeScript
 * type, runtime validation, and JSON serialization used by stores and the
 * HTTP protocol layer. Configuration shapes remain plain interfaces.
 */
import { Schema } from "effect";

/**
 * Arbitrary attribute bag for custom fields on users and sessions.
 * Core fields (email, name, ...) are first-class; anything app-specific
 * lives here.
 */
export const Attributes = Schema.Record(Schema.String, Schema.Unknown);
export type Attributes = typeof Attributes.Type;

/**
 * Represents a user in the authentication system.
 *
 * Core identity fields are first-class (mirroring the common auth data
 * model): `email` (unique, normalized lowercase), `emailVerified`, optional
 * `name` and `image`, plus `createdAt`/`updatedAt` timestamps. App-specific
 * fields go in `attributes`.
 */
export const User = Schema.Struct({
  id: Schema.String,
  email: Schema.String,
  emailVerified: Schema.Boolean,
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Date,
  updatedAt: Schema.Date,
  attributes: Attributes,
});
export type User = typeof User.Type;

/**
 * Represents an active session.
 */
export const Session = Schema.Struct({
  id: Schema.String,
  userId: Schema.String,
  expiresAt: Schema.Date,
  createdAt: Schema.Date,
  lastActivityAt: Schema.Date,
  attributes: Attributes,
});
export type Session = typeof Session.Type;

/**
 * Represents a session with its associated user.
 */
export const SessionWithUser = Schema.Struct({
  session: Session,
  user: User,
});
export type SessionWithUser = typeof SessionWithUser.Type;

/**
 * Configuration for session management.
 *
 * ### Dual-role field semantics
 *
 * The two core periods each serve a dual purpose — mirroring the Lucia v3
 * session model:
 *
 * | Field          | Role 1 — initial state      | Role 2 — ongoing renewal         |
 * |----------------|-----------------------------|----------------------------------|
 * | `activePeriod` | Initial `expiresAt` at creation | **Absolute max lifetime** — sessions are rejected once `now − createdAt > activePeriod`, regardless of recent activity. |
 * | `idlePeriod`   | Idle timeout — sessions are rejected when `now − lastActivityAt > idlePeriod` | **Renewal window** — on each valid request, `expiresAt` is extended to `min(now + idlePeriod, createdAt + activePeriod)`. |
 *
 * **Worked example** (`activePeriod = 30 d`, `idlePeriod = 14 d`):
 * - Day 0: session created, `expiresAt = Day 14`.
 * - Day 1: user is active → `expiresAt` extended to `Day 15`.
 * - Day 29 (last activity): `expiresAt` capped to `Day 30` (absolute max).
 * - Day 31: session rejected by `activePeriod` check even if the user visits daily.
 * - No activity for 14 d: session rejected by `idlePeriod` (idle timeout) first.
 *
 * ### Write-throttle (`updateAge`)
 *
 * By default, `validateSession` writes a refreshed `expiresAt` and
 * `lastActivityAt` to the session store on every request. For high-traffic
 * apps this is one database write per authenticated request.
 *
 * Set `updateAge` to throttle: the store is only updated once per `updateAge`
 * window. Expiry and idle checks still run on every call — only the refresh
 * *write* is skipped when the session was recently updated.
 *
 * The Lucia "extend only past halfway" heuristic is a good default:
 * `updateAge = idlePeriod / 2`. With `idlePeriod = 14 d` that means the
 * store is written at most once every 7 days for an active user.
 *
 * Defaults to `0` (write on every request).
 */
export interface SessionConfig {
  readonly sessionExpiresIn: {
    /**
     * Initial `expiresAt` at session creation, and the **absolute maximum
     * lifetime** — sessions whose `now − createdAt > activePeriod` are always
     * rejected. In milliseconds.
     */
    readonly activePeriod: number;
    /**
     * Idle timeout — sessions whose `now − lastActivityAt > idlePeriod` are
     * rejected. Also the **renewal window**: on each valid request `expiresAt`
     * is extended by `idlePeriod` (capped at `createdAt + activePeriod`). In
     * milliseconds.
     */
    readonly idlePeriod: number;
    /**
     * Minimum age (in milliseconds) of a session's `lastActivityAt` before
     * `validateSession` writes a refreshed record to the store. When the
     * session was updated more recently than `updateAge` ago, the store write
     * is skipped (saving one DB write per request for active users).
     *
     * Expiry and idle-timeout checks still run on every call — only the
     * refresh *write* is throttled.
     *
     * Default `0` — write on every request (no throttle).
     * Recommended: `idlePeriod / 2` (Lucia "past halfway" heuristic).
     */
    readonly updateAge?: number;
  };
}

/**
 * Represents credentials for authentication
 */
export interface Credentials {
  readonly userId: string;
  readonly password: string;
}

/**
 * Represents a hashed password with salt
 */
export interface HashedPassword {
  readonly hash: string;
  readonly algorithm: string;
}

/**
 * Permission check result
 */
export interface Permission {
  readonly resource: string;
  readonly action: string;
  readonly granted: boolean;
}
