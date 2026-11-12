/**
 * Core types for the Effect Auth library.
 *
 * The central domain records (`User`, `Session`, `SessionWithUser`) are
 * defined as `Schema` structs so a single definition provides the TypeScript
 * type, runtime validation, and JSON serialization used by stores and the
 * HTTP protocol layer. Configuration shapes remain plain interfaces.
 */
import type { Effect } from "effect";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import type * as Errors from "./Errors.ts";

/**
 * Any JSON value: `null`, a number, a boolean, a string, a readonly array of
 * JSON values or a {@link JsonObject}. The value type of every attribute,
 * metadata and claims bag the library stores or sends, since each one is
 * persisted and transmitted as JSON. Effect's `Schema.Json`, so the same
 * name validates one.
 */
export const Json: Schema.Codec<Json> = Schema.Json;
export type Json = null | number | boolean | string | ReadonlyArray<Json> | JsonObject;

/**
 * A readonly string-keyed record of {@link Json} values: an attribute,
 * metadata or claims bag. Effect's `Schema.JsonObject`. `Date`s, `undefined`
 * values, class instances and functions are not JSON; convert them first
 * (an ISO string or epoch milliseconds for a `Date`, an omitted key for
 * `undefined`).
 */
export const JsonObject: Schema.Codec<JsonObject> = Schema.JsonObject;
// A type literal rather than `Schema.JsonObject` itself: that interface shares
// its name with a value, which type-aware lint reads as a class instance.
export type JsonObject = { readonly [key: string]: Json };

/**
 * Arbitrary attribute bag for custom fields on users and sessions.
 * Core fields (email, name, ...) are first-class; anything app-specific
 * lives here, as JSON ({@link JsonObject}).
 */
export const Attributes = JsonObject;
export type Attributes = JsonObject;

/**
 * Represents a user in the authentication system.
 *
 * The `User` record is **surrogate-keyed**: it carries no natural key. Login
 * handles (email, username, phone) are first-class `Identifier` records (see
 * `Identifier.ts`) with global uniqueness on `(type, value)` — a user may
 * hold several, or none at all (passkey-only, anonymous, agent users).
 * Optional profile fields (`name`, `image`) and `createdAt`/`updatedAt`
 * timestamps are first-class; app-specific fields go in `attributes`.
 */
export const User = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  image: Schema.optional(Schema.String),
  createdAt: Schema.Date,
  updatedAt: Schema.Date,
  attributes: Attributes,
});
export type User = typeof User.Type;

/**
 * Represents an active session. Its `id` is the stored id: the SHA-256 digest
 * of the session token (`hashToken`), never the token itself, so a session
 * record is safe to log, serialize into a page or send to a browser. The raw
 * token exists only in the {@link IssuedSession} a sign-in returns, and in
 * the credential the client presents (#581).
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
 * Whether a session is an admin impersonation, one
 * `AdminService.impersonateUser` issued: it carries
 * `attributes.impersonatedBy`. The user did not earn it, so
 * `AccountLockoutPlugin` leaves the user's lockout standing when one is
 * issued (#678).
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { isImpersonationSession } from "@thomasfosterau/effect-auth"
 *
 * const session = {
 *   id: "digest",
 *   userId: "u-1",
 *   expiresAt: new Date(),
 *   createdAt: new Date(),
 *   lastActivityAt: new Date(),
 *   attributes: { impersonatedBy: "admin-1" },
 * }
 * assert.equal(isImpersonationSession(session), true)
 * assert.equal(isImpersonationSession({ ...session, attributes: {} }), false)
 * ```
 */
export const isImpersonationSession = (session: Session): boolean =>
  P.isString(session.attributes["impersonatedBy"]);

/**
 * Represents a session with its associated user.
 */
export const SessionWithUser = Schema.Struct({
  session: Session,
  user: User,
});
export type SessionWithUser = typeof SessionWithUser.Type;

/**
 * A session just issued: the stored record (its `id` the digest the store keys
 * it by) and the raw bearer `token` the client presents. `SessionService`'s
 * `createSession` returns it, and every sign-in result carries both fields.
 * The token is a credential: the HTTP tier puts it only in the httpOnly
 * session cookie and, in bearer mode, the `set-auth-token` header, never in a
 * response body (#581).
 */
export const IssuedSession = Schema.Struct({
  session: Session,
  token: Schema.String,
});
export type IssuedSession = typeof IssuedSession.Type;

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

/**
 * The wrong codes counted against one (address, purpose) pair of a one-time
 * code flow (email OTP, phone OTP): the failure budget that survives resends
 * (#590). A store keeps it apart from the code's record, so replacing,
 * expiring or deleting the code leaves it as it was; only a successful
 * verification clears it.
 */
export interface OtpFailures {
  /** Wrong codes since the last successful verification. */
  readonly count: number;
  /** When the latest one was counted, in epoch milliseconds. */
  readonly lastFailureAt: number;
}

/**
 * The failure-budget methods of `EmailOtpStore` and `PhoneOtpStore` (#590),
 * over the store's purposes `P`: `getFailures` reads a pair's
 * {@link OtpFailures} (`null` when it has none), `recordFailure` counts one
 * wrong code at `at` (epoch ms) and returns the budget after it, and
 * `clearFailures` forgets it.
 */
export interface OtpFailureBudget<P> {
  readonly getFailures: (
    address: string,
    purpose: P,
  ) => Effect.Effect<OtpFailures | null, Errors.AuthError>;
  readonly recordFailure: (
    address: string,
    purpose: P,
    at: number,
  ) => Effect.Effect<OtpFailures, Errors.AuthError>;
  readonly clearFailures: (address: string, purpose: P) => Effect.Effect<void, Errors.AuthError>;
}

/**
 * How a one-time code flow (`EmailOtpConfig.backoff`, `PhoneOtpConfig.backoff`)
 * delays sends to an (address, purpose) pair that keeps receiving wrong codes
 * (#590). Once the pair's wrong codes reach `freeFailures`, a send is refused
 * with `ResendTooSoonError` until `baseDelay * 2 ** (count - freeFailures)`,
 * capped at `maxDelay`, has passed since the latest wrong code. A successful
 * verification resets the count. There is no lockout: a send succeeds again
 * once the delay has passed, so an attacker can slow the owner down but never
 * lock them out.
 */
export interface OtpBackoffConfig {
  /** Wrong codes allowed before sends are delayed. Default `5`. */
  readonly freeFailures?: number | undefined;
  /** The first delay, in ms, doubled for each further wrong code. Default 60 000 (one minute). */
  readonly baseDelay?: number | undefined;
  /** The longest delay, in ms. Default 86 400 000 (one day). */
  readonly maxDelay?: number | undefined;
}

/**
 * The per-recipient send cap (#684): at most `max` messages to one address or
 * phone number for one purpose within `windowMs`, counted through the
 * `RateLimitStore`. A send past it fails with `RateLimitError` (`429` over
 * HTTP). It counts every request that reaches it, whether or not the address
 * has an account, so a capped request reveals nothing about which addresses
 * are registered. The services that take it (`recipientSendLimit`) default to
 * 5 sends per hour; `false` turns it off.
 */
export interface RecipientSendLimit {
  /** The sends one recipient may get for one purpose in a window. */
  readonly max: number;
  /** The window, in ms, from the first send counted in it. */
  readonly windowMs: number;
}
