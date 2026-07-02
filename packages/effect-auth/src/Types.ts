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
 * Configuration for session management
 */
export interface SessionConfig {
  readonly sessionExpiresIn: {
    readonly activePeriod: number; // milliseconds
    readonly idlePeriod: number; // milliseconds
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
