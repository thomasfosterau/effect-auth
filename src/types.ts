/**
 * Core types for the Effect Auth library
 */

/**
 * Represents a user in the authentication system
 */
export interface User {
  readonly id: string
  readonly attributes: Record<string, unknown>
}

/**
 * Represents an active session
 */
export interface Session {
  readonly id: string
  readonly userId: string
  readonly expiresAt: Date
  readonly createdAt: Date
  readonly lastActivityAt: Date
  readonly attributes: Record<string, unknown>
}

/**
 * Represents a session with its associated user
 */
export interface SessionWithUser {
  readonly session: Session
  readonly user: User
}

/**
 * Configuration for session management
 */
export interface SessionConfig {
  readonly sessionExpiresIn: {
    readonly activePeriod: number // milliseconds
    readonly idlePeriod: number // milliseconds
  }
}

/**
 * Represents credentials for authentication
 */
export interface Credentials {
  readonly userId: string
  readonly password: string
}

/**
 * Represents a hashed password with salt
 */
export interface HashedPassword {
  readonly hash: string
  readonly algorithm: string
}

/**
 * Permission check result
 */
export interface Permission {
  readonly resource: string
  readonly action: string
  readonly granted: boolean
}
