/**
 * Shared internal utilities.
 *
 * @module utils
 */

/** Trim surrounding whitespace and lower-case an email address. */
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();

/** Trim surrounding whitespace and lower-case a username. */
export const normalizeUsername = (username: string): string => username.trim().toLowerCase();
