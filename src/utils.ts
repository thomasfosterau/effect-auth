/**
 * Shared internal utilities.
 *
 * @module utils
 */


/** Trim surrounding whitespace and lower-case an email address. */
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();
