/**
 * OAuth-style scope helpers.
 *
 * OAuth 2.0 access tokens carry a space-delimited list of granted scopes (for
 * example `"read:user write:repo"`). These utilities parse and check such
 * scopes for authorization decisions. The boolean helpers accept granted scopes
 * either as a raw space-delimited string or as any iterable of scope strings.
 */

import { Effect } from "effect";
import * as Errors from "../Errors.ts";

/**
 * Parse a space-delimited scope string into an array of scopes, dropping empty
 * entries. Splitting on any run of whitespace tolerates extra spaces.
 */
export const parseScopes = (scope: string): readonly string[] =>
  scope.split(/\s+/).filter((s) => s.length > 0);

/**
 * Format an iterable of scopes into a single space-delimited string.
 */
export const formatScopes = (scopes: Iterable<string>): string => [...scopes].join(" ");

const toSet = (granted: string | Iterable<string>): ReadonlySet<string> =>
  new Set(typeof granted === "string" ? parseScopes(granted) : granted);

/**
 * Check whether the granted scopes include the required scope.
 */
export const hasScope = (granted: string | Iterable<string>, required: string): boolean =>
  toSet(granted).has(required);

/**
 * Check whether the granted scopes include *all* of the required scopes.
 */
export const hasAllScopes = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): boolean => {
  const set = toSet(granted);
  for (const scope of required) {
    if (!set.has(scope)) return false;
  }
  return true;
};

/**
 * Check whether the granted scopes include *at least one* of the required
 * scopes.
 */
export const hasAnyScope = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): boolean => {
  const set = toSet(granted);
  for (const scope of required) {
    if (set.has(scope)) return true;
  }
  return false;
};

/**
 * Require a single scope, failing with `InsufficientScopeError` if it is not
 * granted.
 */
export const requireScope = (
  granted: string | Iterable<string>,
  required: string,
): Effect.Effect<void, Errors.InsufficientScopeError> =>
  hasScope(granted, required)
    ? Effect.void
    : Effect.fail(
        new Errors.InsufficientScopeError({
          message: `Insufficient scope: requires "${required}"`,
          requiredScope: required,
          grantedScopes: [...toSet(granted)],
        }),
      );

/**
 * Require all of the given scopes, failing with `InsufficientScopeError` listing
 * the missing scopes if any are not granted.
 */
export const requireAllScopes = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): Effect.Effect<void, Errors.InsufficientScopeError> => {
  const set = toSet(granted);
  const missing = [...required].filter((scope) => !set.has(scope));

  return missing.length === 0
    ? Effect.void
    : Effect.fail(
        new Errors.InsufficientScopeError({
          message: `Insufficient scope: missing [${missing.join(", ")}]`,
          requiredScope: missing.join(" "),
          grantedScopes: [...set],
        }),
      );
};
