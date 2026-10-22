/**
 * OAuth-style scope helpers.
 *
 * OAuth 2.0 access tokens carry a space-delimited list of granted scopes (for
 * example `"read:user write:repo"`). These utilities parse and check such
 * scopes for authorization decisions. The boolean helpers accept granted scopes
 * either as a raw space-delimited string or as any iterable of scope strings.
 */

import { Array as Arr, Effect, Predicate, String as Str } from "effect";
import * as Errors from "../Errors.ts";

/**
 * Parse a space-delimited scope string into an array of scopes, dropping empty
 * entries. Splitting on any run of whitespace tolerates extra spaces.
 */
export const parseScopes = (scope: string): readonly string[] =>
  Arr.filter(scope.split(/\s+/), Str.isNonEmpty);

/**
 * Format an iterable of scopes into a single space-delimited string.
 */
export const formatScopes = (scopes: Iterable<string>): string => [...scopes].join(" ");

// The granted scopes, deduplicated in first-seen order (the order
// `grantedScopes` reports them in).
const toScopeList = (granted: string | Iterable<string>): ReadonlyArray<string> =>
  Arr.dedupe(Predicate.isString(granted) ? parseScopes(granted) : granted);

/**
 * Check whether the granted scopes include the required scope.
 */
export const hasScope = (granted: string | Iterable<string>, required: string): boolean =>
  Arr.contains(toScopeList(granted), required);

/**
 * Check whether the granted scopes include *all* of the required scopes.
 * Returns `false` when `required` is empty (consistent with `hasAnyScope`).
 */
export const hasAllScopes = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): boolean => {
  const set = toScopeList(granted);
  const requiredArr = Arr.fromIterable(required);
  return (
    Arr.isReadonlyArrayNonEmpty(requiredArr) &&
    Arr.every(requiredArr, (scope) => Arr.contains(set, scope))
  );
};

/**
 * Check whether the granted scopes include *at least one* of the required
 * scopes.
 */
export const hasAnyScope = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): boolean => {
  const set = toScopeList(granted);
  return Arr.some(Arr.fromIterable(required), (scope) => Arr.contains(set, scope));
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
          grantedScopes: [...toScopeList(granted)],
        }),
      );

/**
 * Require all of the given scopes, failing with `InsufficientScopeError` listing
 * the missing scopes if any are not granted, or immediately when `required` is
 * empty (consistent with `requireAnyScope` / `requireScope`).
 */
export const requireAllScopes = (
  granted: string | Iterable<string>,
  required: Iterable<string>,
): Effect.Effect<void, Errors.InsufficientScopeError> => {
  const set = toScopeList(granted);
  const requiredArr = [...required];

  if (Arr.isReadonlyArrayEmpty(requiredArr)) {
    return Effect.fail(
      new Errors.InsufficientScopeError({
        message: "Insufficient scope: no scopes provided",
        requiredScope: "",
        grantedScopes: [...set],
      }),
    );
  }

  const missing = Arr.filter(requiredArr, (scope) => !Arr.contains(set, scope));
  return Arr.match(missing, {
    onEmpty: () => Effect.void,
    onNonEmpty: (missing) =>
      Effect.fail(
        new Errors.InsufficientScopeError({
          message: `Insufficient scope: missing [${missing.join(", ")}]`,
          requiredScope: missing.join(" "),
          grantedScopes: [...set],
        }),
      ),
  });
};
