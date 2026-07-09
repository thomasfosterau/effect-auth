/**
 * Permission value helpers.
 *
 * A {@link PermissionRef} is a `{ resource, action }` pair describing either a
 * granted permission or a requested one. The `"*"` wildcard is supported in the
 * `resource` and/or `action` of a *granted* permission to match anything.
 *
 * These helpers are pure (no Effect, no dependencies) so they can be used in
 * stores, policies, tests, or plain application code.
 */

/**
 * A permission reference: a resource paired with an action.
 *
 * In a granted permission, `"*"` matches any resource or action. For example
 * `{ resource: "posts", action: "*" }` grants every action on `posts`, and
 * `{ resource: "*", action: "*" }` grants everything (superadmin).
 */
export interface PermissionRef {
  readonly resource: string;
  readonly action: string;
}

/**
 * Construct a {@link PermissionRef}.
 */
export const makePermission = (resource: string, action: string): PermissionRef => ({
  resource,
  action,
});

/**
 * Parse a `"resource:action"` string into a {@link PermissionRef}.
 *
 * The string is split on the first `:`. If there is no `:`, the whole string is
 * treated as the resource and the action defaults to `"*"`. Surrounding
 * whitespace is trimmed.
 *
 * @example
 * ```ts
 * import { parsePermission } from "effect-auth/authz"
 *
 * parsePermission("posts:read") // { resource: "posts", action: "read" }
 * parsePermission("posts:*") // { resource: "posts", action: "*" }
 * parsePermission("posts") // { resource: "posts", action: "*" }
 * ```
 */
export const parsePermission = (input: string): PermissionRef => {
  const trimmed = input.trim();
  const separator = trimmed.indexOf(":");

  if (separator === -1) {
    return { resource: trimmed, action: "*" };
  }

  return {
    resource: trimmed.slice(0, separator).trim(),
    action: trimmed.slice(separator + 1).trim(),
  };
};

/**
 * Format a {@link PermissionRef} as a `"resource:action"` string.
 */
export const formatPermission = (permission: PermissionRef): string =>
  `${permission.resource}:${permission.action}`;

/**
 * Check whether a `granted` permission satisfies a `requested` one.
 *
 * A `"*"` wildcard in the granted resource or action matches anything. The
 * requested permission is matched literally — wildcards there are not expanded.
 *
 * @example
 * ```ts
 * import { permissionMatches } from "effect-auth/authz"
 *
 * permissionMatches({ resource: "posts", action: "*" }, { resource: "posts", action: "read" }) // true
 * permissionMatches({ resource: "*", action: "*" }, { resource: "users", action: "delete" }) // true
 * permissionMatches({ resource: "posts", action: "read" }, { resource: "posts", action: "delete" }) // false
 * ```
 */
export const permissionMatches = (granted: PermissionRef, requested: PermissionRef): boolean => {
  const resourceMatches = granted.resource === "*" || granted.resource === requested.resource;
  const actionMatches = granted.action === "*" || granted.action === requested.action;
  return resourceMatches && actionMatches;
};
