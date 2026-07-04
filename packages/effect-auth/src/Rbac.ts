/**
 * In-memory {@link RoleStoreShape} builder for role-based access control (RBAC).
 *
 * This removes the boilerplate of hand-rolling a `RoleStore` from `Map`s and
 * adds optional role inheritance: a role can declare parent roles whose
 * permissions it inherits (resolved transitively, guarding against cycles).
 *
 * Pair the resulting store with {@link makeRoleBasedPolicy} (which understands
 * `"*"` wildcard permissions) for a complete RBAC setup.
 */

import { Effect } from "effect";
import type { RoleStoreShape } from "./Authorization.js";
import { formatPermission, type PermissionRef } from "./Permission.js";

/**
 * Either a plain object record or a `ReadonlyMap`, keyed by string.
 */
type StringKeyed<V> = ReadonlyMap<string, V> | Record<string, V>;

/**
 * Configuration for {@link makeInMemoryRoleStore}.
 */
export interface InMemoryRoleStoreConfig {
  /** Map of `userId` to the roles assigned to that user. */
  readonly userRoles: StringKeyed<readonly string[]>;
  /** Map of role name to the permissions directly granted by that role. */
  readonly rolePermissions: StringKeyed<readonly PermissionRef[]>;
  /**
   * Optional map of role name to parent roles. A role inherits all permissions
   * of its parents (transitively). Cycles are tolerated and resolved safely.
   */
  readonly roleHierarchy?: StringKeyed<readonly string[]>;
}

const lookup = <V>(source: StringKeyed<V>, key: string): V | undefined =>
  source instanceof Map ? source.get(key) : (source as Record<string, V>)[key];

/**
 * Create an in-memory {@link RoleStoreShape} from static configuration.
 *
 * The returned store is synchronous (its methods wrap results in
 * `Effect.succeed`). When `roleHierarchy` is provided, `getRolePermissions`
 * returns the union of a role's own permissions and those of all ancestor
 * roles, de-duplicated by `"resource:action"`.
 *
 * @example
 * ```ts
 * import { makeInMemoryRoleStore } from "effect-auth"
 *
 * const store = makeInMemoryRoleStore({
 *   userRoles: { "user-1": ["editor"] },
 *   rolePermissions: {
 *     viewer: [{ resource: "posts", action: "read" }],
 *     editor: [{ resource: "posts", action: "update" }],
 *   },
 *   roleHierarchy: { editor: ["viewer"] }, // editor also gets viewer's permissions
 * })
 * ```
 */
export const makeInMemoryRoleStore = (config: InMemoryRoleStoreConfig): RoleStoreShape => {
  const { userRoles, rolePermissions, roleHierarchy } = config;

  const directPermissions = (role: string): readonly PermissionRef[] =>
    lookup(rolePermissions, role) ?? [];

  const parents = (role: string): readonly string[] =>
    roleHierarchy === undefined ? [] : (lookup(roleHierarchy, role) ?? []);

  /** Collect a role and all of its ancestors, guarding against cycles. */
  const resolveRoles = (role: string): readonly string[] => {
    const seen = new Set<string>();
    const stack = [role];
    while (stack.length > 0) {
      const current = stack.pop()!;
      if (seen.has(current)) continue;
      seen.add(current);
      for (const parent of parents(current)) {
        if (!seen.has(parent)) stack.push(parent);
      }
    }
    return [...seen];
  };

  return {
    getUserRoles: (userId) => Effect.succeed(lookup(userRoles, userId) ?? []),

    getRolePermissions: (role) =>
      Effect.succeed(
        (() => {
          const byKey = new Map<string, PermissionRef>();
          for (const resolved of resolveRoles(role)) {
            for (const permission of directPermissions(resolved)) {
              byKey.set(formatPermission(permission), permission);
            }
          }
          return [...byKey.values()];
        })(),
      ),
  };
};
