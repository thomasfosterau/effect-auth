import { Context, Effect, Layer } from "effect";
import * as Errors from "../Errors.ts";
import { formatPermission, permissionMatches, type PermissionRef } from "./Permission.ts";

/**
 * Authorization policy interface
 * Users should implement this to define their authorization rules
 */
export class AuthorizationPolicy extends Context.Service<
  AuthorizationPolicy,
  {
    /**
     * Check if a user has permission to perform an action on a resource
     */
    readonly checkPermission: (
      userId: string,
      resource: string,
      action: string,
    ) => Effect.Effect<boolean, never>;
  }
>()("@effect-auth/AuthorizationPolicy") {
  /**
   * Construct a Layer providing this service.
   */
  static readonly layer = () => Layer.effect(AuthorizationPolicy, make());
}

/**
 * Simple role-based authorization policy
 * This is a basic implementation that users can extend or replace
 */
export class RoleStore extends Context.Service<
  RoleStore,
  {
    /**
     * Get roles for a user
     */
    readonly getUserRoles: (userId: string) => Effect.Effect<readonly string[], never>;

    /**
     * Get permissions for a role
     */
    readonly getRolePermissions: (
      role: string,
    ) => Effect.Effect<readonly { resource: string; action: string }[], never>;
  }
>()("@effect-auth/RoleStore") {}

/**
 * Create a simple role-based authorization policy
 */
export const make = (): Effect.Effect<typeof AuthorizationPolicy.Service, never, RoleStore> =>
  Effect.gen(function* () {
    const roleStore = yield* RoleStore;

    return {
      checkPermission: (userId, resource, action) =>
        Effect.gen(function* () {
          // Get user roles
          const roles = yield* roleStore.getUserRoles(userId);

          // Check if any role has the required permission
          for (const role of roles) {
            const permissions = yield* roleStore.getRolePermissions(role);

            const hasPermission = permissions.some((p) =>
              permissionMatches(p, { resource, action }),
            );

            if (hasPermission) {
              return true;
            }
          }

          return false;
        }),
    };
  });

/**
 * Utility function to require permission
 * Throws PermissionDeniedError if permission is not granted
 */
export const requirePermission = (
  userId: string,
  resource: string,
  action: string,
): Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy> =>
  Effect.gen(function* () {
    const policy = yield* AuthorizationPolicy;
    const hasPermission = yield* policy.checkPermission(userId, resource, action);

    if (!hasPermission) {
      return yield* Effect.fail(
        new Errors.PermissionDeniedError({
          message: `Permission denied: ${action} on ${resource}`,
          resource,
          action,
        }),
      );
    }
  });

// ---------------------------------------------------------------------------
// Policy combinators
// ---------------------------------------------------------------------------

/**
 * A policy that grants every permission.
 */
export const allowAll: typeof AuthorizationPolicy.Service = {
  checkPermission: () => Effect.succeed(true),
};

/**
 * A policy that denies every permission.
 */
export const denyAll: typeof AuthorizationPolicy.Service = {
  checkPermission: () => Effect.succeed(false),
};

/**
 * Build a policy from an arbitrary predicate.
 *
 * This is the building block for attribute-based (ABAC) rules: the predicate can
 * close over any data needed to make a decision. Note the predicate operates on
 * `(userId, resource, action)` with no extra context — per-instance/ownership
 * checks that need to load a specific record are best done at the call site and
 * composed here with {@link allOf} / {@link anyOf}.
 */
export const fromPredicate = (
  check: (userId: string, resource: string, action: string) => Effect.Effect<boolean, never>,
): typeof AuthorizationPolicy.Service => ({
  checkPermission: check,
});

/**
 * Combine policies with logical OR: permission is granted if *any* policy grants
 * it. Evaluation short-circuits on the first grant. With no policies, denies.
 */
export const anyOf = (
  ...policies: readonly (typeof AuthorizationPolicy.Service)[]
): typeof AuthorizationPolicy.Service => ({
  checkPermission: (userId, resource, action) =>
    Effect.gen(function* () {
      for (const policy of policies) {
        if (yield* policy.checkPermission(userId, resource, action)) {
          return true;
        }
      }
      return false;
    }),
});

/**
 * Combine policies with logical AND: permission is granted only if *every*
 * policy grants it. Evaluation short-circuits on the first denial. With no
 * policies, grants (vacuously true).
 */
export const allOf = (
  ...policies: readonly (typeof AuthorizationPolicy.Service)[]
): typeof AuthorizationPolicy.Service => ({
  checkPermission: (userId, resource, action) =>
    Effect.gen(function* () {
      for (const policy of policies) {
        if (!(yield* policy.checkPermission(userId, resource, action))) {
          return false;
        }
      }
      return true;
    }),
});

/**
 * Negate a policy: grants what the wrapped policy denies and vice versa.
 */
export const not = (
  policy: typeof AuthorizationPolicy.Service,
): typeof AuthorizationPolicy.Service => ({
  checkPermission: (userId, resource, action) =>
    Effect.map(policy.checkPermission(userId, resource, action), (granted) => !granted),
});

// ---------------------------------------------------------------------------
// Ergonomic guards (read the policy from context)
// ---------------------------------------------------------------------------

/**
 * Check a permission against the `typeof AuthorizationPolicy.Service` in context,
 * returning a boolean instead of failing.
 */
export const can = (
  userId: string,
  resource: string,
  action: string,
): Effect.Effect<boolean, never, AuthorizationPolicy> =>
  Effect.gen(function* () {
    const policy = yield* AuthorizationPolicy;
    return yield* policy.checkPermission(userId, resource, action);
  });

/**
 * Require that the user has *all* of the given permissions. Fails with
 * `PermissionDeniedError` for the first permission that is not granted.
 */
export const requireAllPermissions = (
  userId: string,
  permissions: readonly PermissionRef[],
): Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy> =>
  Effect.forEach(
    permissions,
    ({ resource, action }) => requirePermission(userId, resource, action),
    {
      discard: true,
    },
  );

/**
 * Require that the user has *at least one* of the given permissions. Fails with
 * `PermissionDeniedError` only if none are granted.
 */
export const requireAnyPermission = (
  userId: string,
  permissions: readonly PermissionRef[],
): Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy> =>
  Effect.gen(function* () {
    const policy = yield* AuthorizationPolicy;

    for (const { resource, action } of permissions) {
      if (yield* policy.checkPermission(userId, resource, action)) {
        return;
      }
    }

    const first = permissions[0];
    const summary = permissions.map(formatPermission).join(", ");
    return yield* Effect.fail(
      new Errors.PermissionDeniedError({
        message:
          permissions.length === 0
            ? "Permission denied: no permissions provided"
            : `Permission denied: requires any of [${summary}]`,
        resource: first?.resource ?? "*",
        action: first?.action ?? "*",
      }),
    );
  });
