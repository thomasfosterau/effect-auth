import { Effect, Context } from "effect"
import * as Errors from "./errors.js"

/**
 * Authorization policy interface
 * Users should implement this to define their authorization rules
 */
export interface AuthorizationPolicy {
  /**
   * Check if a user has permission to perform an action on a resource
   */
  readonly checkPermission: (
    userId: string,
    resource: string,
    action: string
  ) => Effect.Effect<boolean, never>
}

/**
 * Tag for AuthorizationPolicy service
 */
export const AuthorizationPolicy = Context.GenericTag<AuthorizationPolicy>(
  "@effect-auth/AuthorizationPolicy"
)

/**
 * Simple role-based authorization policy
 * This is a basic implementation that users can extend or replace
 */
export interface RoleStore {
  /**
   * Get roles for a user
   */
  readonly getUserRoles: (userId: string) => Effect.Effect<readonly string[], never>
  
  /**
   * Get permissions for a role
   */
  readonly getRolePermissions: (
    role: string
  ) => Effect.Effect<readonly { resource: string; action: string }[], never>
}

/**
 * Tag for RoleStore service
 */
export const RoleStore = Context.GenericTag<RoleStore>("@effect-auth/RoleStore")

/**
 * Create a simple role-based authorization policy
 */
export const makeRoleBasedPolicy = (): Effect.Effect<
  AuthorizationPolicy,
  never,
  RoleStore
> =>
  Effect.gen(function* () {
    const roleStore = yield* RoleStore

    return {
      checkPermission: (userId, resource, action) =>
        Effect.gen(function* () {
          // Get user roles
          const roles = yield* roleStore.getUserRoles(userId)

          // Check if any role has the required permission
          for (const role of roles) {
            const permissions = yield* roleStore.getRolePermissions(role)
            
            const hasPermission = permissions.some(
              (p) => p.resource === resource && p.action === action
            )

            if (hasPermission) {
              return true
            }
          }

          return false
        })
    }
  })

/**
 * Utility function to require permission
 * Throws PermissionDeniedError if permission is not granted
 */
export const requirePermission = (
  userId: string,
  resource: string,
  action: string
): Effect.Effect<void, Errors.PermissionDeniedError, AuthorizationPolicy> =>
  Effect.gen(function* () {
    const policy = yield* AuthorizationPolicy
    const hasPermission = yield* policy.checkPermission(userId, resource, action)

    if (!hasPermission) {
      return yield* Effect.fail(
        new Errors.PermissionDeniedError({
          message: `Permission denied: ${action} on ${resource}`,
          resource,
          action
        })
      )
    }
  })
