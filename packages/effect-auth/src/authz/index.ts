export {
  AuthorizationPolicy,
  RoleStore,
  requirePermission,
  allowAll,
  denyAll,
  fromPredicate,
  anyOf,
  allOf,
  not,
  can,
  requireAllPermissions,
  requireAnyPermission,
} from "./Authorization.ts";
export {
  type PermissionRef,
  parsePermission,
  formatPermission,
  permissionMatches,
} from "./Permission.ts";
export { type InMemoryRoleStoreConfig } from "./RBAC.ts";

// The policy kernel (namespaced: `Authz.Policy.permit`, `Authz.Condition.eq`,
// `Authz.Entity.ref`, ...). See docs/better-auth-parity.md §2.5.
export * as Entity from "./Entity.ts";
export * as Condition from "./Condition.ts";
export * as Policy from "./Policy.ts";
export * as Model from "./Model.ts";
export { AuthorizationDeniedError, type Decision, type PolicyOutcome } from "./Policy.ts";
export {
  CurrentPrincipal,
  EntityResolver,
  memoryEntityResolver,
  requestRefs,
  type AuthorizeInput,
  type AuthorizerConfig,
  PolicyValidationError,
  Authorizer,
} from "./Authorizer.ts";
