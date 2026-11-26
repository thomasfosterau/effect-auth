/**
 * Role-based access control as authoring sugar over the policy kernel: {@link
 * policies} compiles roles and permissions into declarative policies, and
 * {@link entities} the principal-to-role graph, for `Authorizer`. Roles are for
 * users: `principalType: "System"` is refused. See ADR-0018 and
 * `docs/guides/authorization-kernel-migration.md`.
 *
 * @example One-call RBAC setup
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const rbac = Auth.Rbac.layer({
 *   userRoles: { "user-1": ["editor"] },
 *   rolePermissions: {
 *     viewer: [{ resource: "posts", action: "read" }],
 *     editor: [{ resource: "posts", action: "update" }],
 *     admin: [{ resource: "*", action: "*" }],
 *   },
 *   roleHierarchy: { editor: ["viewer"] }, // editor also gets viewer's grants
 * })
 *
 * const post = Auth.Entity.ref("posts", "post-1")
 *
 * const program = Effect.gen(function* () {
 *   const authorizer = yield* Auth.Authorizer
 *   // Inherited from viewer through the hierarchy.
 *   assert.equal(yield* authorizer.check({ action: "read", resource: post }), true)
 *   // The editor role grants update, and nothing grants delete to user-1.
 *   assert.equal(yield* authorizer.check({ action: "update", resource: post }), true)
 *   assert.equal(yield* authorizer.check({ action: "delete", resource: post }), false)
 * }).pipe(Auth.CurrentPrincipal.provide(Auth.Entity.ref("User", "user-1")), Effect.provide(rbac))
 *
 * await Effect.runPromise(program)
 * ```
 *
 * @module rbac
 */

import * as Schema from "effect/Schema";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import { Authorizer, EntityResolver, memoryEntityResolver } from "./Authorizer.ts";
import * as Entity from "./Entity.ts";
import type * as Errors from "./Errors.ts";
import { formatPermission, type PermissionRef } from "./Permission.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/**
 * Entity type for role entities (`Role::"editor"`). One of the two types the
 * kernel itself gives meaning to; roles are *parents* of principals.
 */
export const RoleEntityType = "Role";

/** Entity type for action entities (`Action::"read"`). */
export const ActionEntityType = "Action";

/** Default entity type for the principals named in {@link RbacConfig.userRoles}. */
export const DefaultPrincipalType = "User";

/** `Role::"<roleId>"`. */
export const roleRef = (roleId: string): Entity.EntityRef => Entity.ref(RoleEntityType, roleId);

/**
 * Either a plain object record or a `ReadonlyMap`, keyed by string.
 */
type StringKeyed<V> = ReadonlyMap<string, V> | Record<string, V>;

/**
 * Flat RBAC configuration: the short way to author a policy set.
 *
 * The shape is unchanged from the pre-kernel `RoleStore` builder, so existing
 * configuration objects carry over verbatim — what changed is what comes out
 * the other end.
 */
export interface RbacConfig {
  /** Map of `userId` to the roles assigned to that user. */
  readonly userRoles: StringKeyed<readonly string[]>;
  /** Map of role name to the permissions directly granted by that role. */
  readonly rolePermissions: StringKeyed<readonly PermissionRef[]>;
  /**
   * Optional map of role name to parent roles. A role inherits all permissions
   * of its parents, transitively: the parent link becomes a `Role -> Role`
   * edge in the entity graph, and the kernel's cycle-safe `in` check does the
   * walking. Cycles are tolerated.
   */
  readonly roleHierarchy?: StringKeyed<readonly string[]>;
  /**
   * Entity type for the principals in {@link userRoles}. Defaults to
   * `"User"` — set it when principals are, say, `ApiKey::"..."`. `"System"`
   * is refused: role assignment is for users, and a system principal is
   * allowed only what an explicit `System.grant` names (ADR-0019).
   */
  readonly principalType?: string;
}

/**
 * The configured principal type, refusing the reserved `System` type: a role
 * change must never widen what a job may do, so system principals hold no
 * roles. (The kernel enforces the same thing at decision time: a role permit,
 * `principal in Role::"…"`, never reaches a system principal, whatever parents
 * a resolver gives it.)
 */
class ReservedPrincipalTypeError extends Schema.TaggedError<
  ReservedPrincipalTypeError,
  { readonly brand: unique symbol }
>()("ReservedPrincipalTypeError", {
  message: Schema.String,
}) {}

const principalTypeOf = (config: RbacConfig): string => {
  const principalType = config.principalType ?? DefaultPrincipalType;
  if (principalType === Entity.systemType) {
    throw new ReservedPrincipalTypeError({
      message: `Rbac: principalType "${principalType}" is reserved for system principals, which hold no roles; grant a job with System.grant`,
    });
  }
  return principalType;
};

const isMap = <V>(source: StringKeyed<V>): source is ReadonlyMap<string, V> =>
  source instanceof Map;

const entries = <V>(source: StringKeyed<V>): ReadonlyArray<readonly [string, V]> =>
  isMap(source) ? Arr.fromIterable(source) : R.toEntries(source);

const lookup = <V>(source: StringKeyed<V>, key: string): V | undefined =>
  isMap(source) ? source.get(key) : Object.hasOwn(source, key) ? source[key] : undefined;

const dedupeRefs = (refs: ReadonlyArray<Entity.EntityRef>): ReadonlyArray<Entity.EntityRef> =>
  Arr.dedupeWith(refs, (a, b) => Entity.refKey(a) === Entity.refKey(b));

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/** The generated policy id for one (role, permission) grant. */
export const policyId = (role: string, permission: PermissionRef): string =>
  `rbac:${role}:${formatPermission(permission)}`;

/**
 * Compile `rolePermissions` into declarative permits — one per (role,
 * permission) pair, de-duplicated by {@link policyId}.
 *
 * The permission → scope mapping is the same one {@link Policy.permission}
 * uses, with the principal narrowed to the granting role:
 *
 * | `PermissionRef`                   | policy scopes                                                |
 * | --------------------------------- | ------------------------------------------------------------ |
 * | `{ resource: "posts", action: "read" }` | `principal in Role::"<role>"`, `action == Action::"read"`, `resource is posts` |
 * | `{ resource: "posts", action: "*" }`    | …`action` unscoped                                            |
 * | `{ resource: "*", action: "*" }`        | …`action` and `resource` unscoped (superadmin)                |
 *
 * Inherited permissions are deliberately *not* expanded here: inheritance is
 * carried by {@link entities} as `Role -> Role` hierarchy, so a child role
 * matches its parent's policy through `in` instead of duplicating the grant.
 */
export const policies = (config: RbacConfig): ReadonlyArray<Policy.DeclarativePolicy> => {
  const grants = Arr.flatMap(entries(config.rolePermissions), ([role, permissions]) =>
    Arr.map(permissions, (permission) => ({ role, permission, id: policyId(role, permission) })),
  );
  return Arr.map(
    Arr.dedupeWith(grants, (a, b) => a.id === b.id),
    ({ role, permission, id }) =>
      Policy.permit({
        id,
        principal: Policy.inScope(roleRef(role)),
        action:
          permission.action === "*"
            ? Policy.any
            : Policy.eq(Entity.ref(ActionEntityType, permission.action)),
        resource: permission.resource === "*" ? Policy.any : Policy.isType(permission.resource),
        description: `role "${role}" may ${formatPermission(permission)}`,
      }),
  );
};

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

const roleNames = (config: RbacConfig): ReadonlyArray<string> =>
  Arr.dedupe([
    ...Arr.flatMap(entries(config.userRoles), ([, roles]) => roles),
    ...Arr.map(entries(config.rolePermissions), ([role]) => role),
    ...Arr.flatMap(entries(config.roleHierarchy ?? {}), ([role, parents]) => [role, ...parents]),
  ]);

/**
 * Project the configuration into entities: one principal per `userRoles` key
 * with its roles as parents, and one `Role::` entity per role naming its
 * parent roles. Throws when `principalType` is `"System"`.
 *
 * Feed these to an {@link EntityResolver} (see {@link entityResolver}) — or
 * merge them with an application's own entities when policies also talk about
 * domain objects.
 */
export const entities = (config: RbacConfig): ReadonlyArray<Entity.Entity> => {
  const principalType = principalTypeOf(config);
  const hierarchy = config.roleHierarchy;
  const parentsOf = (role: string): readonly string[] =>
    hierarchy === undefined ? [] : (lookup(hierarchy, role) ?? []);

  const principals = entries(config.userRoles).map(([userId, roles]) =>
    Entity.entity(Entity.ref(principalType, userId), {
      parents: dedupeRefs(roles.map(roleRef)),
    }),
  );

  const roles = roleNames(config).map((role) =>
    Entity.entity(roleRef(role), { parents: dedupeRefs(parentsOf(role).map(roleRef)) }),
  );

  return [...principals, ...roles];
};

/**
 * An {@link EntityResolver} over {@link entities} — the in-memory counterpart
 * of a database-backed role lookup. Returns requested entities plus their
 * transitive ancestors, per the resolver contract.
 */
export const entityResolver = (config: RbacConfig): typeof EntityResolver.Service =>
  memoryEntityResolver(entities(config));

/** Layer providing {@link EntityResolver} from an RBAC configuration. */
export const entityResolverLayer = (config: RbacConfig): Layer.Layer<EntityResolver> =>
  Layer.succeed(EntityResolver)(entityResolver(config));

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/** A model's entity types by name, filled in as the grants are read. */
interface EntityDecls {
  [entityType: string]: AuthorizationModel.EntityTypeDecl;
}

/**
 * Derive an {@link AuthorizationModel.Model} from the configuration, so the
 * generated policies can be validated (and so an application declaring its
 * own model has a starting point to merge with).
 *
 * The derivation is mechanical: every non-wildcard resource string becomes an
 * entity type, every non-wildcard action becomes an action applying to the
 * principal type and to the resource types it is actually granted on, and
 * both the principal type and `Role` declare `memberOf: ["Role"]` — the
 * type-level statement that role assignment and role inheritance are
 * hierarchy edges.
 */
export const model = (config: RbacConfig): AuthorizationModel.Model => {
  const principalType = principalTypeOf(config);
  const grants = Arr.flatMap(entries(config.rolePermissions), ([, permissions]) => permissions);
  const resourcesOf = (scoped: ReadonlyArray<PermissionRef>): Array<string> =>
    Arr.dedupe(
      Arr.map(
        Arr.filter(scoped, ({ resource }) => resource !== "*"),
        ({ resource }) => resource,
      ),
    );
  const actions = Arr.dedupe(
    Arr.map(
      Arr.filter(grants, ({ action }) => action !== "*"),
      ({ action }) => action,
    ),
  );

  const baseEntityDecls: EntityDecls = {
    [principalType]: { memberOf: [RoleEntityType] },
    [RoleEntityType]: { memberOf: [RoleEntityType] },
  };
  const entityDecls = Arr.reduce(resourcesOf(grants), baseEntityDecls, (decls, resource) => {
    decls[resource] ??= {};
    return decls;
  });

  const baseActionDecls: Record<string, AuthorizationModel.ActionDecl> = {};
  const actionDecls = Arr.reduce(actions, baseActionDecls, (decls, action) => {
    decls[action] = {
      appliesTo: {
        principal: [principalType],
        resource: resourcesOf(Arr.filter(grants, (grant) => grant.action === action)),
      },
    };
    return decls;
  });

  return { entities: entityDecls, actions: actionDecls };
};

// ---------------------------------------------------------------------------
// Batteries-included layer
// ---------------------------------------------------------------------------

/**
 * The shortest path from a flat RBAC configuration to a working
 * {@link Authorizer}: derives the policies, the model and the entity
 * resolver, and wires them together.
 *
 * Stored policies are ignored (`useStore: false`) so the layer means exactly
 * what the configuration says. Throws when `principalType` is `"System"`:
 * role assignment is for users, and a system principal is granted with
 * `System.grant`. Applications that mix RBAC with their own
 * policies, a `PolicyStore` or a domain entity resolver should compose
 * {@link policies}, {@link model} and {@link entities} into their own
 * `Authorizer.layer(...)` instead.
 */
export const layer = (
  config: RbacConfig,
): Layer.Layer<Authorizer | EntityResolver, Errors.AuthError> =>
  Layer.provideMerge(
    Authorizer.layer({ policies: policies(config), model: model(config), useStore: false }),
    entityResolverLayer(config),
  );
