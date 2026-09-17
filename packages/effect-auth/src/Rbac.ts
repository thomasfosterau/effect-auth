/**
 * Role-based access control as **authoring sugar over the policy kernel**.
 *
 * RBAC is a way of *writing* policies, not a second engine. This module turns
 * the familiar flat configuration — who has which roles, which permissions a
 * role grants, which roles inherit which — into the two kernel artefacts a
 * decision is actually made from:
 *
 * - {@link policies} — one {@link Policy.DeclarativePolicy} per
 *   (role, permission) pair, so every rule authored the short way is pure
 *   data: storable, traceable, model-checkable, and partially evaluable.
 * - {@link entities} — the principal → role → parent-role fragment of the
 *   entity graph, so role assignment and role inheritance are ordinary
 *   hierarchy (`principal in Role::"editor"`) rather than a set union
 *   computed by a bespoke store.
 *
 * There is no `RoleStore` and no `checkPermission` behind this: the output
 * feeds `Authorizer`/`Policy.decide` like any other policy set. See
 * [ADR 0018](../../../docs/adr/0018-one-authorization-kernel.md) and
 * [the migration guide](../../../docs/guides/authorization-kernel-migration.md).
 *
 * @example One-call RBAC setup
 * ```ts
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
 * const program = Effect.gen(function* () {
 *   const authorizer = yield* Auth.Authorizer
 *   return yield* authorizer.check({
 *     action: "read",
 *     resource: Auth.Entity.ref("posts", "post-1"),
 *   })
 * }).pipe(Auth.CurrentPrincipal.provide(Auth.Entity.ref("User", "user-1")))
 * ```
 *
 * @module rbac
 */

import { Layer } from "effect";
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
   * `"User"` — set it when principals are, say, `ApiKey::"..."`.
   */
  readonly principalType?: string;
}

const entries = <V>(source: StringKeyed<V>): ReadonlyArray<readonly [string, V]> =>
  source instanceof Map ? [...source.entries()] : Object.entries(source);

const lookup = <V>(source: StringKeyed<V>, key: string): V | undefined =>
  source instanceof Map ? source.get(key) : (source as Record<string, V>)[key];

const dedupeRefs = (refs: ReadonlyArray<Entity.EntityRef>): ReadonlyArray<Entity.EntityRef> => {
  const seen = new Set<string>();
  return refs.filter((ref) => {
    const key = Entity.refKey(ref);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

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
  const byId = new Map<string, Policy.DeclarativePolicy>();
  for (const [role, permissions] of entries(config.rolePermissions)) {
    for (const permission of permissions) {
      const id = policyId(role, permission);
      if (byId.has(id)) continue;
      byId.set(
        id,
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
    }
  }
  return [...byId.values()];
};

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

const roleNames = (config: RbacConfig): ReadonlyArray<string> => {
  const names = new Set<string>();
  for (const [, roles] of entries(config.userRoles)) for (const role of roles) names.add(role);
  for (const [role] of entries(config.rolePermissions)) names.add(role);
  for (const [role, parents] of entries(config.roleHierarchy ?? {})) {
    names.add(role);
    for (const parent of parents) names.add(parent);
  }
  return [...names];
};

/**
 * Project the configuration into entities: one principal per `userRoles` key
 * with its roles as parents, and one `Role::` entity per role naming its
 * parent roles.
 *
 * Feed these to an {@link EntityResolver} (see {@link entityResolver}) — or
 * merge them with an application's own entities when policies also talk about
 * domain objects.
 */
export const entities = (config: RbacConfig): ReadonlyArray<Entity.Entity> => {
  const principalType = config.principalType ?? DefaultPrincipalType;
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
  const principalType = config.principalType ?? DefaultPrincipalType;
  const resourceTypes = new Set<string>();
  const actionResources = new Map<string, Set<string>>();

  for (const [, permissions] of entries(config.rolePermissions)) {
    for (const { resource, action } of permissions) {
      if (resource !== "*") resourceTypes.add(resource);
      if (action === "*") continue;
      const resources = actionResources.get(action) ?? new Set<string>();
      if (resource !== "*") resources.add(resource);
      actionResources.set(action, resources);
    }
  }

  const entityDecls: Record<string, AuthorizationModel.EntityTypeDecl> = {
    [principalType]: { memberOf: [RoleEntityType] },
    [RoleEntityType]: { memberOf: [RoleEntityType] },
  };
  for (const resource of resourceTypes) {
    entityDecls[resource] ??= {};
  }

  const actionDecls: Record<string, AuthorizationModel.ActionDecl> = {};
  for (const [action, resources] of actionResources) {
    actionDecls[action] = {
      appliesTo: { principal: [principalType], resource: [...resources] },
    };
  }

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
 * what the configuration says. Applications that mix RBAC with their own
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
