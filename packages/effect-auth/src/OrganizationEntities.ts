/**
 * The organization world, as authorization entities.
 *
 * `Organization.ts` answers permission questions inside one organization
 * (`checkPermission(userId, organizationId, "team:create")`). The policy
 * kernel (`Policy` / `Authorizer`) answers them over an entity graph. This module is the
 * bridge: it projects organizations, teams, memberships and roles into
 * {@link Entity} values so application policies can talk about them directly:
 *
 * ```ts
 * import { OrganizationEntities, Policy } from "@thomasfosterau/effect-auth"
 *
 * declare const orgId: string
 *
 * // "org admins may update anything scoped to their organization"
 * Policy.role(OrganizationEntities.orgRoleId(orgId, "admin"), {
 *   resource: Policy.inScope(OrganizationEntities.organizationRef(orgId)),
 * })
 * ```
 *
 * The projection, for the reference types it recognizes:
 *
 * - `User::"<userId>"` - parents `Org::"<organizationId>"` and
 *   `Role::"org:<organizationId>:<role>"` for every *active* membership
 *   (deactivated ones project nothing, matching `Organization.ts`), plus
 *   `Team::"<teamId>"` for every team membership.
 * - `Team::"<teamId>"` - attributes `{ name, organizationId }`, parent
 *   `Org::"<organizationId>"`.
 * - `Org::"<organizationId>"` - attributes `{ name, slug }`, no parents.
 *
 * Roles are namespaced per organization (`org:<organizationId>:<role>`) so
 * `admin` in one tenant is not `admin` in another. `Role::` references
 * themselves resolve to nothing: they carry no attributes and no parents, and
 * hierarchy checks only need them to appear as *parents* of the user, which
 * they do.
 *
 * Ancestors are included per the {@link EntityResolver} contract (a resolved
 * user drags in its organizations and teams, a resolved team its
 * organization), so `principal in Role::"org:o1:admin"` and
 * `resource in Org::"o1"` decide correctly from the returned slice alone.
 *
 * **Composition is out of scope:** this resolver answers only for the
 * reference types above and omits everything else. An application that also
 * resolves its own domain entities should merge slices itself - e.g. by
 * writing an `EntityResolver` that calls this one and concatenates the
 * result with its own - rather than expecting a combinator here.
 *
 * @module organization-entities
 */
import { Effect, Layer } from "effect";
import type * as Errors from "./Errors.ts";
import { OrganizationStore, isActiveMember } from "./Organization.ts";
import * as Entity from "./Entity.ts";
import { EntityResolver } from "./Authorizer.ts";

/** Entity type for organizations. */
export const OrganizationEntityType = "Org";
/** Entity type for teams. */
export const TeamEntityType = "Team";
/** Entity type for users (principals). */
export const UserEntityType = "User";
/** Entity type for roles (principal parents). */
export const RoleEntityType = "Role";

/**
 * The role entity id for a role inside one organization:
 * `org:<organizationId>:<role>`. Roles are namespaced per organization so
 * `admin` in one tenant never matches `admin` in another.
 */
export const orgRoleId = (organizationId: string, role: string): string =>
  `org:${organizationId}:${role}`;

/** `Org::"<organizationId>"`. */
export const organizationRef = (organizationId: string): Entity.EntityRef =>
  Entity.ref(OrganizationEntityType, organizationId);

/** `Team::"<teamId>"`. */
export const teamRef = (teamId: string): Entity.EntityRef => Entity.ref(TeamEntityType, teamId);

/** `User::"<userId>"`. */
export const userRef = (userId: string): Entity.EntityRef => Entity.ref(UserEntityType, userId);

/** `Role::"org:<organizationId>:<role>"`. */
export const roleRef = (organizationId: string, role: string): Entity.EntityRef =>
  Entity.ref(RoleEntityType, orgRoleId(organizationId, role));

/**
 * An {@link EntityResolver} backed by an {@link OrganizationStore}, projecting
 * users, teams and organizations as described in the module documentation.
 * Unknown references (including `Role::` and every application-defined type)
 * are omitted, which the kernel reads as "no attributes, no parents".
 */
export const organizationEntityResolver = (
  store: typeof OrganizationStore.Service,
): typeof EntityResolver.Service => {
  const resolveOrganization = (
    organizationId: string,
  ): Effect.Effect<Entity.Entity | null, Errors.AuthError> =>
    Effect.map(store.getOrganizationById(organizationId), (organization) =>
      organization === null
        ? null
        : Entity.entity(organizationRef(organization.id), {
            attributes: { name: organization.name, slug: organization.slug },
          }),
    );

  const resolveTeam = (teamId: string): Effect.Effect<Entity.Entity | null, Errors.AuthError> =>
    Effect.map(store.getTeam(teamId), (team) =>
      team === null
        ? null
        : Entity.entity(teamRef(team.id), {
            attributes: { name: team.name, organizationId: team.organizationId },
            parents: [organizationRef(team.organizationId)],
          }),
    );

  /**
   * A user's parents: one `Org::` and one `Role::` per membership, plus a
   * `Team::` per team membership. A user with no memberships still resolves
   * (to an entity with no parents) - absence of parents is the answer.
   *
   * Deactivated memberships are skipped: `Organization.ts` treats an inactive
   * member as a non-member for every permission question, and the policy
   * kernel has to agree - otherwise a deactivated owner would keep deciding
   * policies through `Role::"org:<id>:owner"`.
   */
  const resolveUser = (userId: string): Effect.Effect<Entity.Entity, Errors.AuthError> =>
    Effect.gen(function* () {
      const allMemberships = yield* store.listMembersByUser(userId);
      const memberships = allMemberships.filter(isActiveMember);
      const parents: Entity.EntityRef[] = [];
      for (const membership of memberships) {
        parents.push(organizationRef(membership.organizationId));
        parents.push(roleRef(membership.organizationId, membership.role));
      }
      const teamsPerOrganization = yield* Effect.forEach(memberships, (membership) =>
        store.listTeamsForMember(membership.organizationId, userId),
      );
      for (const teams of teamsPerOrganization) {
        for (const team of teams) parents.push(teamRef(team.id));
      }
      return Entity.entity(userRef(userId), { parents });
    });

  const resolveOne = (
    ref: Entity.EntityRef,
  ): Effect.Effect<Entity.Entity | null, Errors.AuthError> => {
    switch (ref.type) {
      case UserEntityType:
        return resolveUser(ref.id);
      case TeamEntityType:
        return resolveTeam(ref.id);
      case OrganizationEntityType:
        return resolveOrganization(ref.id);
      default:
        return Effect.succeed(null);
    }
  };

  return {
    resolve: Effect.fn("OrganizationEntities.resolve")(function* (
      refs: ReadonlyArray<Entity.EntityRef>,
    ) {
      // Breadth-first over the parent DAG so the slice carries the ancestors
      // the resolver contract promises (a user's teams, a team's organization).
      const resolved = new Map<string, Entity.Entity>();
      const seen = new Set<string>();
      let frontier = [...refs];
      while (frontier.length > 0) {
        const pending = frontier.filter((ref) => {
          const key = Entity.refKey(ref);
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        const entities = yield* Effect.forEach(pending, resolveOne);
        const next: Entity.EntityRef[] = [];
        for (const entity of entities) {
          if (entity === null) continue;
          resolved.set(Entity.refKey(entity.ref), entity);
          next.push(...entity.parents);
        }
        frontier = next;
      }
      return [...resolved.values()];
    }),
  };
};

/**
 * Layer providing {@link EntityResolver} from the {@link OrganizationStore} in
 * context.
 */
export const layer: Layer.Layer<EntityResolver, never, OrganizationStore> = Layer.effect(
  EntityResolver,
  Effect.gen(function* () {
    return organizationEntityResolver(yield* OrganizationStore);
  }),
);
