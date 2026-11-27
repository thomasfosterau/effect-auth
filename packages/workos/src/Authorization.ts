/**
 * WorkOS roles in the core's authorization kernel. A session's `workos.role`
 * and `workos.roles` (from its verified access token) become `Role::` parents
 * of the signed-in `User::`, so `Auth.Rbac.policies` written for those role
 * slugs decide as they do over the core's own role tables. Organizations are
 * read-only here: membership and roles are managed in WorkOS.
 *
 * @since 0.1.0
 */
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Auth from "@thomasfosterau/effect-auth";
import { SessionAttribute } from "./Session.ts";

/**
 * The role slugs a session carries, `workos.role` first, without duplicates.
 *
 * @since 0.1.0
 * @category utils
 */
export const sessionRoles = (session: Auth.Types.Session): ReadonlyArray<string> => {
  const role = session.attributes[SessionAttribute.role];
  const roles = session.attributes[SessionAttribute.roles];
  return Arr.dedupe([
    ...(P.isString(role) && role !== "" ? [role] : []),
    ...(Array.isArray(roles) ? roles.filter((r): r is string => P.isString(r) && r !== "") : []),
  ]);
};

/**
 * Options for {@link entityResolverLayer}.
 *
 * @since 0.1.0
 * @category models
 */
export interface EntityResolverOptions {
  /** Role inheritance, as `Auth.Rbac`'s `roleHierarchy`: `{ admin: ["member"] }`. */
  readonly roleHierarchy?: Readonly<Record<string, ReadonlyArray<string>>>;
  /** The principal type the session's user is, `User` by default (`Auth.Rbac.DefaultPrincipalType`). */
  readonly principalType?: string;
}

/**
 * An `EntityResolver` that gives the current session's user its WorkOS roles
 * as parents. It reads `CurrentSession` when it resolves, so it knows only
 * the caller: any other `User::` it is asked for is unknown (no roles). Role
 * entities carry their `roleHierarchy` parents.
 *
 * @since 0.1.0
 * @category layers
 */
export const entityResolverLayer = (
  options: EntityResolverOptions = {},
): Layer.Layer<Auth.Authorizer.EntityResolver> => {
  const principalType = options.principalType ?? Auth.Rbac.DefaultPrincipalType;
  const hierarchy = options.roleHierarchy ?? {};
  const roleEntities = Arr.dedupe([...R.keys(hierarchy), ...R.values(hierarchy).flat()]).map(
    (role) =>
      Auth.Entity.entity(Auth.Rbac.roleRef(role), {
        parents: (hierarchy[role] ?? []).map(Auth.Rbac.roleRef),
      }),
  );
  return Layer.succeed(Auth.Authorizer.EntityResolver)({
    resolve: (refs) =>
      Effect.gen(function* () {
        const session = yield* Effect.serviceOption(Auth.SessionContext.CurrentSession);
        const caller = Option.map(session, (s) =>
          Auth.Entity.entity(Auth.Entity.ref(principalType, s.userId), {
            parents: sessionRoles(s).map(Auth.Rbac.roleRef),
          }),
        );
        const known = [...Option.toArray(caller), ...roleEntities];
        const extraRoles = Option.match(caller, {
          onNone: () => [],
          onSome: (entity) =>
            entity.parents
              .filter((parent) => !roleEntities.some((r) => Auth.Entity.refEquals(r.ref, parent)))
              .map((parent) => Auth.Entity.entity(parent)),
        });
        return yield* Auth.Authorizer.memoryEntityResolver([...known, ...extraRoles]).resolve(refs);
      }),
  });
};
