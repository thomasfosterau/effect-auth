/**
 * System principals (`System::"<name>"`): the job or pipeline step that acts
 * with no person behind it. One is denied by default, allowed only what a
 * permit naming the `System` type grants ({@link grant}), never
 * short-circuited, and named in every decision log. Keep `Role` entities out of
 * `System` groups.
 *
 * @module system
 */
import { Data, Layer } from "effect";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Authorizer from "./Authorizer.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";

/**
 * The reserved entity type of system principals. Application principal types
 * (`Guard.make({ principalType })`) may not use it.
 *
 * @since 0.1.0
 * @category constants
 */
export const entityType = Entity.systemType;

/** `ref` was given an empty (or all-whitespace) name. */
class SystemPrincipalNameError extends Data.TaggedError("SystemPrincipalNameError")<{
  readonly message: string;
}> {}

/**
 * The entity reference of the named system principal: `System::"<name>"`.
 *
 * Throws on an empty name: a system principal with no name cannot be granted,
 * audited or told apart from another, so it is a construction error.
 *
 * @since 0.1.0
 * @category constructors
 */
export const ref = (name: string): Entity.EntityRef => {
  if (name.trim() === "") {
    throw new SystemPrincipalNameError({
      message: "System.ref: a system principal needs a non-empty name",
    });
  }
  return Entity.ref(entityType, name);
};

/**
 * Whether an entity reference names a system principal (its type is `System`).
 * Reads the type only: it does not say whether any policy grants it anything.
 *
 * @since 0.1.0
 * @category predicates
 */
export const isSystem = (principal: Entity.EntityRef): boolean => principal.type === entityType;

/**
 * Run an effect as the named system principal: provides
 * {@link Authorizer.CurrentPrincipal} as `System::"<name>"`, so
 * `Authorizer.authorize`/`check` decide for that job.
 *
 * @since 0.1.0
 * @category combinators
 */
export const provide = (name: string) => Authorizer.CurrentPrincipal.provide(ref(name));

/**
 * A layer providing {@link Authorizer.CurrentPrincipal} as `System::"<name>"`,
 * for a job runtime that holds one principal for its whole lifetime.
 *
 * @since 0.1.0
 * @category constructors
 */
export const layer = (name: string): Layer.Layer<Authorizer.CurrentPrincipal> =>
  Layer.succeed(Authorizer.CurrentPrincipal, ref(name));

/**
 * The declaration a model needs for system principals to validate: add it as
 * the `System` entry of `AuthorizationModel.make({ entities })`. Without it,
 * a policy that names `System::"<name>"` fails validation with an undeclared
 * entity type.
 *
 * @since 0.1.0
 * @category constants
 */
export const declaration: AuthorizationModel.EntityTypeDecl = {};

/** The options of {@link grant}. */
export interface GrantOptions {
  /** The policy id. It appears in every decision trace that the grant determines. */
  readonly id: string;
  /** The action the grant allows, as an `Action::"<action>"` id. */
  readonly action: string;
  /** The resources the grant allows the action on. `Policy.any` is every resource. */
  readonly resource: Policy.Scope;
  /** An optional extra condition on the request, ANDed onto the grant. */
  readonly when?: Condition.Condition | undefined;
  /** An optional human-readable description. */
  readonly description?: string | undefined;
}

/**
 * The explicit grant for a system principal: a permit for `System::"<name>"`
 * to perform one action on one resource scope, and nothing else. The action and
 * resource are required, so a grant always names what it allows. A grant wider
 * than one action is written as several grants, each with its own id.
 *
 * @example
 * ```ts
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const grant = Auth.System.grant("translation-pipeline", {
 *   id: "translation-pipeline:write-translations",
 *   action: "page-translation:write",
 *   resource: Auth.Policy.isType("PageTranslation"),
 * })
 * ```
 *
 * @since 0.1.0
 * @category constructors
 */
export const grant = (name: string, options: GrantOptions): Policy.DeclarativePolicy =>
  Policy.permit({
    id: options.id,
    principal: Policy.eq(ref(name)),
    action: Policy.eq(Entity.ref("Action", options.action)),
    resource: options.resource,
    ...(options.when !== undefined ? { when: options.when } : {}),
    ...(options.description !== undefined ? { description: options.description } : {}),
  });
