/**
 * System principals: the background job, cron handler or pipeline step that
 * acts with no person behind it.
 *
 * A system principal is the entity `System::"<name>"`. The type `System` is
 * reserved for it and is distinct from every application's user type, so a
 * system principal can be neither mistaken for a user nor impersonate one. It is
 * provided as {@link Authorizer.CurrentPrincipal} exactly like a user, and it is
 * decided exactly like a user, with four properties:
 *
 * - **Denied by default.** A policy must name it before it is allowed anything.
 * - **Granted explicitly.** It is allowed what a policy grants and nothing else.
 *   {@link grant} writes that policy: a permit scoped to `System::"<name>"` that
 *   names one action and one resource scope. A grant is data, so it can be
 *   stored, validated against an `AuthorizationModel`, and found in a decision
 *   trace.
 * - **Never short-circuited.** There is no "system bypasses the kernel" branch,
 *   and no allow-all for system principals. Its decisions run the same policies
 *   as everyone's.
 * - **Named in every audit.** Each decision about it is logged with
 *   `System::"<name>"` and the policies that determined it, and a denial's error
 *   message names it (see {@link Authorizer}).
 *
 * Two consequences for policy authors. A permit whose principal scope is `any`
 * reaches a system principal too, so scope user policies to users
 * (`Policy.isType("User")`, or `Policy.eq(User::"…")`). And a forbid whose
 * condition reads a user attribute errors for a system principal, and an erroring
 * forbid denies, so scope forbids the same way. The rung and owner policies that
 * `Guard` builds are already scoped to the viewer's type.
 *
 * ```ts
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 *
 * const policies = [
 *   Auth.System.grant("billing-cron", {
 *     id: "billing-cron:charge-invoices",
 *     action: "invoice:charge",
 *     resource: Auth.Policy.isType("Invoice"),
 *   }),
 * ]
 *
 * // In the billing job: the job names itself, then calls the same gated operation.
 * const runBillingJob = Effect.gen(function* () {
 *   const authorizer = yield* Auth.Authorizer
 *   yield* authorizer.authorize({ action: "invoice:charge", resource: Auth.Entity.ref("Invoice", "inv-1") })
 * }).pipe(Auth.System.provide("billing-cron"))
 * ```
 *
 * @module system
 */
import { Layer } from "effect";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Authorizer from "./Authorizer.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";

/**
 * The reserved entity type of system principals. Application principal types
 * (`Guard.make({ principalType })`) may not use it.
 *
 * @since 1.0.0
 * @category constants
 */
export const entityType = Entity.systemType;

/**
 * The entity reference of the named system principal: `System::"<name>"`.
 *
 * Throws on an empty name: a system principal with no name cannot be granted,
 * audited or told apart from another, so it is a construction error.
 *
 * @since 1.0.0
 * @category constructors
 */
export const ref = (name: string): Entity.EntityRef => {
  if (name.trim() === "") {
    throw new Error("System.ref: a system principal needs a non-empty name");
  }
  return Entity.ref(entityType, name);
};

/**
 * Whether an entity reference names a system principal (its type is `System`).
 * Reads the type only: it does not say whether any policy grants it anything.
 *
 * @since 1.0.0
 * @category predicates
 */
export const isSystem = (principal: Entity.EntityRef): boolean => principal.type === entityType;

/**
 * Run an effect as the named system principal: provides
 * {@link Authorizer.CurrentPrincipal} as `System::"<name>"`, so
 * `Authorizer.authorize`/`check` decide for that job.
 *
 * @since 1.0.0
 * @category combinators
 */
export const provide = (name: string) => Authorizer.CurrentPrincipal.provide(ref(name));

/**
 * A layer providing {@link Authorizer.CurrentPrincipal} as `System::"<name>"`,
 * for a job runtime that holds one principal for its whole lifetime.
 *
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
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
