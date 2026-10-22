/**
 * The policy kernel: `Policy` values, the pure decision procedure, and the
 * `enforce`/`check` entry points.
 *
 * A `Policy` is the primary object of the authorization framework
 * (`docs/better-auth-parity.md` §2.5, "Effect-native-first"). Policies come
 * in two kinds, and the types keep the difference visible:
 *
 * - {@link DeclarativePolicy} — pure data: a permit/forbid effect, PARC
 *   scopes (principal / action / resource), and an optional declarative
 *   `when` condition. Because it is data it is Schema-validated, storable,
 *   tenant-editable, and evaluated by a **pure, total** function over a
 *   pre-fetched {@link Entity.EntitySlice}.
 * - {@link CustomPolicy} — the first-class escape hatch: an arbitrary Effect
 *   predicate. Accepted everywhere policies are accepted, but opaque — not
 *   storable or analyzable, and its error/requirement channels surface in
 *   the `Policy<E, R>` type.
 *
 * ## Decision semantics (settled 2026-08-30)
 *
 * Default deny; forbid overrides permit; order-independent; the decision
 * carries its determining policies as a trace. Error posture deviates from
 * Cedar deliberately and is **fail-closed in both directions**: an erroring
 * permit cannot grant, and an erroring forbid DENIES (Cedar skips erroring
 * policies, which fails open for forbids). Errors are recorded in the trace.
 *
 * ## System principals are reached only by name
 *
 * A system principal (`System::"<name>"`, see the `System` module) is allowed
 * only by a permit that names it. The kernel enforces this, not each policy
 * author: a permit applies to a system principal only when its principal scope
 * names the `System` type (`eq`/`in` a `System::"…"` reference, or
 * `is("System")`). A permit scoped `any` (the default of {@link permit},
 * {@link permission}, {@link action} and {@link roleAtLeast}) or scoped to
 * another type or to a role (`in Role::"…"`) never matches one, and neither
 * does a {@link CustomPolicy} permit, whose predicate the kernel cannot see
 * into. Forbids are not narrowed: an unscoped forbid binds a system principal
 * like everyone else. For every other principal, scopes match as documented on
 * {@link Scope}.
 *
 * @module policy
 */
import { Array as Arr, Data, Effect, Match, Predicate, Schema } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import type * as Ladder from "./Ladder.ts";
import { type PermissionRef } from "./Permission.ts";

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/**
 * The question being decided, Cedar's PARC shape: may `principal` perform
 * `action` on `resource`, given `context`?
 */
export const PolicyRequest = Schema.Struct({
  principal: Entity.EntityRef,
  action: Entity.EntityRef,
  resource: Entity.EntityRef,
  context: Schema.Record(Schema.String, Entity.AttributeValue),
});
export type PolicyRequest = typeof PolicyRequest.Type;

/** Construct a {@link PolicyRequest}; `context` defaults to empty. */
export const request = (input: {
  readonly principal: Entity.EntityRef;
  readonly action: Entity.EntityRef;
  readonly resource: Entity.EntityRef;
  readonly context?: Readonly<Record<string, Entity.AttributeValue>>;
}): PolicyRequest => ({
  principal: input.principal,
  action: input.action,
  resource: input.resource,
  context: input.context ?? {},
});

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

/**
 * A PARC scope: which principals / actions / resources a policy applies to.
 * `any` matches everything; `eq` one entity; `in` an entity and its
 * transitive descendants (hierarchy membership, reflexive); `is` every
 * entity of a type.
 *
 * One exception, in a permit's principal position: a system principal
 * (`System::"<name>"`) is matched only by a scope that names the `System` type,
 * so `any`, `is("User")` and `in(Role::"…")` do not reach it (see the module
 * docs).
 */
export const Scope = Schema.Union([
  Schema.TaggedStruct("any", {}),
  Schema.TaggedStruct("eq", { ref: Entity.EntityRef }),
  Schema.TaggedStruct("in", { ref: Entity.EntityRef }),
  Schema.TaggedStruct("is", { entityType: Schema.String }),
]);
export type Scope = typeof Scope.Type;

/** Scope constructors. */
export const any: Scope = { _tag: "any" };
/** Scope matching exactly the referenced entity. */
export const eq = (ref: Entity.EntityRef): Scope => ({ _tag: "eq", ref });
/** Scope matching the referenced entity or any of its descendants in the entity slice. */
export const inScope = (ref: Entity.EntityRef): Scope => ({ _tag: "in", ref });
/** Scope matching any entity of the given type. */
export const isType = (entityType: string): Scope => ({ _tag: "is", entityType });

/**
 * Whether a principal scope names system principals: an `eq`/`in` scope on a
 * `System::"…"` reference, or `is("System")`. Only such a scope lets a permit
 * reach a system principal.
 */
const namesSystem = (scope: Scope): boolean =>
  Match.valueTags(scope, {
    any: () => false,
    eq: ({ ref }) => ref.type === Entity.systemType,
    in: ({ ref }) => ref.type === Entity.systemType,
    is: ({ entityType }) => entityType === Entity.systemType,
  });

/**
 * Whether a permit is barred from a request's principal: the principal is a
 * system principal and the permit cannot name it (a custom permit, or a
 * declarative one whose principal scope does not name `System`). The single
 * place the kernel keeps system principals default-deny under unscoped permits.
 */
const permitBarredFromSystem = (
  principal: Entity.EntityRef,
  principalScope: Scope | undefined,
): boolean =>
  principal.type === Entity.systemType &&
  (principalScope === undefined || !namesSystem(principalScope));

const scopeMatches = (slice: Entity.EntitySlice, scope: Scope, ref: Entity.EntityRef): boolean =>
  Match.valueTags(scope, {
    any: () => true,
    eq: (scoped) => Entity.refEquals(scoped.ref, ref),
    in: (scoped) => Entity.entityIn(slice, ref, scoped.ref),
    is: (scoped) => ref.type === scoped.entityType,
  });

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/** Whether a policy grants (`permit`) or overridingly revokes (`forbid`). */
export const PolicyEffect = Schema.Literals(["permit", "forbid"]);
export type PolicyEffect = typeof PolicyEffect.Type;

/**
 * The declarative subset: pure data, Schema-validated. This same shape is
 * the body of the stored policy document format (`PolicyStore`).
 */
export const DeclarativePolicy = Schema.TaggedStruct("DeclarativePolicy", {
  id: Schema.String,
  effect: PolicyEffect,
  principal: Scope,
  action: Scope,
  resource: Scope,
  when: Schema.optional(Condition.Condition),
  description: Schema.optional(Schema.String),
});
export type DeclarativePolicy = typeof DeclarativePolicy.Type;

/**
 * The escape hatch: an arbitrary Effect predicate deciding whether this
 * policy matches the request. A failure is recorded as an error outcome and
 * treated fail-closed. Not storable; `E`/`R` surface in `Policy<E, R>`.
 */
export interface CustomPolicy<E = never, R = never> {
  readonly _tag: "CustomPolicy";
  readonly id: string;
  readonly effect: PolicyEffect;
  readonly description?: string;
  readonly predicate: (
    request: PolicyRequest,
    slice: Entity.EntitySlice,
  ) => Effect.Effect<boolean, E, R>;
}

/** A policy value: declarative data, or an opaque custom predicate. */
export type Policy<E = never, R = never> = DeclarativePolicy | CustomPolicy<E, R>;

/** Options shared by the declarative policy constructors. */
export interface MakeOptions {
  readonly id: string;
  readonly principal?: Scope;
  readonly action?: Scope;
  readonly resource?: Scope;
  readonly when?: Condition.Condition;
  readonly description?: string;
}

const makeDeclarative = (effect: PolicyEffect, options: MakeOptions): DeclarativePolicy => ({
  _tag: "DeclarativePolicy",
  id: options.id,
  effect,
  principal: options.principal ?? any,
  action: options.action ?? any,
  resource: options.resource ?? any,
  ...(options.when !== undefined ? { when: options.when } : {}),
  ...(options.description !== undefined ? { description: options.description } : {}),
});

/**
 * Build a declarative permit policy (scopes default to `any`). A permit whose
 * principal scope is `any` does not reach a system principal: name it with
 * `System.grant`, `eq(System.ref(…))`, `inScope(System.ref(…))` or
 * `isType("System")`.
 */
export const permit = (options: MakeOptions): DeclarativePolicy =>
  makeDeclarative("permit", options);

/** Build a declarative forbid policy (scopes default to `any`). */
export const forbid = (options: MakeOptions): DeclarativePolicy =>
  makeDeclarative("forbid", options);

/**
 * Build a custom (opaque) policy from an arbitrary Effect predicate. The
 * predicate decides whether the policy *matches* the request; `effect`
 * (default `"permit"`) decides what a match means. A custom permit never
 * reaches a system principal (the kernel cannot see whether its predicate
 * names one); grant a system principal with a declarative `System.grant`.
 */
export const custom = <E = never, R = never>(options: {
  readonly id: string;
  readonly effect?: PolicyEffect;
  readonly description?: string;
  readonly predicate: (
    request: PolicyRequest,
    slice: Entity.EntitySlice,
  ) => Effect.Effect<boolean, E, R>;
}): CustomPolicy<E, R> => ({
  _tag: "CustomPolicy",
  id: options.id,
  effect: options.effect ?? "permit",
  ...(options.description !== undefined ? { description: options.description } : {}),
  predicate: options.predicate,
});

/**
 * Bridge from the flat `PermissionRef` world: a permit for action
 * `Action::"<action>"` on resources of type `<resource>`. `"*"` wildcards
 * map to `any` scopes, so existing admin/API-key grants translate directly.
 * The principal scope is `any`, which does not reach a system principal, so
 * even `{ action: "*", resource: "*" }` grants a system principal nothing.
 */
export const permission = (
  ref: PermissionRef,
  options?: { readonly id?: string },
): DeclarativePolicy =>
  permit({
    id: options?.id ?? `permission:${ref.resource}:${ref.action}`,
    action: ref.action === "*" ? any : eq(Entity.ref("Action", ref.action)),
    resource: ref.resource === "*" ? any : isType(ref.resource),
  });

/**
 * RBAC as hierarchy: a permit for principals in `Role::"<roleId>"`,
 * optionally narrowed to an action/resource scope. It never reaches a system
 * principal: roles are for users (see `System`).
 */
export const role = (
  roleId: string,
  options?: Omit<MakeOptions, "id" | "principal"> & { readonly id?: string },
): DeclarativePolicy =>
  permit({
    id: options?.id ?? `role:${roleId}`,
    principal: inScope(Entity.ref("Role", roleId)),
    ...(options?.action !== undefined ? { action: options.action } : {}),
    ...(options?.resource !== undefined ? { resource: options.resource } : {}),
    ...(options?.when !== undefined ? { when: options.when } : {}),
    ...(options?.description !== undefined ? { description: options.description } : {}),
  });

/**
 * A permit for one named action (`Action::"<actionId>"`), optionally
 * narrowed further. The principal scope defaults to `any`, which does not
 * reach a system principal.
 */
export const action = (
  actionId: string,
  options?: Omit<MakeOptions, "id" | "action"> & { readonly id?: string },
): DeclarativePolicy =>
  permit({
    id: options?.id ?? `action:${actionId}`,
    action: eq(Entity.ref("Action", actionId)),
    ...(options?.principal !== undefined ? { principal: options.principal } : {}),
    ...(options?.resource !== undefined ? { resource: options.resource } : {}),
    ...(options?.when !== undefined ? { when: options.when } : {}),
    ...(options?.description !== undefined ? { description: options.description } : {}),
  });

/**
 * The declarative condition "the principal holds `min` or a more privileged
 * rung of `ladder`": `principal.<roleAttribute>` is one of
 * `ladder.atOrAbove(min)`.
 *
 * Written as array membership over the rungs rather than as a numeric
 * comparison on a rank, so the condition needs no rank attribute on the
 * principal and inherits the ladder's fail-closed posture from the kernel's
 * own: a role string off the ladder is simply not a member, and a principal
 * with no role attribute (anonymous, or an entity the resolver did not know)
 * is an evaluation error, which the decision treats fail-closed.
 *
 * @since 1.0.0
 * @category conditions
 */
export const roleAtLeastCondition = <Rung extends string>(
  ladder: Ladder.Ladder<Rung>,
  min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  options?: { readonly roleAttribute?: string },
): Condition.Condition =>
  Condition.contains(
    Condition.lit([...ladder.atOrAbove(min)]),
    Condition.attr("principal", options?.roleAttribute ?? "role"),
  );

/**
 * The ordered-ladder bridge into the kernel: a permit for every principal
 * holding `min` (a rung, or a named axis) or a more privileged rung,
 * optionally narrowed to an action/resource scope. The principal scope
 * defaults to `any`, which does not reach a system principal, whatever `role`
 * attribute the resolver gives it.
 *
 * Because it is an ordinary declarative policy, a ladder comparison is
 * storable in a `PolicyStore` and validated against an `AuthorizationModel`
 * like any other — declare the principal type's `role` attribute in the model
 * and scope the policy to that type (`principal: Policy.isType("User")`) for
 * the attribute to be checked. The zero-IO gates in `Guard.ts` decide the
 * same question from the same `ladder.atOrAbove(min)` set without a slice.
 *
 * @since 1.0.0
 * @category constructors
 */
export const roleAtLeast = <Rung extends string>(
  ladder: Ladder.Ladder<Rung>,
  min: NoInfer<Rung> | Ladder.Axis<NoInfer<Rung>>,
  options?: Omit<MakeOptions, "id"> & {
    readonly id?: string;
    /** The principal attribute holding the rung. Defaults to `"role"`. */
    readonly roleAttribute?: string;
  },
): DeclarativePolicy => {
  const ladderCondition = roleAtLeastCondition(ladder, min, options);
  const name = Predicate.isString(min) ? min : min.name;
  return permit({
    id: options?.id ?? `ladder:${name}`,
    ...(options?.principal !== undefined ? { principal: options.principal } : {}),
    ...(options?.action !== undefined ? { action: options.action } : {}),
    ...(options?.resource !== undefined ? { resource: options.resource } : {}),
    when:
      options?.when === undefined ? ladderCondition : Condition.and(ladderCondition, options.when),
    ...(options?.description !== undefined ? { description: options.description } : {}),
  });
};

/** Add (AND) a condition onto a declarative policy's `when` clause. */
export const when = (
  policy: DeclarativePolicy,
  condition: Condition.Condition,
): DeclarativePolicy => ({
  ...policy,
  when: policy.when === undefined ? condition : Condition.and(policy.when, condition),
});

// ---------------------------------------------------------------------------
// Decisions and traces
// ---------------------------------------------------------------------------

/** How one policy evaluated against the request. */
export interface PolicyOutcome {
  readonly policyId: string;
  readonly effect: PolicyEffect;
  readonly result: "matched" | "not-matched" | "error";
  readonly error?: string;
}

/**
 * The full decision: `allowed`, why (`reason`), the policies that determined
 * it, and every policy's outcome (the trace fed to audit hooks and spans).
 */
export interface Decision {
  readonly allowed: boolean;
  readonly reason: "forbid" | "permit" | "default-deny";
  readonly determining: ReadonlyArray<PolicyOutcome>;
  readonly outcomes: ReadonlyArray<PolicyOutcome>;
}

/** Raised by {@link enforce} when the decision is a deny. */
export class AuthorizationDeniedError extends Data.TaggedError("AuthorizationDeniedError")<{
  readonly message: string;
  readonly request: PolicyRequest;
  readonly decision: Decision;
}> {}

const combineOutcomes = (outcomes: ReadonlyArray<PolicyOutcome>): Decision => {
  // Fail-closed both ways: an errored forbid denies; an errored permit
  // cannot grant (it is simply not a determining permit).
  const denying = outcomes.filter(
    (outcome) =>
      outcome.effect === "forbid" && (outcome.result === "matched" || outcome.result === "error"),
  );
  if (Arr.isReadonlyArrayNonEmpty(denying)) {
    return { allowed: false, reason: "forbid", determining: denying, outcomes };
  }
  const permitting = outcomes.filter(
    (outcome) => outcome.effect === "permit" && outcome.result === "matched",
  );
  if (Arr.isReadonlyArrayNonEmpty(permitting)) {
    return { allowed: true, reason: "permit", determining: permitting, outcomes };
  }
  return { allowed: false, reason: "default-deny", determining: [], outcomes };
};

const evaluateDeclarative = (
  slice: Entity.EntitySlice,
  req: PolicyRequest,
  policy: DeclarativePolicy,
): PolicyOutcome => {
  const barred =
    policy.effect === "permit" && permitBarredFromSystem(req.principal, policy.principal);
  const applies =
    !barred &&
    scopeMatches(slice, policy.principal, req.principal) &&
    scopeMatches(slice, policy.action, req.action) &&
    scopeMatches(slice, policy.resource, req.resource);
  if (!applies) {
    return { policyId: policy.id, effect: policy.effect, result: "not-matched" };
  }
  if (policy.when === undefined) {
    return { policyId: policy.id, effect: policy.effect, result: "matched" };
  }
  const evaluated = Condition.evaluate(slice, req, policy.when);
  if (!evaluated.ok) {
    return {
      policyId: policy.id,
      effect: policy.effect,
      result: "error",
      error: evaluated.error.message,
    };
  }
  return {
    policyId: policy.id,
    effect: policy.effect,
    result: evaluated.value ? "matched" : "not-matched",
  };
};

/**
 * The pure decision procedure over declarative policies: deterministic,
 * total, order-independent, replayable from a logged slice + request.
 */
export const decidePure = (
  policies: ReadonlyArray<DeclarativePolicy>,
  req: PolicyRequest,
  slice: Entity.EntitySlice = Entity.emptySlice,
): Decision => combineOutcomes(policies.map((policy) => evaluateDeclarative(slice, req, policy)));

/**
 * Decide over a mixed policy set (declarative + custom). Custom predicate
 * failures never escape: they become `error` outcomes, treated fail-closed
 * by {@link Decision} combination. Only the custom policies' requirements
 * (`R`) remain. A custom permit is `not-matched` for a system principal
 * without running its predicate (see the module docs); a custom forbid runs
 * as usual.
 */
export const decide = <E, R>(
  policies: ReadonlyArray<Policy<E, R>>,
  req: PolicyRequest,
  slice: Entity.EntitySlice = Entity.emptySlice,
): Effect.Effect<Decision, never, R> =>
  Effect.forEach(
    policies,
    (policy): Effect.Effect<PolicyOutcome, never, R> => {
      if (Predicate.isTagged(policy, "DeclarativePolicy")) {
        return Effect.succeed(evaluateDeclarative(slice, req, policy));
      }
      // A custom permit cannot name a system principal in a way the kernel can
      // see, so it never reaches one; its predicate is not run for it.
      if (policy.effect === "permit" && permitBarredFromSystem(req.principal, undefined)) {
        return Effect.succeed<PolicyOutcome>({
          policyId: policy.id,
          effect: policy.effect,
          result: "not-matched",
        });
      }
      return policy.predicate(req, slice).pipe(
        Effect.map((matched): PolicyOutcome => ({
          policyId: policy.id,
          effect: policy.effect,
          result: matched ? "matched" : "not-matched",
        })),
        Effect.catch((error) =>
          Effect.succeed<PolicyOutcome>({
            policyId: policy.id,
            effect: policy.effect,
            result: "error",
            error: String(error),
          }),
        ),
      );
    },
    { concurrency: 1 },
  ).pipe(Effect.map(combineOutcomes));

/** Decide and return only whether the request is allowed. */
export const check = <E, R>(
  policies: ReadonlyArray<Policy<E, R>>,
  req: PolicyRequest,
  slice?: Entity.EntitySlice,
): Effect.Effect<boolean, never, R> =>
  Effect.map(decide(policies, req, slice), (decision) => decision.allowed);

/**
 * Decide and fail with {@link AuthorizationDeniedError} (carrying the full
 * decision trace) unless the request is allowed.
 */
export const enforce = <E, R>(
  policies: ReadonlyArray<Policy<E, R>>,
  req: PolicyRequest,
  slice?: Entity.EntitySlice,
): Effect.Effect<Decision, AuthorizationDeniedError, R> =>
  Effect.flatMap(decide(policies, req, slice), (decision) =>
    decision.allowed
      ? Effect.succeed(decision)
      : Effect.fail(
          new AuthorizationDeniedError({
            message: `Authorization denied: ${Entity.formatRef(req.principal)} may not ${Entity.formatRef(req.action)} on ${Entity.formatRef(req.resource)} (${decision.reason})`,
            request: req,
            decision,
          }),
        ),
  );
