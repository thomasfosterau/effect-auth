/**
 * The Effect shell around the pure policy kernel: principal context, entity
 * slice resolution, and the batteries-included `Authorizer` service.
 *
 * Cedar's architecture split, Effect-natively: services fetch the entity
 * slice (an Effect); the decision over the slice is the pure function in
 * `Policy.ts`. Every decision is deterministic and replayable from the
 * `(request, slice)` pair the trace hooks see.
 *
 * @module authorizer
 */
import {
  Array as Arr,
  Context,
  Effect,
  HashMap,
  Layer,
  Match,
  MutableHashSet,
  Option,
  Predicate,
  Result,
} from "effect";
import * as Errors from "./Errors.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Policy from "./Policy.ts";
import * as PolicyStore from "./PolicyStore.ts";

// ---------------------------------------------------------------------------
// Principal context
// ---------------------------------------------------------------------------

/**
 * The authenticated principal for the current execution, as an entity
 * reference. Provided per-request (e.g. by the HTTP session middleware:
 * `User::"<userId>"`; an API key works the same way). A background job names
 * itself with `System.provide("<name>")`, which provides `System::"<name>"`.
 * `Authorizer.authorize`/`check` read it from context so call sites only
 * name the action and resource.
 */
export class CurrentPrincipal extends Context.Service<CurrentPrincipal, Entity.EntityRef>()(
  "@effect-auth/CurrentPrincipal",
) {
  /** Provide a principal for a scoped effect. */
  static readonly provide =
    (ref: Entity.EntityRef) =>
    <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, Exclude<R, CurrentPrincipal>> =>
      Effect.provideService(effect, CurrentPrincipal, ref);
}

/**
 * What kind of credential resolved {@link CurrentPrincipal}: an interactive
 * session (a human at a keyboard, cookie or bearer session token) versus a
 * machine credential (an API key, a service-to-service bearer token) acting
 * on the principal's behalf.
 *
 * A principal alone answers *who*; this answers *how they got in* — the
 * distinction a policy needs to say "an API key may act as this user, but
 * may not mint another API key" (epic #180: a credential changes WHO the
 * request is, never WHAT it may do, unless a policy explicitly extends that
 * trust). Kept as its own service rather than folded into the principal
 * entity or the session record: neither a bare `EntityRef` nor a machine
 * credential (which has no `Types.Session`) has a natural place to carry it,
 * and a separate tag lets non-HTTP callers (a worker, a CLI, an RPC handler)
 * provide it without fabricating either.
 */
export type CredentialClass = "interactive" | "machine";

/**
 * Context service carrying the {@link CredentialClass} of the credential that
 * resolved {@link CurrentPrincipal}. Optional: providers that never set it
 * (existing non-HTTP callers, tests) leave policies that don't ask about it
 * unaffected — `Authorizer.authorize`/`check` merge it into the decision's
 * `context.credentialClass` attribute when present, so declarative policies
 * can condition on it (`Condition.attr("context", "credentialClass")`)
 * without every call site restating it by hand.
 */
export class CurrentCredential extends Context.Service<CurrentCredential, CredentialClass>()(
  "@effect-auth/CurrentCredential",
) {
  /** Provide a credential class for a scoped effect. */
  static readonly provide =
    (credentialClass: CredentialClass) =>
    <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, Exclude<R, CurrentCredential>> =>
      Effect.provideService(effect, CurrentCredential, credentialClass);
}

// ---------------------------------------------------------------------------
// Slice resolution
// ---------------------------------------------------------------------------

/**
 * Resolves entities for authorization slices. Implementations MUST return,
 * for each requested reference they know, the entity **and its transitive
 * ancestors** (parents' entities, recursively) — hierarchy (`in`) checks
 * only see parents that made it into the slice. References the resolver
 * does not know are simply omitted (unknown entities have no attributes and
 * no parents).
 */
export class EntityResolver extends Context.Service<
  EntityResolver,
  {
    readonly resolve: (
      refs: ReadonlyArray<Entity.EntityRef>,
    ) => Effect.Effect<ReadonlyArray<Entity.Entity>, Errors.AuthError>;
  }
>()("@effect-auth/EntityResolver") {}

/**
 * An {@link EntityResolver} over a fixed entity collection (tests,
 * config-defined hierarchies). Returns the requested entities plus their
 * transitive ancestors, per the contract.
 */
export const memoryEntityResolver = (
  entities: ReadonlyArray<Entity.Entity>,
): typeof EntityResolver.Service => {
  const byKey = HashMap.fromIterable(entities.map((e) => [Entity.refKey(e.ref), e] as const));
  return {
    resolve: (refs) =>
      Effect.sync(() => {
        const seen = MutableHashSet.empty<string>();
        // Depth-first over a stack of pending refs: each step pops one ref and
        // emits its entity the first time it is found, queueing its parents.
        const steps = Arr.unfold([...refs], (queue) =>
          Option.map(
            Option.fromUndefinedOr(queue.pop()),
            (ref): readonly [Option.Option<Entity.Entity>, Array<Entity.EntityRef>] => {
              const key = Entity.refKey(ref);
              if (MutableHashSet.has(seen, key)) return [Option.none(), queue];
              const found = HashMap.get(byKey, key);
              if (Option.isNone(found)) return [Option.none(), queue];
              MutableHashSet.add(seen, key);
              queue.push(...found.value.parents);
              return [found, queue];
            },
          ),
        );
        return Arr.getSomes(steps);
      }),
  };
};

const operandRefs = (operand: Condition.Operand): ReadonlyArray<Entity.EntityRef> =>
  Predicate.isTagged(operand, "Lit") && Entity.isEntityValue(operand.value)
    ? [operand.value.__entity]
    : [];

const conditionRefs = (condition: Condition.Condition): ReadonlyArray<Entity.EntityRef> =>
  Match.valueTags(condition, {
    And: ({ conditions }) => Arr.flatMap(conditions, conditionRefs),
    Or: ({ conditions }) => Arr.flatMap(conditions, conditionRefs),
    Not: (not) => conditionRefs(not.condition),
    Eq: ({ left, right }) => [...operandRefs(left), ...operandRefs(right)],
    Compare: ({ left, right }) => [...operandRefs(left), ...operandRefs(right)],
    In: ({ left, right }) => [...operandRefs(left), ...operandRefs(right)],
    Contains: ({ collection, value }) => [...operandRefs(collection), ...operandRefs(value)],
    Has: (): ReadonlyArray<Entity.EntityRef> => [],
  });

/**
 * The references a decision needs resolved: the request's principal, action
 * and resource, plus every entity a declarative policy names in its scopes
 * or condition literals (custom policies receive the same slice but resolve
 * anything else themselves). Ancestors come from the resolver contract.
 */
export const requestRefs = <E, R>(
  policies: ReadonlyArray<Policy.Policy<E, R>>,
  request: Policy.PolicyRequest,
): ReadonlyArray<Entity.EntityRef> => {
  const refs: ReadonlyArray<Entity.EntityRef> = [
    request.principal,
    request.action,
    request.resource,
    ...Arr.flatMap(policies, (policy) => {
      if (!Predicate.isTagged(policy, "DeclarativePolicy")) return [];
      return [
        ...Arr.filterMap([policy.principal, policy.action, policy.resource], (scope) =>
          Predicate.isTagged(scope, "eq") || Predicate.isTagged(scope, "in")
            ? Result.succeed(scope.ref)
            : Result.failVoid,
        ),
        ...(policy.when !== undefined ? conditionRefs(policy.when) : []),
      ];
    }),
  ];
  const seen = MutableHashSet.empty<string>();
  return refs.filter((ref) => {
    const key = Entity.refKey(ref);
    if (MutableHashSet.has(seen, key)) return false;
    MutableHashSet.add(seen, key);
    return true;
  });
};

// ---------------------------------------------------------------------------
// The Authorizer service
// ---------------------------------------------------------------------------

/** The action/resource pair a call site names; the principal comes from context. */
export interface AuthorizeInput {
  readonly action: Entity.EntityRef | string;
  readonly resource: Entity.EntityRef;
  readonly context?: Readonly<Record<string, Entity.AttributeValue>>;
}

const toActionRef = (action: Entity.EntityRef | string): Entity.EntityRef =>
  Predicate.isString(action) ? Entity.ref("Action", action) : action;

/**
 * The audit record of a system principal's decision. A background job has no
 * request or session to log against, so its decisions are logged here, always,
 * with the principal's name and the policies that determined the outcome:
 * allows at info, denies at warning. Human decisions are not logged by this
 * module; the HTTP authorization middleware logs its own.
 *
 * Every kernel entry point that decides for a {@link CurrentPrincipal} calls
 * it: `Authorizer` here, and the `protectedField` schema guard
 * (`Protected.ts`), which passes `"resolver-error"` as the reason when its
 * slice could not be resolved and it denied without deciding. A no-op for any
 * principal that is not a system principal.
 *
 * @internal
 */
export const auditSystemDecision = (
  request: Policy.PolicyRequest,
  outcome: {
    readonly allowed: boolean;
    readonly reason: Policy.Decision["reason"] | "resolver-error";
    readonly determining: ReadonlyArray<Policy.PolicyOutcome>;
  },
): Effect.Effect<void> => {
  if (request.principal.type !== Entity.systemType) return Effect.void;
  const fields = {
    principal: Entity.formatRef(request.principal),
    action: Entity.formatRef(request.action),
    resource: Entity.formatRef(request.resource),
    allowed: outcome.allowed,
    reason: outcome.reason,
    policies: outcome.determining.map((determining) => determining.policyId),
  };
  return outcome.allowed
    ? Effect.logInfo("authorization.decision", fields)
    : Effect.logWarning("authorization.decision", fields);
};

/**
 * Configuration for {@link Authorizer.layer}.
 */
export interface AuthorizerConfig<E = unknown> {
  /** The static policy set every decision is made against. */
  readonly policies: ReadonlyArray<Policy.Policy<E, never>>;
  /**
   * Optional declared model. When present: declarative policies are
   * validated at layer construction (a layer build failure beats a policy
   * that can never match — or a forbid that always denies), and the model's
   * action entities are merged into every slice so action groups work.
   */
  readonly model?: AuthorizationModel.Model;
  /**
   * Read stored policies (a `PolicyStore`'s {@link effectivePolicies},
   * including instantiated template links) into every decision, on top of
   * the static `policies`. When a `PolicyStore` is in context at layer
   * construction this defaults to `true`; pass `false` to ignore it.
   * Stored policies are fetched per decision (edits apply immediately) and
   * are NOT validated against `model` at decision time — validate on write
   * with `AuthorizationModel.validatePolicies` / `validateTemplates`.
   */
  readonly useStore?: boolean;
}

/** Raised by `Authorizer.layer` when policies do not validate against the model. */
export class PolicyValidationError extends Errors.AuthError {}

/**
 * The authorization service: decides, checks and enforces requests against the configured policies (plus a `PolicyStore`'s, when one is in context).
 *
 * `check` returns a boolean; `authorize` fails with `AuthorizationDeniedError` carrying the decision trace. Build it with {@link Authorizer.layer}, or `Rbac.layer` for role-based policies.
 */
export class Authorizer extends Context.Service<
  Authorizer,
  {
    /** Decide a fully explicit request. Never fails: errors land in the trace. */
    readonly decideRequest: (
      request: Policy.PolicyRequest,
    ) => Effect.Effect<Policy.Decision, Errors.AuthError>;

    /**
     * Decide for the {@link CurrentPrincipal}, failing with
     * `AuthorizationDeniedError` (carrying the trace) on deny.
     */
    readonly authorize: (
      input: AuthorizeInput,
    ) => Effect.Effect<
      Policy.Decision,
      Policy.AuthorizationDeniedError | Errors.AuthError,
      CurrentPrincipal
    >;

    /** Boolean form of {@link authorize} (never fails on deny). */
    readonly check: (
      input: AuthorizeInput,
    ) => Effect.Effect<boolean, Errors.AuthError, CurrentPrincipal>;
  }
>()("@effect-auth/Authorizer") {
  /**
   * Construct a Layer providing this service. Requires an `EntityResolver`
   * when one is in context; without one, decisions run over the model's
   * action entities alone (pure-context/ownerless policies still work).
   */
  static readonly layer = <E = unknown>(config: AuthorizerConfig<E>) =>
    Layer.effect(Authorizer, make(config));
}

export const make = <E = unknown>(
  config: AuthorizerConfig<E>,
): Effect.Effect<typeof Authorizer.Service, Errors.AuthError, never> =>
  Effect.gen(function* () {
    const resolver = yield* Effect.serviceOption(EntityResolver);
    const store = yield* Effect.serviceOption(PolicyStore.PolicyStore);
    const useStore = (config.useStore ?? true) && Option.isSome(store);
    const modelEntities =
      config.model !== undefined ? AuthorizationModel.actionEntities(config.model) : [];

    if (config.model !== undefined) {
      const declarative = config.policies.filter((policy): policy is Policy.DeclarativePolicy =>
        Predicate.isTagged(policy, "DeclarativePolicy"),
      );
      const issues = AuthorizationModel.validatePolicies(config.model, declarative);
      if (Arr.isReadonlyArrayNonEmpty(issues)) {
        return yield* new PolicyValidationError({
          message: `Policy validation failed: ${issues
            .map((issue) => `[${issue.policyId}] ${issue.message}`)
            .join("; ")}`,
        });
      }
    }

    // Stored policies (template links included) are fetched per decision so
    // edits apply immediately; static policies are appended after them.
    const allPolicies = (): Effect.Effect<
      ReadonlyArray<Policy.Policy<E, never>>,
      Errors.AuthError
    > =>
      useStore && Option.isSome(store)
        ? Effect.map(PolicyStore.effectivePolicies(store.value), (stored) => [
            ...stored,
            ...config.policies,
          ])
        : Effect.succeed(config.policies);

    const sliceFor = (
      policies: ReadonlyArray<Policy.Policy<E, never>>,
      request: Policy.PolicyRequest,
    ): Effect.Effect<Entity.EntitySlice, Errors.AuthError> =>
      Option.isSome(resolver)
        ? resolver.value
            .resolve(requestRefs(policies, request))
            .pipe(Effect.map((resolved) => Entity.slice([...modelEntities, ...resolved])))
        : Effect.succeed(Entity.slice(modelEntities));

    const decideRequest = Effect.fn("Authorizer.decideRequest")(function* (
      request: Policy.PolicyRequest,
    ) {
      const policies = yield* allPolicies();
      const slice = yield* sliceFor(policies, request);
      const decision = yield* Policy.decide(policies, request, slice);
      yield* auditSystemDecision(request, decision);
      return decision;
    });

    const requestFrom = (
      input: AuthorizeInput,
    ): Effect.Effect<Policy.PolicyRequest, never, CurrentPrincipal> =>
      Effect.gen(function* () {
        const principal = yield* CurrentPrincipal;
        // `CurrentCredential`, when present, is authoritative over anything
        // a caller passed in `input.context.credentialClass`: it is spread
        // last so a call site cannot spoof its own credential class.
        const credentialClass = yield* Effect.serviceOption(CurrentCredential);
        const context = {
          ...input.context,
          ...(Option.isSome(credentialClass) ? { credentialClass: credentialClass.value } : {}),
        };
        return Policy.request({
          principal,
          action: toActionRef(input.action),
          resource: input.resource,
          context,
        });
      });

    return {
      decideRequest,

      authorize: Effect.fn("Authorizer.authorize")(function* (input: AuthorizeInput) {
        const request = yield* requestFrom(input);
        const decision = yield* decideRequest(request);
        if (!decision.allowed) {
          return yield* new Policy.AuthorizationDeniedError({
            message: `Authorization denied: ${Entity.formatRef(request.principal)} may not ${Entity.formatRef(request.action)} on ${Entity.formatRef(request.resource)} (${decision.reason})`,
            request,
            decision,
          });
        }
        return decision;
      }),

      check: Effect.fn("Authorizer.check")(function* (input: AuthorizeInput) {
        const request = yield* requestFrom(input);
        const decision = yield* decideRequest(request);
        return decision.allowed;
      }),
    };
  });
