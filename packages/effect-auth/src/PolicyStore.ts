/**
 * Policies as data: the versioned stored document, Cedar-style templates with
 * `?principal` and `?resource` slots and the links that fill them, and the
 * `PolicyStore` contract. {@link effectivePolicies} fails on a broken link, so
 * one bad row fails every decision: validate on write, and scope each tenant's
 * policies.
 *
 * @module policy-store
 */
import { Context, Effect, Match, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as Schema from "effect/Schema";
import * as Errors from "./Errors.ts";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as AuthorizationModel from "./AuthorizationModel.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/**
 * A scope in a template position: any {@link Policy.Scope}, plus the two
 * Cedar slot forms — `eqSlot` is `== ?principal` / `== ?resource`, `inSlot`
 * is `in ?principal` / `in ?resource`.
 *
 * Slots are legal only in the principal and resource positions; that is
 * enforced by construction in {@link PolicyTemplate}, whose `action` field is
 * a plain {@link Policy.Scope}.
 */
export const TemplateScope = Schema.Union([
  Policy.Scope,
  Schema.TaggedStruct("eqSlot", {}),
  Schema.TaggedStruct("inSlot", {}),
]);
export type TemplateScope = typeof TemplateScope.Type;

/** The `== ?principal` / `== ?resource` slot scope. */
export const eqSlot: TemplateScope = { _tag: "eqSlot" };
/** The `in ?principal` / `in ?resource` slot scope. */
export const inSlot: TemplateScope = { _tag: "inSlot" };

/** Is this template scope a slot awaiting a link value? */
export const isSlot = (scope: TemplateScope): boolean =>
  P.isTagged(scope, "eqSlot") || P.isTagged(scope, "inSlot");

/**
 * A policy with slots. Same shape as {@link Policy.DeclarativePolicy} except
 * that `principal` and `resource` may be slots; `action` may not be (Cedar
 * has no action slot).
 */
export const PolicyTemplate = Schema.TaggedStruct("PolicyTemplate", {
  id: Schema.String,
  effect: Policy.PolicyEffect,
  principal: TemplateScope,
  action: Policy.Scope,
  resource: TemplateScope,
  when: Schema.optional(Condition.Condition),
  description: Schema.optional(Schema.String),
});
export type PolicyTemplate = typeof PolicyTemplate.Type;

/** Options for {@link template} (scopes default to `any`, effect to `permit`). */
export interface TemplateOptions {
  readonly id: string;
  readonly effect?: Policy.PolicyEffect;
  readonly principal?: TemplateScope;
  readonly action?: Policy.Scope;
  readonly resource?: TemplateScope;
  readonly when?: Condition.Condition;
  readonly description?: string;
}

/** Build a {@link PolicyTemplate} (the eDSL authoring of the stored form). */
export const template = (options: TemplateOptions): PolicyTemplate => ({
  _tag: "PolicyTemplate",
  id: options.id,
  effect: options.effect ?? "permit",
  principal: options.principal ?? Policy.any,
  action: options.action ?? Policy.any,
  resource: options.resource ?? Policy.any,
  ...(options.when !== undefined ? { when: options.when } : {}),
  ...(options.description !== undefined ? { description: options.description } : {}),
});

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/**
 * One instantiation of a template: the values its slots take. A link carries
 * only what the template asks for — `principal` when the template's principal
 * scope is a slot, `resource` when its resource scope is — and supplying a
 * value the template has no slot for is an error, not a silent no-op (see
 * {@link instantiate}).
 */
export const TemplateLink = Schema.Struct({
  id: Schema.String,
  templateId: Schema.String,
  principal: Schema.optional(Entity.EntityRef),
  resource: Schema.optional(Entity.EntityRef),
  createdAt: Schema.Date,
});
export type TemplateLink = typeof TemplateLink.Type;

/**
 * Construct a new (unpersisted) link record with a random id.
 *
 * `now` is the link's `createdAt`, required so the time comes from the
 * caller's `Clock` (`yield* DateTime.nowAsDate`) rather than the wall clock.
 */
export const makeLink = (input: {
  readonly templateId: string;
  readonly id?: string;
  readonly principal?: Entity.EntityRef;
  readonly resource?: Entity.EntityRef;
  readonly now: Date;
}): TemplateLink => ({
  id: input.id ?? globalThis.crypto.randomUUID(),
  templateId: input.templateId,
  ...(input.principal !== undefined ? { principal: input.principal } : {}),
  ...(input.resource !== undefined ? { resource: input.resource } : {}),
  createdAt: input.now,
});

// ---------------------------------------------------------------------------
// Instantiation
// ---------------------------------------------------------------------------

/**
 * The result of instantiating a template: a real declarative policy, or a
 * message explaining why the link and template do not fit together. Pure and
 * total, like condition evaluation — the Effect shell decides what a failure
 * means (see {@link effectivePolicies}).
 */
export type InstantiateResult =
  | { readonly ok: true; readonly value: Policy.DeclarativePolicy }
  | { readonly ok: false; readonly error: { readonly message: string } };

type Substitution =
  | { readonly ok: true; readonly scope: Policy.Scope }
  | { readonly ok: false; readonly message: string };

const substitute = (
  slot: "principal" | "resource",
  scope: TemplateScope,
  value: Entity.EntityRef | undefined,
): Substitution =>
  Match.value(scope).pipe(
    Match.tag("eqSlot", (): Substitution =>
      value === undefined
        ? { ok: false, message: `no value supplied for ?${slot}` }
        : { ok: true, scope: Policy.eq(value) },
    ),
    Match.tag("inSlot", (): Substitution =>
      value === undefined
        ? { ok: false, message: `no value supplied for ?${slot}` }
        : { ok: true, scope: Policy.inScope(value) },
    ),
    Match.orElse((scope): Substitution =>
      value === undefined
        ? { ok: true, scope }
        : {
            ok: false,
            message: `a ?${slot} value was supplied but the template has no ?${slot} slot`,
          },
    ),
  );

/**
 * Substitute a link's slot values into its template, producing a
 * template-linked {@link Policy.DeclarativePolicy}.
 *
 * The instantiated id is `<templateId>#<linkId>` — stable across template
 * edits (so traces and audit logs stay comparable) and unique per link.
 *
 * Fails (as data, never throwing) when the link does not fit the template:
 * the link targets a different template, a slot has no value, or a value is
 * supplied for a position that is not a slot. The last case is deliberately
 * an error rather than an ignored field: a link written against the wrong
 * template would otherwise instantiate to a *broader* policy than its author
 * intended.
 */
export const instantiate = (template: PolicyTemplate, link: TemplateLink): InstantiateResult => {
  const context = `template "${template.id}" link "${link.id}"`;
  const fail = (message: string): InstantiateResult => ({
    ok: false,
    error: { message: `${context}: ${message}` },
  });

  if (link.templateId !== template.id) {
    return fail(`link targets template "${link.templateId}"`);
  }
  const principal = substitute("principal", template.principal, link.principal);
  if (!principal.ok) return fail(principal.message);
  const resource = substitute("resource", template.resource, link.resource);
  if (!resource.ok) return fail(resource.message);

  return {
    ok: true,
    value: {
      _tag: "DeclarativePolicy",
      id: `${template.id}#${link.id}`,
      effect: template.effect,
      principal: principal.scope,
      action: template.action,
      resource: resource.scope,
      ...(template.when !== undefined ? { when: template.when } : {}),
      ...(template.description !== undefined ? { description: template.description } : {}),
    },
  };
};

// ---------------------------------------------------------------------------
// The stored document format (decision 4)
// ---------------------------------------------------------------------------

/**
 * The canonical stored form of a declarative policy: a versioned envelope
 * around the policy body. `version` is a literal so that a future format
 * change is a decode failure on old readers rather than a silent
 * misinterpretation; readers of several versions become a Schema union.
 */
export const PolicyDocument = Schema.Struct({
  version: Schema.Literal(1),
  policy: Policy.DeclarativePolicy,
});
export type PolicyDocument = typeof PolicyDocument.Type;

/** Wrap a policy in the current document envelope. */
export const policyDocument = (policy: Policy.DeclarativePolicy): PolicyDocument => ({
  version: 1,
  policy,
});

/** The same envelope for templates. */
export const TemplateDocument = Schema.Struct({
  version: Schema.Literal(1),
  template: PolicyTemplate,
});
export type TemplateDocument = typeof TemplateDocument.Type;

/** Wrap a template in the current document envelope. */
export const templateDocument = (template: PolicyTemplate): TemplateDocument => ({
  version: 1,
  template,
});

/** Encode a policy document to its JSON-safe representation. */
export const encodePolicyDocument = (
  document: PolicyDocument,
): Effect.Effect<typeof PolicyDocument.Encoded, Schema.SchemaError> =>
  Schema.encodeEffect(PolicyDocument)(document);

/** Decode (and validate) a policy document from unknown input. */
export const decodePolicyDocument = (
  input: unknown,
): Effect.Effect<PolicyDocument, Schema.SchemaError> =>
  Schema.decodeUnknownEffect(PolicyDocument)(input);

/** Encode a template document to its JSON-safe representation. */
export const encodeTemplateDocument = (
  document: TemplateDocument,
): Effect.Effect<typeof TemplateDocument.Encoded, Schema.SchemaError> =>
  Schema.encodeEffect(TemplateDocument)(document);

/** Decode (and validate) a template document from unknown input. */
export const decodeTemplateDocument = (
  input: unknown,
): Effect.Effect<TemplateDocument, Schema.SchemaError> =>
  Schema.decodeUnknownEffect(TemplateDocument)(input);

// ---------------------------------------------------------------------------
// Store contract (D3 conventions: null on miss, AuthError for infra failures)
// ---------------------------------------------------------------------------

/**
 * Persistence for policies, templates and template links.
 *
 * Conventions match the rest of the library: lookups return `null` on a miss,
 * deletes no-op when the row is absent, and the error channel carries
 * {@link Errors.AuthError} for *infrastructure* failures only — with one
 * modelled conflict: `createPolicy` / `createTemplate` / `createLink` fail
 * with `AuthError` when the id already exists, mirroring a unique-index
 * violation (use the `update*` operations to change an existing row).
 *
 * `deleteTemplate` **also deletes every link of that template**: a link
 * without its template cannot be instantiated, and
 * {@link effectivePolicies} refuses to build a policy set that contains one,
 * so leaving orphans behind would take the whole authorization path down.
 * Implementations must perform the cascade (ideally in one transaction, or
 * via an `ON DELETE CASCADE` foreign key).
 *
 * Implementations must also reject, with `AuthError`, a policy or template
 * whose `when` fails `Condition.isWithinBounds`, so that no stored condition
 * is too deep to decode or evaluate. Decoding through {@link PolicyDocument}
 * or {@link TemplateDocument} does this.
 */
export class PolicyStore extends Context.Service<
  PolicyStore,
  {
    /** Look up a stored policy by id; `null` when absent. */
    readonly getPolicy: (
      id: string,
    ) => Effect.Effect<Policy.DeclarativePolicy | null, Errors.AuthError>;

    /** Every stored policy (excluding template-linked ones). */
    readonly listPolicies: Effect.Effect<ReadonlyArray<Policy.DeclarativePolicy>, Errors.AuthError>;

    /** Persist a new policy. Fails when `policy.id` is already taken. */
    readonly createPolicy: (
      policy: Policy.DeclarativePolicy,
    ) => Effect.Effect<Policy.DeclarativePolicy, Errors.AuthError>;

    /** Replace a stored policy by its id; `null` when no such policy exists. */
    readonly updatePolicy: (
      policy: Policy.DeclarativePolicy,
    ) => Effect.Effect<Policy.DeclarativePolicy | null, Errors.AuthError>;

    /** Delete a policy by id. No-ops when it does not exist. */
    readonly deletePolicy: (id: string) => Effect.Effect<void, Errors.AuthError>;

    /** Look up a template by id; `null` when absent. */
    readonly getTemplate: (id: string) => Effect.Effect<PolicyTemplate | null, Errors.AuthError>;

    /** Every stored template. */
    readonly listTemplates: Effect.Effect<ReadonlyArray<PolicyTemplate>, Errors.AuthError>;

    /** Persist a new template. Fails when `template.id` is already taken. */
    readonly createTemplate: (
      template: PolicyTemplate,
    ) => Effect.Effect<PolicyTemplate, Errors.AuthError>;

    /**
     * Replace a stored template by its id; `null` when no such template
     * exists. Existing links are untouched and instantiate against the new
     * body — editing a template retroactively updates its links.
     */
    readonly updateTemplate: (
      template: PolicyTemplate,
    ) => Effect.Effect<PolicyTemplate | null, Errors.AuthError>;

    /**
     * Delete a template by id, **cascading to its links**. No-ops when the
     * template does not exist.
     */
    readonly deleteTemplate: (id: string) => Effect.Effect<void, Errors.AuthError>;

    /** Every link, or only those of `templateId` when one is given. */
    readonly listLinks: (
      templateId?: string,
    ) => Effect.Effect<ReadonlyArray<TemplateLink>, Errors.AuthError>;

    /** Look up a link by id; `null` when absent. */
    readonly getLink: (id: string) => Effect.Effect<TemplateLink | null, Errors.AuthError>;

    /** Persist a new link. Fails when `link.id` is already taken. */
    readonly createLink: (link: TemplateLink) => Effect.Effect<TemplateLink, Errors.AuthError>;

    /** Delete a link by id. No-ops when it does not exist. */
    readonly deleteLink: (id: string) => Effect.Effect<void, Errors.AuthError>;
  }
>()("@effect-auth/PolicyStore") {}

/**
 * The policy set a decision should run against: every stored policy, plus
 * every template link instantiated against its template.
 *
 * Fail-closed: a link whose template is missing, or whose values do not fit
 * the template's slots, fails the effect with an {@link Errors.AuthError}
 * naming the link. Skipping the broken link would drop a grant silently —
 * and, for a `forbid` template, would turn a storage inconsistency into an
 * over-permissive decision. So one broken link fails every decision: validate
 * tenant-written rows on write (decode them, check them against the model,
 * instantiate each link), and scope each tenant's policies to that tenant.
 *
 * Reads the store three times (`listPolicies`, `listLinks`, `listTemplates`)
 * however many links there are.
 */
export const effectivePolicies = (
  store: typeof PolicyStore.Service,
): Effect.Effect<ReadonlyArray<Policy.DeclarativePolicy>, Errors.AuthError> =>
  Effect.gen(function* () {
    const stored = yield* store.listPolicies;
    const links = yield* store.listLinks();
    // One `listTemplates` for every link, not a `getTemplate` per link.
    const templates = MutableHashMap.fromIterable(
      Arr.map(yield* store.listTemplates, (found) => [found.id, found] as const),
    );
    const linked = yield* Effect.forEach(
      links,
      (link) => {
        const found = MutableHashMap.get(templates, link.templateId);
        if (Option.isNone(found)) {
          return Effect.fail(
            new Errors.AuthError({
              message: `Template link "${link.id}" references unknown template "${link.templateId}"`,
            }),
          );
        }
        const result = instantiate(found.value, link);
        return result.ok
          ? Effect.succeed(result.value)
          : Effect.fail(
              new Errors.AuthError({
                message: `Template link "${link.id}" could not be instantiated: ${result.error.message}`,
              }),
            );
      },
      { concurrency: 1 },
    );
    return [...stored, ...linked];
  });

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/**
 * In-memory {@link PolicyStore} for tests and single-instance deployments.
 * Id uniqueness is enforced by construction (synchronous, single-threaded):
 * the `create*` operations fail with `AuthError` when the id is taken,
 * mirroring a SQL unique-index violation. `deleteTemplate` cascades to links,
 * and writes reject a condition beyond `Condition.isWithinBounds`, per the
 * contract.
 *
 * Pass your own `MutableHashMap`s (each keyed by record id) to inspect or pre-seed state
 * in tests.
 */
export const memoryPolicyStore = (
  records: {
    readonly policies?: MutableHashMap.MutableHashMap<string, Policy.DeclarativePolicy>;
    readonly templates?: MutableHashMap.MutableHashMap<string, PolicyTemplate>;
    readonly links?: MutableHashMap.MutableHashMap<string, TemplateLink>;
  } = {},
): typeof PolicyStore.Service => {
  const policies = records.policies ?? MutableHashMap.empty<string, Policy.DeclarativePolicy>();
  const templates = records.templates ?? MutableHashMap.empty<string, PolicyTemplate>();
  const links = records.links ?? MutableHashMap.empty<string, TemplateLink>();

  const insert = <A extends { readonly id: string }>(
    store: MutableHashMap.MutableHashMap<string, A>,
    label: string,
    value: A,
  ): Effect.Effect<A, Errors.AuthError> =>
    Effect.suspend(() => {
      if (MutableHashMap.has(store, value.id)) {
        return Effect.fail(
          new Errors.AuthError({ message: `${label} "${value.id}" already exists` }),
        );
      }
      MutableHashMap.set(store, value.id, value);
      return Effect.succeed(value);
    });

  const bounded = <B>(
    label: string,
    value: { readonly id: string; readonly when?: Condition.Condition | undefined },
    write: Effect.Effect<B, Errors.AuthError>,
  ): Effect.Effect<B, Errors.AuthError> =>
    value.when === undefined || Condition.isWithinBounds(value.when)
      ? write
      : Effect.fail(
          new Errors.AuthError({
            message: `${label} "${value.id}" has a condition deeper than ${Condition.maxDepth} levels or larger than ${Condition.maxNodes} nodes`,
          }),
        );

  const replace = <A extends { readonly id: string }>(
    store: MutableHashMap.MutableHashMap<string, A>,
    value: A,
  ): Effect.Effect<A | null, Errors.AuthError> =>
    Effect.sync(() => {
      if (!MutableHashMap.has(store, value.id)) return null;
      MutableHashMap.set(store, value.id, value);
      return value;
    });

  return {
    getPolicy: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(policies, id))),
    listPolicies: Effect.sync(() => Arr.fromIterable(MutableHashMap.values(policies))),
    createPolicy: (policy) => bounded("Policy", policy, insert(policies, "Policy", policy)),
    updatePolicy: (policy) => bounded("Policy", policy, replace(policies, policy)),
    deletePolicy: (id) => Effect.sync(() => void MutableHashMap.remove(policies, id)),

    getTemplate: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(templates, id))),
    listTemplates: Effect.sync(() => Arr.fromIterable(MutableHashMap.values(templates))),
    createTemplate: (value) =>
      bounded("Policy template", value, insert(templates, "Policy template", value)),
    updateTemplate: (value) => bounded("Policy template", value, replace(templates, value)),
    deleteTemplate: (id) =>
      Effect.sync(() => {
        MutableHashMap.remove(templates, id);
        Arr.forEach(
          Arr.filter(Arr.fromIterable(links), ([, link]) => link.templateId === id),
          ([linkId]) => void MutableHashMap.remove(links, linkId),
        );
      }),

    listLinks: (templateId) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(links)).filter(
          (link) => templateId === undefined || link.templateId === templateId,
        ),
      ),
    getLink: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(links, id))),
    createLink: (link) => insert(links, "Template link", link),
    deleteLink: (id) => Effect.sync(() => void MutableHashMap.remove(links, id)),
  } satisfies typeof PolicyStore.Service;
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * The policy a template validates as: slots erased to `any`, since a slot's
 * value is not known until link time. Everything else — entity types, action
 * ids, `appliesTo` signatures, condition literals — is exactly the policy
 * check, so validation reuses {@link AuthorizationModel.validatePolicies} rather than
 * duplicating it.
 */
const erased = (value: PolicyTemplate): Policy.DeclarativePolicy => {
  const scope = (s: TemplateScope): Policy.Scope =>
    Match.value(s).pipe(
      Match.tag("eqSlot", "inSlot", (): Policy.Scope => Policy.any),
      Match.orElse((scope) => scope),
    );
  return {
    _tag: "DeclarativePolicy",
    id: value.id,
    effect: value.effect,
    principal: scope(value.principal),
    action: value.action,
    resource: scope(value.resource),
    ...(value.when !== undefined ? { when: value.when } : {}),
    ...(value.description !== undefined ? { description: value.description } : {}),
  };
};

/**
 * Validate templates against a {@link AuthorizationModel.Model}, the way
 * {@link AuthorizationModel.validatePolicies} validates policies: non-slot scopes and
 * condition entity literals must name declared types and actions. Slots
 * validate trivially (their value arrives with the link), so a template with
 * `?principal` never constrains the principal side of an action's
 * `appliesTo`.
 *
 * Issues carry the template id in `policyId`.
 */
export const validateTemplates = (
  model: AuthorizationModel.Model,
  templates: ReadonlyArray<PolicyTemplate>,
): ReadonlyArray<AuthorizationModel.ValidationIssue> =>
  AuthorizationModel.validatePolicies(model, templates.map(erased));
