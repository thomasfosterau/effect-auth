/**
 * The authorization model: Schema-declared entity types and actions.
 *
 * Declaring the entity vocabulary once gives Cedar-style **policy
 * validation** for free: a stored or authored declarative policy can be
 * checked against the model — do the entity types it names exist, are the
 * actions declared, does the policy's action actually apply to the
 * principal/resource types it is scoped to? Validation catches typos and
 * drift *before* a policy reaches the decision path, where an invalid
 * policy would otherwise just silently never match (or, worse for a forbid,
 * silently always deny).
 *
 * The attribute schemas double as the app's own entity codecs: the same
 * `Schema.Struct` that validates `Document.attributes` in the model is the
 * one the app uses to build slice entities from its rows.
 *
 * @module authorization-model
 */
import { Array as Arr, Match, Predicate, Record as Rec, Result, Schema } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import type { DeclarativePolicy, Scope } from "./Policy.ts";

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

/** Declaration of one entity type. */
export interface EntityTypeDecl {
  /**
   * Schema for this type's attribute bag. Used by apps to encode their rows
   * into slice entities; presence here also lets validation flag top-level
   * attribute names that the type does not declare (when the schema is a
   * struct).
   */
  readonly attributes?: Schema.Struct<Schema.Struct.Fields>;
  /** Entity types this type's entities may be `in` (parent types). */
  readonly memberOf?: ReadonlyArray<string>;
}

/** Declaration of one action (an `Action::"<id>"` entity). */
export interface ActionDecl {
  /** Which principal/resource entity types the action applies to. */
  readonly appliesTo: {
    readonly principal: ReadonlyArray<string>;
    readonly resource: ReadonlyArray<string>;
  };
  /** Action-group actions this action is `in` (e.g. `"doc:all"`). */
  readonly memberOf?: ReadonlyArray<string>;
}

/**
 * The declared authorization model: entity types keyed by name, actions
 * keyed by id. `"Action"` is implicit — do not declare it as an entity type.
 */
export interface Model {
  readonly entities: Readonly<Record<string, EntityTypeDecl>>;
  readonly actions: Readonly<Record<string, ActionDecl>>;
}

/** Declare a model (identity constructor; exists for inference + symmetry). */
export const make = (model: Model): Model => model;

/**
 * The action entities a model implies: one per declared action, with
 * `memberOf` groups as parents. Merge these into slices so `in`-scoped
 * action policies (action groups) work without hand-maintaining them.
 */
export const actionEntities = (model: Model): ReadonlyArray<Entity.Entity> => {
  const groups = Arr.dedupe(Arr.flatMap(Rec.values(model.actions), (decl) => decl.memberOf ?? []));
  const declared = Rec.toEntries(model.actions).map(([id, decl]) =>
    Entity.entity(Entity.ref("Action", id), {
      parents: (decl.memberOf ?? []).map((group) => Entity.ref("Action", group)),
    }),
  );
  const groupEntities = groups
    .filter((group) => !(group in model.actions))
    .map((group) => Entity.entity(Entity.ref("Action", group)));
  return [...declared, ...groupEntities];
};

// ---------------------------------------------------------------------------
// Policy validation
// ---------------------------------------------------------------------------

/** One validation finding; `policyId` ties it back to the offending policy. */
export interface ValidationIssue {
  readonly policyId: string;
  readonly message: string;
}

const knownEntityType = (model: Model, type: string): boolean =>
  type === "Action" || type in model.entities;

const knownActionId = (model: Model, id: string): boolean => {
  if (id in model.actions) return true;
  // Action groups referenced via memberOf are legal `in` targets.
  return Arr.some(Rec.values(model.actions), (decl) => (decl.memberOf ?? []).includes(id));
};

const validateScope = (
  model: Model,
  policy: DeclarativePolicy,
  slot: "principal" | "action" | "resource",
  scope: Scope,
): ReadonlyArray<ValidationIssue> => {
  const validateRef = (ref: Entity.EntityRef): ReadonlyArray<ValidationIssue> => {
    if (!knownEntityType(model, ref.type)) {
      return [
        {
          policyId: policy.id,
          message: `${slot} scope names undeclared entity type "${ref.type}"`,
        },
      ];
    }
    if (slot === "action") {
      if (ref.type !== "Action") {
        return [
          {
            policyId: policy.id,
            message: `action scope must reference Action entities (got "${ref.type}")`,
          },
        ];
      } else if (!knownActionId(model, ref.id)) {
        return [
          {
            policyId: policy.id,
            message: `action scope names undeclared action "${ref.id}"`,
          },
        ];
      }
    }
    return [];
  };
  return Match.valueTags(scope, {
    any: (): ReadonlyArray<ValidationIssue> => [],
    is: ({ entityType }): ReadonlyArray<ValidationIssue> =>
      knownEntityType(model, entityType)
        ? []
        : [
            {
              policyId: policy.id,
              message: `${slot} scope names undeclared entity type "${entityType}"`,
            },
          ],
    eq: ({ ref }) => validateRef(ref),
    in: ({ ref }) => validateRef(ref),
  });
};

/** The operands a condition compares, in evaluation order (`Has` has none). */
const conditionOperands = (condition: Condition.Condition): ReadonlyArray<Condition.Operand> =>
  Match.valueTags(condition, {
    And: ({ conditions }) => Arr.flatMap(conditions, conditionOperands),
    Or: ({ conditions }) => Arr.flatMap(conditions, conditionOperands),
    Not: (not) => conditionOperands(not.condition),
    Eq: ({ left, right }): ReadonlyArray<Condition.Operand> => [left, right],
    Compare: ({ left, right }): ReadonlyArray<Condition.Operand> => [left, right],
    In: ({ left, right }): ReadonlyArray<Condition.Operand> => [left, right],
    Contains: ({ collection, value }): ReadonlyArray<Condition.Operand> => [collection, value],
    Has: (): ReadonlyArray<Condition.Operand> => [],
  });

const conditionRefs = (condition: Condition.Condition): ReadonlyArray<Entity.EntityRef> =>
  Arr.filterMap(conditionOperands(condition), (operand) =>
    Predicate.isTagged(operand, "Lit") && Entity.isEntityValue(operand.value)
      ? Result.succeed(operand.value.__entity)
      : Result.failVoid,
  );

const attrOperands = (condition: Condition.Condition): ReadonlyArray<Condition.Attr> =>
  Arr.filter(conditionOperands(condition), (operand): operand is Condition.Attr =>
    Predicate.isTagged(operand, "Attr"),
  );

const pinnedType = (scope: Scope): string | null =>
  Match.valueTags(scope, {
    is: ({ entityType }): string | null => entityType,
    eq: ({ ref }): string | null => ref.type,
    any: (): string | null => null,
    in: (): string | null => null,
  });

/**
 * When a policy pins its principal or resource to one declared type whose
 * attributes are a struct, check every attribute its condition reads on that
 * slot against the struct's fields. A misspelt attribute otherwise evaluates
 * as absent — an error the decision treats fail-closed, so a permit that
 * silently never grants (and a forbid that silently always denies).
 * `Has` is exempt: testing presence of an undeclared attribute is legitimate.
 */
const validateAttributes = (
  model: Model,
  policy: DeclarativePolicy,
  condition: Condition.Condition,
): ReadonlyArray<ValidationIssue> => {
  const attrs = attrOperands(condition);
  return Arr.flatMap(["principal", "resource"] as const, (slot) => {
    const type = pinnedType(policy[slot]);
    const fields = type === null ? undefined : model.entities[type]?.attributes?.fields;
    if (fields === undefined) return [];
    return Arr.filterMap(attrs, (attr) => {
      if (attr.of !== slot) return Result.failVoid;
      const [head] = attr.path;
      return head !== undefined && !(head in fields)
        ? Result.succeed({
            policyId: policy.id,
            message: `condition reads ${slot}.${attr.path.join(".")}, but "${type}" declares no attribute "${head}"`,
          })
        : Result.failVoid;
    });
  });
};

/**
 * When both the action scope and the principal/resource scopes pin concrete
 * types, check them against the action's `appliesTo` signature.
 */
const validateAppliesTo = (
  model: Model,
  policy: DeclarativePolicy,
): ReadonlyArray<ValidationIssue> => {
  if (policy.action._tag !== "eq" || policy.action.ref.type !== "Action") return [];
  const actionId = policy.action.ref.id;
  const decl = model.actions[actionId];
  if (decl === undefined) return [];

  const check = (
    slot: "principal" | "resource",
    scope: Scope,
    allowed: ReadonlyArray<string>,
  ): ReadonlyArray<ValidationIssue> => {
    const pinned = pinnedType(scope);
    return pinned !== null && !allowed.includes(pinned)
      ? [
          {
            policyId: policy.id,
            message: `action "${actionId}" does not apply to ${slot} type "${pinned}" (appliesTo: ${allowed.join(", ")})`,
          },
        ]
      : [];
  };
  return [
    ...check("principal", policy.principal, decl.appliesTo.principal),
    ...check("resource", policy.resource, decl.appliesTo.resource),
  ];
};

/**
 * Validate declarative policies against a model. Returns every issue found
 * (an empty array means the set is well-formed). Checks: scope entity types
 * and action ids are declared, action scopes reference `Action` entities,
 * pinned principal/resource types satisfy the action's `appliesTo`, entity
 * literals inside conditions use declared types, and — where a scope pins a
 * type whose attributes are declared — the attributes a condition reads on
 * that slot exist.
 */
export const validatePolicies = (
  model: Model,
  policies: ReadonlyArray<DeclarativePolicy>,
): ReadonlyArray<ValidationIssue> =>
  Arr.flatMap(policies, (policy) => [
    ...validateScope(model, policy, "principal", policy.principal),
    ...validateScope(model, policy, "action", policy.action),
    ...validateScope(model, policy, "resource", policy.resource),
    ...validateAppliesTo(model, policy),
    ...(policy.when === undefined
      ? []
      : [
          ...validateAttributes(model, policy, policy.when),
          ...Arr.filterMap(conditionRefs(policy.when), (ref) =>
            knownEntityType(model, ref.type)
              ? Result.failVoid
              : Result.succeed({
                  policyId: policy.id,
                  message: `condition references undeclared entity type "${ref.type}"`,
                }),
          ),
        ]),
  ]);
