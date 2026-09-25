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
import { Schema } from "effect";
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
  const groups = new Set<string>();
  for (const decl of Object.values(model.actions)) {
    for (const group of decl.memberOf ?? []) groups.add(group);
  }
  const declared = Object.entries(model.actions).map(([id, decl]) =>
    Entity.entity(Entity.ref("Action", id), {
      parents: (decl.memberOf ?? []).map((group) => Entity.ref("Action", group)),
    }),
  );
  const groupEntities = [...groups]
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
  return Object.values(model.actions).some((decl) => (decl.memberOf ?? []).includes(id));
};

const validateScope = (
  model: Model,
  policy: DeclarativePolicy,
  slot: "principal" | "action" | "resource",
  scope: Scope,
  issues: ValidationIssue[],
): void => {
  switch (scope._tag) {
    case "any":
      return;
    case "is": {
      if (!knownEntityType(model, scope.entityType)) {
        issues.push({
          policyId: policy.id,
          message: `${slot} scope names undeclared entity type "${scope.entityType}"`,
        });
      }
      return;
    }
    case "eq":
    case "in": {
      const ref = scope.ref;
      if (!knownEntityType(model, ref.type)) {
        issues.push({
          policyId: policy.id,
          message: `${slot} scope names undeclared entity type "${ref.type}"`,
        });
        return;
      }
      if (slot === "action") {
        if (ref.type !== "Action") {
          issues.push({
            policyId: policy.id,
            message: `action scope must reference Action entities (got "${ref.type}")`,
          });
        } else if (!knownActionId(model, ref.id)) {
          issues.push({
            policyId: policy.id,
            message: `action scope names undeclared action "${ref.id}"`,
          });
        }
      }
      return;
    }
  }
};

const collectConditionRefs = (condition: Condition.Condition, out: Entity.EntityRef[]): void => {
  const fromOperand = (operand: Condition.Operand): void => {
    if (operand._tag === "Lit" && Entity.isEntityValue(operand.value)) {
      out.push(operand.value.__entity);
    }
  };
  switch (condition._tag) {
    case "And":
    case "Or":
      for (const inner of condition.conditions) collectConditionRefs(inner, out);
      return;
    case "Not":
      collectConditionRefs(condition.condition, out);
      return;
    case "Eq":
    case "Compare":
    case "In":
      fromOperand(condition.left);
      fromOperand(condition.right);
      return;
    case "Contains":
      fromOperand(condition.collection);
      fromOperand(condition.value);
      return;
    case "Has":
      return;
  }
};

const collectAttrOperands = (condition: Condition.Condition, out: Condition.Attr[]): void => {
  const fromOperand = (operand: Condition.Operand): void => {
    if (operand._tag === "Attr") out.push(operand);
  };
  switch (condition._tag) {
    case "And":
    case "Or":
      for (const inner of condition.conditions) collectAttrOperands(inner, out);
      return;
    case "Not":
      collectAttrOperands(condition.condition, out);
      return;
    case "Eq":
    case "Compare":
    case "In":
      fromOperand(condition.left);
      fromOperand(condition.right);
      return;
    case "Contains":
      fromOperand(condition.collection);
      fromOperand(condition.value);
      return;
    case "Has":
      return;
  }
};

const pinnedType = (scope: Scope): string | null =>
  scope._tag === "is" ? scope.entityType : scope._tag === "eq" ? scope.ref.type : null;

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
  issues: ValidationIssue[],
): void => {
  const attrs: Condition.Attr[] = [];
  collectAttrOperands(condition, attrs);
  for (const slot of ["principal", "resource"] as const) {
    const type = pinnedType(policy[slot]);
    const fields = type === null ? undefined : model.entities[type]?.attributes?.fields;
    if (fields === undefined) continue;
    for (const attr of attrs) {
      if (attr.of !== slot) continue;
      const [head] = attr.path;
      if (head !== undefined && !(head in fields)) {
        issues.push({
          policyId: policy.id,
          message: `condition reads ${slot}.${attr.path.join(".")}, but "${type}" declares no attribute "${head}"`,
        });
      }
    }
  }
};

/**
 * When both the action scope and the principal/resource scopes pin concrete
 * types, check them against the action's `appliesTo` signature.
 */
const validateAppliesTo = (
  model: Model,
  policy: DeclarativePolicy,
  issues: ValidationIssue[],
): void => {
  if (policy.action._tag !== "eq" || policy.action.ref.type !== "Action") return;
  const actionId = policy.action.ref.id;
  const decl = model.actions[actionId];
  if (decl === undefined) return;

  const check = (slot: "principal" | "resource", scope: Scope, allowed: ReadonlyArray<string>) => {
    const pinned =
      scope._tag === "is" ? scope.entityType : scope._tag === "eq" ? scope.ref.type : null;
    if (pinned !== null && !allowed.includes(pinned)) {
      issues.push({
        policyId: policy.id,
        message: `action "${actionId}" does not apply to ${slot} type "${pinned}" (appliesTo: ${allowed.join(", ")})`,
      });
    }
  };
  check("principal", policy.principal, decl.appliesTo.principal);
  check("resource", policy.resource, decl.appliesTo.resource);
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
): ReadonlyArray<ValidationIssue> => {
  const issues: ValidationIssue[] = [];
  for (const policy of policies) {
    validateScope(model, policy, "principal", policy.principal, issues);
    validateScope(model, policy, "action", policy.action, issues);
    validateScope(model, policy, "resource", policy.resource, issues);
    validateAppliesTo(model, policy, issues);
    if (policy.when !== undefined) {
      validateAttributes(model, policy, policy.when, issues);
      const refs: Entity.EntityRef[] = [];
      collectConditionRefs(policy.when, refs);
      for (const ref of refs) {
        if (!knownEntityType(model, ref.type)) {
          issues.push({
            policyId: policy.id,
            message: `condition references undeclared entity type "${ref.type}"`,
          });
        }
      }
    }
  }
  return issues;
};
