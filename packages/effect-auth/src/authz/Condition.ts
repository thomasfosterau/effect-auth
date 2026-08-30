/**
 * The declarative condition language: a small, serializable expression AST
 * evaluated by a **pure, total** function over a {@link Entity.EntitySlice}.
 *
 * Conditions are the `when` clause of declarative policies. Because they are
 * data (Schema-validated, versioned with the policy document format) they
 * are storable, tenant-editable, and analyzable — the extra powers the
 * declarative subset earns (`docs/better-auth-parity.md` §2.5). Arbitrary
 * code belongs in `Policy.custom`, not here.
 *
 * Evaluation never throws and never performs IO: a type mismatch (comparing
 * a string with `<`, calling `in` on a non-entity) produces a typed
 * {@link ConditionError} result, which the decision layer treats
 * **fail-closed** (an erroring permit cannot grant; an erroring forbid
 * denies). `and`/`or` short-circuit, so `false && <error>` is `false` and
 * `true || <error>` is `true` — the same posture as Cedar's operators.
 *
 * @module authz/condition
 */
import { Schema } from "effect";
import * as Entity from "./Entity.ts";

// ---------------------------------------------------------------------------
// Operand AST: expressions that produce a value
// ---------------------------------------------------------------------------

/** The four request slots an operand can reference. */
export const RequestSlot = Schema.Literals(["principal", "action", "resource", "context"]);
export type RequestSlot = typeof RequestSlot.Type;

/** A literal {@link Entity.AttributeValue}. */
export const Lit = Schema.Struct({
  _tag: Schema.Literal("Lit"),
  value: Entity.AttributeValue,
});
export type Lit = typeof Lit.Type;

/**
 * An attribute read: `Attr("resource", ["owner"])` is `resource.owner`.
 * Paths with several segments traverse nested record values. Reading an
 * attribute that is absent (or traversing through a non-record) is an
 * evaluation error — guard with {@link Has} where absence is expected.
 */
export const Attr = Schema.Struct({
  _tag: Schema.Literal("Attr"),
  of: RequestSlot,
  path: Schema.Array(Schema.String).check(Schema.isMinLength(1)),
});
export type Attr = typeof Attr.Type;

/** The request's principal/action/resource reference itself, as a value. */
export const SlotRef = Schema.Struct({
  _tag: Schema.Literal("SlotRef"),
  of: Schema.Literals(["principal", "action", "resource"]),
});
export type SlotRef = typeof SlotRef.Type;

export const Operand = Schema.Union([Lit, Attr, SlotRef]);
export type Operand = typeof Operand.Type;

// ---------------------------------------------------------------------------
// Condition AST: expressions that produce a boolean
// ---------------------------------------------------------------------------

export interface And {
  readonly _tag: "And";
  readonly conditions: ReadonlyArray<Condition>;
}
export interface Or {
  readonly _tag: "Or";
  readonly conditions: ReadonlyArray<Condition>;
}
export interface Not {
  readonly _tag: "Not";
  readonly condition: Condition;
}
/** Deep structural equality between two operand values. */
export interface Eq {
  readonly _tag: "Eq";
  readonly left: Operand;
  readonly right: Operand;
}
/** Numeric comparison; both operands must evaluate to numbers. */
export interface Compare {
  readonly _tag: "Compare";
  readonly op: "lt" | "lte" | "gt" | "gte";
  readonly left: Operand;
  readonly right: Operand;
}
/** Array membership: `collection` must evaluate to an array. */
export interface Contains {
  readonly _tag: "Contains";
  readonly collection: Operand;
  readonly value: Operand;
}
/**
 * Hierarchy membership: both operands must evaluate to entity values (or be
 * `SlotRef`s); true when the left entity is the right entity or a
 * transitive descendant in the slice (reflexive, like Cedar's `in`).
 */
export interface In {
  readonly _tag: "In";
  readonly left: Operand;
  readonly right: Operand;
}
/** Attribute presence: true when the slot has the attribute path. Never errors. */
export interface Has {
  readonly _tag: "Has";
  readonly of: RequestSlot;
  readonly path: ReadonlyArray<string>;
}

export type Condition = And | Or | Not | Eq | Compare | Contains | In | Has;

export const Condition: Schema.Codec<Condition> = Schema.Union([
  Schema.Struct({
    _tag: Schema.Literal("And"),
    conditions: Schema.Array(Schema.suspend((): Schema.Codec<Condition> => Condition)),
  }),
  Schema.Struct({
    _tag: Schema.Literal("Or"),
    conditions: Schema.Array(Schema.suspend((): Schema.Codec<Condition> => Condition)),
  }),
  Schema.Struct({
    _tag: Schema.Literal("Not"),
    condition: Schema.suspend((): Schema.Codec<Condition> => Condition),
  }),
  Schema.Struct({ _tag: Schema.Literal("Eq"), left: Operand, right: Operand }),
  Schema.Struct({
    _tag: Schema.Literal("Compare"),
    op: Schema.Literals(["lt", "lte", "gt", "gte"]),
    left: Operand,
    right: Operand,
  }),
  Schema.Struct({ _tag: Schema.Literal("Contains"), collection: Operand, value: Operand }),
  Schema.Struct({ _tag: Schema.Literal("In"), left: Operand, right: Operand }),
  Schema.Struct({
    _tag: Schema.Literal("Has"),
    of: RequestSlot,
    path: Schema.Array(Schema.String).check(Schema.isMinLength(1)),
  }),
]);

// ---------------------------------------------------------------------------
// eDSL builders (the TS authoring of the same subset)
// ---------------------------------------------------------------------------

/** Literal value operand. */
export const lit = (value: Entity.AttributeValue): Lit => ({ _tag: "Lit", value });

/** Entity-reference literal operand (`User::"u1"` as a value). */
export const entityLit = (ref: Entity.EntityRef): Lit => ({
  _tag: "Lit",
  value: Entity.entityValue(ref),
});

/** Attribute read operand: `attr("resource", "owner")` is `resource.owner`. */
export const attr = (of: RequestSlot, ...path: readonly [string, ...string[]]): Attr => ({
  _tag: "Attr",
  of,
  path,
});

/** The request's principal reference, as an operand. */
export const principal: SlotRef = { _tag: "SlotRef", of: "principal" };
/** The request's action reference, as an operand. */
export const action: SlotRef = { _tag: "SlotRef", of: "action" };
/** The request's resource reference, as an operand. */
export const resource: SlotRef = { _tag: "SlotRef", of: "resource" };

export const and = (...conditions: ReadonlyArray<Condition>): And => ({
  _tag: "And",
  conditions,
});
export const or = (...conditions: ReadonlyArray<Condition>): Or => ({ _tag: "Or", conditions });
export const not = (condition: Condition): Not => ({ _tag: "Not", condition });
export const eq = (left: Operand, right: Operand): Eq => ({ _tag: "Eq", left, right });
export const ne = (left: Operand, right: Operand): Not => not(eq(left, right));
export const lt = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "lt",
  left,
  right,
});
export const lte = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "lte",
  left,
  right,
});
export const gt = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "gt",
  left,
  right,
});
export const gte = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "gte",
  left,
  right,
});
export const contains = (collection: Operand, value: Operand): Contains => ({
  _tag: "Contains",
  collection,
  value,
});
/** Hierarchy membership condition (see {@link In}). */
export const isIn = (left: Operand, right: Operand): In => ({ _tag: "In", left, right });
export const has = (of: RequestSlot, ...path: readonly [string, ...string[]]): Has => ({
  _tag: "Has",
  of,
  path,
});

// ---------------------------------------------------------------------------
// Pure evaluation
// ---------------------------------------------------------------------------

/** The request a condition is evaluated against (defined here to stay pure). */
export interface ConditionRequest {
  readonly principal: Entity.EntityRef;
  readonly action: Entity.EntityRef;
  readonly resource: Entity.EntityRef;
  readonly context: Readonly<Record<string, Entity.AttributeValue>>;
}

/** A typed evaluation error — recorded in the decision trace, never thrown. */
export interface ConditionError {
  readonly message: string;
}

/** Total evaluation result. */
export type EvalResult<A> =
  | { readonly ok: true; readonly value: A }
  | { readonly ok: false; readonly error: ConditionError };

const ok = <A>(value: A): EvalResult<A> => ({ ok: true, value });
const err = <A>(message: string): EvalResult<A> => ({ ok: false, error: { message } });

const describeOperand = (operand: Operand): string => {
  switch (operand._tag) {
    case "Lit":
      return "literal";
    case "Attr":
      return `${operand.of}.${operand.path.join(".")}`;
    case "SlotRef":
      return operand.of;
  }
};

const resolvePath = (
  root: Entity.AttributeValue | null,
  path: ReadonlyArray<string>,
  describe: string,
): EvalResult<Entity.AttributeValue> => {
  let current: Entity.AttributeValue | null = root;
  for (const segment of path) {
    if (
      current === null ||
      typeof current !== "object" ||
      Array.isArray(current) ||
      Entity.isEntityValue(current)
    ) {
      return err(`attribute "${describe}" is absent`);
    }
    current =
      segment in current ? (current as Record<string, Entity.AttributeValue>)[segment]! : null;
  }
  return current === null ? err(`attribute "${describe}" is absent`) : ok(current);
};

const slotRoot = (
  slice: Entity.EntitySlice,
  request: ConditionRequest,
  of: RequestSlot,
): Entity.AttributeValue => {
  if (of === "context") return request.context;
  const found = Entity.getEntity(slice, request[of]);
  return found === null ? {} : found.attributes;
};

const evaluateOperand = (
  slice: Entity.EntitySlice,
  request: ConditionRequest,
  operand: Operand,
): EvalResult<Entity.AttributeValue> => {
  switch (operand._tag) {
    case "Lit":
      return ok(operand.value);
    case "SlotRef":
      return ok(Entity.entityValue(request[operand.of]));
    case "Attr":
      return resolvePath(
        slotRoot(slice, request, operand.of),
        operand.path,
        describeOperand(operand),
      );
  }
};

/**
 * Evaluate a condition over a slice and request. Pure and total: the result
 * is a boolean or a {@link ConditionError}, never an exception.
 */
export const evaluate = (
  slice: Entity.EntitySlice,
  request: ConditionRequest,
  condition: Condition,
): EvalResult<boolean> => {
  switch (condition._tag) {
    case "And": {
      for (const inner of condition.conditions) {
        const result = evaluate(slice, request, inner);
        if (!result.ok) return result;
        if (!result.value) return ok(false);
      }
      return ok(true);
    }
    case "Or": {
      for (const inner of condition.conditions) {
        const result = evaluate(slice, request, inner);
        if (!result.ok) return result;
        if (result.value) return ok(true);
      }
      return ok(false);
    }
    case "Not": {
      const result = evaluate(slice, request, condition.condition);
      return result.ok ? ok(!result.value) : result;
    }
    case "Eq": {
      const left = evaluateOperand(slice, request, condition.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, condition.right);
      if (!right.ok) return right;
      return ok(Entity.attributeValueEquals(left.value, right.value));
    }
    case "Compare": {
      const left = evaluateOperand(slice, request, condition.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, condition.right);
      if (!right.ok) return right;
      if (typeof left.value !== "number" || typeof right.value !== "number") {
        return err(
          `comparison "${condition.op}" requires numbers (got ${typeof left.value} and ${typeof right.value})`,
        );
      }
      switch (condition.op) {
        case "lt":
          return ok(left.value < right.value);
        case "lte":
          return ok(left.value <= right.value);
        case "gt":
          return ok(left.value > right.value);
        case "gte":
          return ok(left.value >= right.value);
      }
    }
    // eslint-disable-next-line no-fallthrough -- every Compare op returns above
    case "Contains": {
      const collection = evaluateOperand(slice, request, condition.collection);
      if (!collection.ok) return collection;
      const value = evaluateOperand(slice, request, condition.value);
      if (!value.ok) return value;
      if (!Array.isArray(collection.value)) {
        return err(`contains requires an array collection (got ${typeof collection.value})`);
      }
      return ok(collection.value.some((item) => Entity.attributeValueEquals(item, value.value)));
    }
    case "In": {
      const left = evaluateOperand(slice, request, condition.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, condition.right);
      if (!right.ok) return right;
      if (!Entity.isEntityValue(left.value) || !Entity.isEntityValue(right.value)) {
        return err(`in requires entity operands`);
      }
      return ok(Entity.entityIn(slice, left.value.__entity, right.value.__entity));
    }
    case "Has": {
      const result = resolvePath(
        slotRoot(slice, request, condition.of),
        condition.path,
        condition.path.join("."),
      );
      return ok(result.ok);
    }
  }
};
