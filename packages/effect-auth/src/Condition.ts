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
 * @module condition
 */
import { Array as Arr, Match, Predicate, Schema } from "effect";
import * as Entity from "./Entity.ts";

// ---------------------------------------------------------------------------
// Operand AST: expressions that produce a value
// ---------------------------------------------------------------------------

/** The four request slots an operand can reference. */
export const RequestSlot = Schema.Literals(["principal", "action", "resource", "context"]);
export type RequestSlot = typeof RequestSlot.Type;

/** A literal {@link Entity.AttributeValue}. */
export const Lit = Schema.TaggedStruct("Lit", {
  value: Entity.AttributeValue,
});
export type Lit = typeof Lit.Type;

/**
 * An attribute read: `Attr("resource", ["owner"])` is `resource.owner`.
 * Paths with several segments traverse nested record values. Reading an
 * attribute that is absent (or traversing through a non-record) is an
 * evaluation error — guard with {@link Has} where absence is expected.
 */
export const Attr = Schema.TaggedStruct("Attr", {
  of: RequestSlot,
  path: Schema.Array(Schema.String).check(Schema.isMinLength(1)),
});
export type Attr = typeof Attr.Type;

/** The request's principal/action/resource reference itself, as a value. */
export const SlotRef = Schema.TaggedStruct("SlotRef", {
  of: Schema.Literals(["principal", "action", "resource"]),
});
export type SlotRef = typeof SlotRef.Type;

/** A value a condition compares: a literal, an attribute read, or a request slot reference. */
export const Operand = Schema.Union([Lit, Attr, SlotRef]);
export type Operand = typeof Operand.Type;

// ---------------------------------------------------------------------------
// Condition AST: expressions that produce a boolean
// ---------------------------------------------------------------------------

/** Holds when every condition in `conditions` holds. */
export interface And {
  readonly _tag: "And";
  readonly conditions: ReadonlyArray<Condition>;
}
/** Holds when at least one condition in `conditions` holds. */
export interface Or {
  readonly _tag: "Or";
  readonly conditions: ReadonlyArray<Condition>;
}
/** Holds when `condition` does not. */
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

/**
 * A serializable boolean expression over the request: the condition language of declarative policies, evaluated purely and totally.
 */
export type Condition = And | Or | Not | Eq | Compare | Contains | In | Has;

export const Condition: Schema.Codec<Condition> = Schema.Union([
  Schema.TaggedStruct("And", {
    conditions: Schema.Array(Schema.suspend((): Schema.Codec<Condition> => Condition)),
  }),
  Schema.TaggedStruct("Or", {
    conditions: Schema.Array(Schema.suspend((): Schema.Codec<Condition> => Condition)),
  }),
  Schema.TaggedStruct("Not", {
    condition: Schema.suspend((): Schema.Codec<Condition> => Condition),
  }),
  Schema.TaggedStruct("Eq", { left: Operand, right: Operand }),
  Schema.TaggedStruct("Compare", {
    op: Schema.Literals(["lt", "lte", "gt", "gte"]),
    left: Operand,
    right: Operand,
  }),
  Schema.TaggedStruct("Contains", { collection: Operand, value: Operand }),
  Schema.TaggedStruct("In", { left: Operand, right: Operand }),
  Schema.TaggedStruct("Has", {
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

/** Condition that holds when every operand condition holds. */
export const and = (...conditions: ReadonlyArray<Condition>): And => ({
  _tag: "And",
  conditions,
});
/** Condition that holds when at least one operand condition holds. */
export const or = (...conditions: ReadonlyArray<Condition>): Or => ({ _tag: "Or", conditions });
/** Condition that holds when `condition` does not. */
export const not = (condition: Condition): Not => ({ _tag: "Not", condition });
/** Condition that holds when the two operands are deeply equal. */
export const eq = (left: Operand, right: Operand): Eq => ({ _tag: "Eq", left, right });
/** Condition that holds when the two operands are not deeply equal. */
export const ne = (left: Operand, right: Operand): Not => not(eq(left, right));
/** Condition that holds when `left` is less than `right`; both must evaluate to numbers. */
export const lt = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "lt",
  left,
  right,
});
/**
 * Condition that holds when `left` is less than or equal to `right`; both must evaluate to numbers.
 */
export const lte = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "lte",
  left,
  right,
});
/** Condition that holds when `left` is greater than `right`; both must evaluate to numbers. */
export const gt = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "gt",
  left,
  right,
});
/**
 * Condition that holds when `left` is greater than or equal to `right`; both must evaluate to numbers.
 */
export const gte = (left: Operand, right: Operand): Compare => ({
  _tag: "Compare",
  op: "gte",
  left,
  right,
});
/** Condition that holds when the array `collection` contains `value`. */
export const contains = (collection: Operand, value: Operand): Contains => ({
  _tag: "Contains",
  collection,
  value,
});
/** Hierarchy membership condition (see {@link In}). */
export const isIn = (left: Operand, right: Operand): In => ({ _tag: "In", left, right });
/** Condition that holds when the request slot has the attribute at `path`; never errors. */
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

const describeOperand = (operand: Operand): string =>
  Match.valueTags(operand, {
    Lit: () => "literal",
    Attr: (attr) => `${attr.of}.${attr.path.join(".")}`,
    SlotRef: (slot) => slot.of,
  });

/** The `typeof` of an attribute value, for error messages. */
const typeName = (value: Entity.AttributeValue): string =>
  Predicate.isString(value)
    ? "string"
    : Predicate.isNumber(value)
      ? "number"
      : Predicate.isBoolean(value)
        ? "boolean"
        : "object";

/** The attribute record at `value`, or `null` when a path cannot descend into it. */
const attributeRecord = (
  value: Entity.AttributeValue | null,
): { readonly [key: string]: Entity.AttributeValue } | null =>
  value === null || !Predicate.isObject(value) || Entity.isEntityValue(value) ? null : value;

const resolvePath = (
  root: Entity.AttributeValue | null,
  path: ReadonlyArray<string>,
  describe: string,
): EvalResult<Entity.AttributeValue> => {
  // `null` is absent: once a segment is missing (or not a record), it stays absent.
  const resolved = Arr.reduce(path, root, (current: Entity.AttributeValue | null, segment) => {
    const record = attributeRecord(current);
    return record !== null && segment in record ? (record[segment] ?? null) : null;
  });
  return resolved === null ? err(`attribute "${describe}" is absent`) : ok(resolved);
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

/**
 * Evaluate one operand over a slice and request: its value, or a
 * {@link ConditionError} when it reads an absent attribute. The read-scope
 * compiler (`ReadScope.compile`) uses it for the operands that don't depend
 * on the row, so they evaluate exactly as the kernel evaluates them.
 */
export const evaluateOperand = (
  slice: Entity.EntitySlice,
  request: ConditionRequest,
  operand: Operand,
): EvalResult<Entity.AttributeValue> =>
  Match.valueTags(operand, {
    Lit: (lit) => ok(lit.value),
    SlotRef: (slot) => ok<Entity.AttributeValue>(Entity.entityValue(request[slot.of])),
    Attr: (attr) =>
      resolvePath(slotRoot(slice, request, attr.of), attr.path, describeOperand(attr)),
  });

/**
 * Evaluate a condition over a slice and request. Pure and total: the result
 * is a boolean or a {@link ConditionError}, never an exception.
 */
export const evaluate = (
  slice: Entity.EntitySlice,
  request: ConditionRequest,
  condition: Condition,
): EvalResult<boolean> =>
  Match.valueTags(condition, {
    // First error or first `false` wins; the rest are not evaluated.
    And: ({ conditions }) =>
      Arr.reduce(conditions, ok(true), (acc, inner) =>
        acc.ok && acc.value ? evaluate(slice, request, inner) : acc,
      ),
    // First error or first `true` wins; the rest are not evaluated.
    Or: ({ conditions }) =>
      Arr.reduce(conditions, ok(false), (acc, inner) =>
        acc.ok && !acc.value ? evaluate(slice, request, inner) : acc,
      ),
    Not: (not): EvalResult<boolean> => {
      const result = evaluate(slice, request, not.condition);
      return result.ok ? ok(!result.value) : result;
    },
    Eq: (eq): EvalResult<boolean> => {
      const left = evaluateOperand(slice, request, eq.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, eq.right);
      if (!right.ok) return right;
      return ok(Entity.attributeValueEquals(left.value, right.value));
    },
    Compare: (compare): EvalResult<boolean> => {
      const left = evaluateOperand(slice, request, compare.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, compare.right);
      if (!right.ok) return right;
      const l = left.value;
      const r = right.value;
      if (!Predicate.isNumber(l) || !Predicate.isNumber(r)) {
        return err(
          `comparison "${compare.op}" requires numbers (got ${typeName(l)} and ${typeName(r)})`,
        );
      }
      return ok(
        Match.value(compare.op).pipe(
          Match.when("lt", () => l < r),
          Match.when("lte", () => l <= r),
          Match.when("gt", () => l > r),
          Match.when("gte", () => l >= r),
          Match.exhaustive,
        ),
      );
    },
    Contains: (contains): EvalResult<boolean> => {
      const collection = evaluateOperand(slice, request, contains.collection);
      if (!collection.ok) return collection;
      const value = evaluateOperand(slice, request, contains.value);
      if (!value.ok) return value;
      if (!Array.isArray(collection.value)) {
        return err(`contains requires an array collection (got ${typeName(collection.value)})`);
      }
      return ok(collection.value.some((item) => Entity.attributeValueEquals(item, value.value)));
    },
    In: (inCondition): EvalResult<boolean> => {
      const left = evaluateOperand(slice, request, inCondition.left);
      if (!left.ok) return left;
      const right = evaluateOperand(slice, request, inCondition.right);
      if (!right.ok) return right;
      if (!Entity.isEntityValue(left.value) || !Entity.isEntityValue(right.value)) {
        return err(`in requires entity operands`);
      }
      return ok(Entity.entityIn(slice, left.value.__entity, right.value.__entity));
    },
    Has: (has): EvalResult<boolean> => {
      const result = resolvePath(slotRoot(slice, request, has.of), has.path, has.path.join("."));
      return ok(result.ok);
    },
  });
