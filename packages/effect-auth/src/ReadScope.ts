/**
 * The read scope: what a policy set compiles to when it is evaluated as a set
 * of rows rather than at one row.
 *
 * A single-row check asks "may this principal read this resource". A LIST asks
 * "which rows may this principal read", and the answer has to reach the
 * database: filtering a page after the fact returns short pages, breaks
 * totals, and reads rows the viewer was never entitled to. {@link ReadScope} is
 * that answer, in a form this library owns and every adapter projects from
 * (ADR-0020):
 *
 * - {@link AllowAll}: every row. A privileged role short-circuits to this
 *   branch, so the renderer emits no filter at all rather than a disjunction
 *   over every axis.
 * - {@link Deny}: no row. The renderer emits no query.
 * - {@link Filter}: the rows a {@link Predicate} admits.
 *
 * ### The predicate is bound-scalar
 *
 * A {@link Predicate} compares a resource attribute (a column, once an adapter
 * binds it) with a {@link Scalar}: text, integer, double, boolean or instant.
 * That is the value domain a database binds as a parameter, and nothing else:
 * no entity hierarchy, no arrays, no nested records. It is not effect-jsonapi's
 * `Filter.Ast` (a wire grammar, typed per resource over decoded attribute
 * values) and not legation's subset predicate (an engine grammar). Both are
 * projection targets, written where they are needed.
 *
 * ### Two-valued by construction
 *
 * Every atom is decided: {@link Eq} and {@link Compare} hold only for a present
 * attribute, and absence is its own atom, {@link IsNull}. A projection to SQL
 * therefore never meets SQL's third truth value: `NOT (x = 'a')` over a NULL
 * `x` can't silently admit or exclude a row, because the predicate states what
 * a NULL does. (The kernel treats an absent attribute as an evaluation error,
 * and its error handling is what the compiler encodes into those atoms.)
 *
 * ### Relationships are named sets
 *
 * "The owner is someone the viewer follows" is an {@link InSet} atom: the
 * attribute, and the *name* of a set the application resolves (a subquery, a
 * semi-join). The predicate never carries the set's members, so its authored
 * form is stable across requests and nothing is resolved per row. A set the
 * runtime can't resolve narrows the scope ({@link withoutSets}); it never
 * widens it.
 *
 * @module read-scope
 */
import { Array as Arr, Match, Order, Predicate as P, Struct } from "effect";
import * as Condition from "./Condition.ts";
import * as Entity from "./Entity.ts";
import * as Policy from "./Policy.ts";

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/**
 * A value a database binds as a parameter, the only kind of value a
 * {@link Predicate} compares an attribute with. `Instant` is epoch
 * milliseconds, the form effect-auth-sql stores timestamps in.
 *
 * @since 1.0.0
 * @category models
 */
export type Scalar =
  | { readonly _tag: "Text"; readonly value: string }
  | { readonly _tag: "Integer"; readonly value: number }
  | { readonly _tag: "Double"; readonly value: number }
  | { readonly _tag: "Boolean"; readonly value: boolean }
  | { readonly _tag: "Instant"; readonly value: number };

/**
 * The kind of a {@link Scalar}.
 *
 * @since 1.0.0
 * @category models
 */
export type ScalarKind = Scalar["_tag"];

/**
 * A text scalar.
 *
 * @since 1.0.0
 * @category constructors
 */
export const text = (value: string): Scalar => ({ _tag: "Text", value });

/**
 * An integer scalar.
 *
 * @since 1.0.0
 * @category constructors
 */
export const integer = (value: number): Scalar => ({ _tag: "Integer", value });

/**
 * A double scalar.
 *
 * @since 1.0.0
 * @category constructors
 */
export const double = (value: number): Scalar => ({ _tag: "Double", value });

/**
 * A boolean scalar.
 *
 * @since 1.0.0
 * @category constructors
 */
export const boolean = (value: boolean): Scalar => ({ _tag: "Boolean", value });

/**
 * An instant scalar, in epoch milliseconds.
 *
 * @since 1.0.0
 * @category constructors
 */
export const instant = (epochMillis: number): Scalar => ({ _tag: "Instant", value: epochMillis });

// ---------------------------------------------------------------------------
// Predicate
// ---------------------------------------------------------------------------

/**
 * Holds when every predicate in `predicates` holds.
 *
 * @since 1.0.0
 * @category models
 */
export interface And {
  readonly _tag: "And";
  readonly predicates: ReadonlyArray<Predicate>;
}

/**
 * Holds when at least one predicate in `predicates` holds.
 *
 * @since 1.0.0
 * @category models
 */
export interface Or {
  readonly _tag: "Or";
  readonly predicates: ReadonlyArray<Predicate>;
}

/**
 * Holds when `predicate` does not.
 *
 * @since 1.0.0
 * @category models
 */
export interface Not {
  readonly _tag: "Not";
  readonly predicate: Predicate;
}

/**
 * Holds when `attribute` is present and equal to `value`. An absent attribute
 * makes it false, never unknown.
 *
 * @since 1.0.0
 * @category models
 */
export interface Eq {
  readonly _tag: "Eq";
  readonly attribute: string;
  readonly value: Scalar;
}

/**
 * Holds when `attribute` is present and `attribute op value` holds.
 *
 * @since 1.0.0
 * @category models
 */
export interface Compare {
  readonly _tag: "Compare";
  readonly op: "lt" | "lte" | "gt" | "gte";
  readonly attribute: string;
  readonly value: Scalar;
}

/**
 * Holds when `attribute` is absent (SQL `NULL`).
 *
 * @since 1.0.0
 * @category models
 */
export interface IsNull {
  readonly _tag: "IsNull";
  readonly attribute: string;
}

/**
 * Holds when `attribute` is present and a member of the named set `set`. The
 * set is resolved by the application: a subquery for a list, a membership test
 * for one row.
 *
 * @since 1.0.0
 * @category models
 */
export interface InSet {
  readonly _tag: "InSet";
  readonly attribute: string;
  readonly set: string;
}

/**
 * A two-valued boolean expression over one resource's attributes, comparing
 * them only with {@link Scalar}s and named sets.
 *
 * @since 1.0.0
 * @category models
 */
export type Predicate = And | Or | Not | Eq | Compare | IsNull | InSet;

// ---------------------------------------------------------------------------
// Read scope
// ---------------------------------------------------------------------------

/**
 * Every row: a renderer emits no filter.
 *
 * @since 1.0.0
 * @category models
 */
export interface AllowAll {
  readonly _tag: "AllowAll";
}

/**
 * No row: a renderer need not query at all.
 *
 * @since 1.0.0
 * @category models
 */
export interface Deny {
  readonly _tag: "Deny";
}

/**
 * The rows `predicate` admits. `sets` names every set the predicate refers to,
 * sorted, so a renderer can check it can resolve each before it renders.
 *
 * @since 1.0.0
 * @category models
 */
export interface Filter {
  readonly _tag: "Filter";
  readonly predicate: Predicate;
  readonly sets: ReadonlyArray<string>;
}

/**
 * Which rows a principal may read: all of them, none of them, or the ones a
 * {@link Predicate} admits.
 *
 * @since 1.0.0
 * @category models
 */
export type ReadScope = AllowAll | Deny | Filter;

/**
 * The scope that admits every row.
 *
 * @since 1.0.0
 * @category constructors
 */
export const allowAll: ReadScope = { _tag: "AllowAll" };

/**
 * The scope that admits no row.
 *
 * @since 1.0.0
 * @category constructors
 */
export const deny: ReadScope = { _tag: "Deny" };

// ---------------------------------------------------------------------------
// Simplifying constructors
// ---------------------------------------------------------------------------

/** A predicate under construction; constants fold away before one is returned. */
type Expr = Predicate | boolean;

const conjunction = (parts: ReadonlyArray<Expr>): Expr => {
  if (parts.includes(false)) return false;
  const terms = parts
    .filter((part): part is Predicate => part !== true)
    .flatMap((part): ReadonlyArray<Predicate> =>
      P.isTagged(part, "And") ? part.predicates : [part],
    );
  return Arr.match(terms, {
    onEmpty: (): Expr => true,
    onNonEmpty: (all): Expr =>
      all.length === 1 ? Arr.headNonEmpty(all) : { _tag: "And", predicates: all },
  });
};

const disjunction = (parts: ReadonlyArray<Expr>): Expr => {
  if (parts.includes(true)) return true;
  const terms = parts
    .filter((part): part is Predicate => part !== false)
    .flatMap((part): ReadonlyArray<Predicate> =>
      P.isTagged(part, "Or") ? part.predicates : [part],
    );
  return Arr.match(terms, {
    onEmpty: (): Expr => false,
    onNonEmpty: (all): Expr =>
      all.length === 1 ? Arr.headNonEmpty(all) : { _tag: "Or", predicates: all },
  });
};

const negation = (part: Expr): Expr =>
  P.isBoolean(part)
    ? !part
    : P.isTagged(part, "Not")
      ? part.predicate
      : { _tag: "Not", predicate: part };

const setsOf = (predicate: Predicate): ReadonlyArray<string> =>
  Match.valueTags(predicate, {
    And: ({ predicates }) => Arr.flatMap(predicates, setsOf),
    Or: ({ predicates }) => Arr.flatMap(predicates, setsOf),
    Not: ({ predicate: inner }) => setsOf(inner),
    Eq: () => [],
    Compare: () => [],
    IsNull: () => [],
    InSet: ({ set }) => [set],
  });

/**
 * Every attribute a predicate reads, sorted and without repeats: what a
 * renderer must have a column for.
 *
 * @since 1.0.0
 * @category evaluation
 */
export const attributes = (predicate: Predicate): ReadonlyArray<string> => {
  const read = (inner: Predicate): ReadonlyArray<string> =>
    Match.valueTags(inner, {
      And: ({ predicates }) => Arr.flatMap(predicates, read),
      Or: ({ predicates }) => Arr.flatMap(predicates, read),
      Not: ({ predicate: negated }) => read(negated),
      Eq: ({ attribute }) => [attribute],
      Compare: ({ attribute }) => [attribute],
      IsNull: ({ attribute }) => [attribute],
      InSet: ({ attribute }) => [attribute],
    });
  return Arr.dedupe(Arr.sort(read(predicate), Order.String));
};

const toScope = (expr: Expr): ReadScope =>
  P.isBoolean(expr)
    ? expr
      ? allowAll
      : deny
    : { _tag: "Filter", predicate: expr, sets: Arr.dedupe(Arr.sort(setsOf(expr), Order.String)) };

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/**
 * What a resource attribute holds, as the compiler needs to know it: one of
 * the {@link ScalarKind}s, or `{ entity: type }` for an attribute whose value
 * is an entity reference of one type, bound as that entity's id (text).
 *
 * @since 1.0.0
 * @category models
 */
export type AttributeKind = ScalarKind | { readonly entity: string };

/**
 * A context fact that is a set membership rather than a value: while
 * compiling, `context[<key>]` is read as "`resource[attribute]` is in the
 * named set `set`". The row-level decision supplies the fact as a boolean;
 * the compiled scope names the set instead.
 *
 * @since 1.0.0
 * @category models
 */
export interface SetFact {
  readonly attribute: string;
  readonly set: string;
}

/**
 * The binding a policy set is compiled against: the resource type the scope
 * is for, the attributes a predicate may read and what each holds, and the
 * context facts that are set memberships.
 *
 * @since 1.0.0
 * @category models
 */
export interface Binding {
  readonly resourceType: string;
  readonly attributes: Readonly<Record<string, AttributeKind>>;
  readonly setFacts?: Readonly<Record<string, SetFact>> | undefined;
}

/**
 * The request a scope is compiled for: everything a decision needs except the
 * resource. `slice` holds the principal's side (its entity and ancestors);
 * `context` the request context, without the set facts.
 *
 * @since 1.0.0
 * @category models
 */
export interface ScopeRequest {
  readonly principal: Entity.EntityRef;
  readonly action: Entity.EntityRef;
  readonly context?: Readonly<Record<string, Entity.AttributeValue>> | undefined;
  readonly slice?: Entity.EntitySlice | undefined;
}

/**
 * A compilation result: the scope, when the policy set compiles exactly, or
 * the reasons it doesn't. An inexact policy set has no scope, because an
 * approximate filter is either a privacy leak or a wrong total.
 *
 * @since 1.0.0
 * @category models
 */
export type Compiled =
  | { readonly _tag: "Exact"; readonly scope: ReadScope }
  | { readonly _tag: "Inexact"; readonly reasons: ReadonlyArray<string> };

/**
 * A condition, partially evaluated: the rows on which it is true, false, and an
 * evaluation error (the kernel's three outcomes). The three always partition
 * the rows, which is what lets a forbid deny on an error.
 */
interface Outcomes {
  readonly t: Expr;
  readonly f: Expr;
  readonly e: Expr;
}

type Partial = { readonly _tag: "Ok"; readonly outcomes: Outcomes } | Unsupported;
interface Unsupported {
  readonly _tag: "Unsupported";
  readonly reasons: ReadonlyArray<string>;
}

const unsupported = (reason: string): Unsupported => ({ _tag: "Unsupported", reasons: [reason] });
const decided = (outcomes: Outcomes): Partial => ({ _tag: "Ok", outcomes });
const constant = (value: boolean): Partial => decided({ t: value, f: !value, e: false });
const errored: Partial = decided({ t: false, f: false, e: true });

/** An operand, resolved as far as the request allows. */
type Operand =
  | { readonly _tag: "Known"; readonly value: Entity.AttributeValue }
  | { readonly _tag: "Absent" }
  | { readonly _tag: "Attribute"; readonly name: string; readonly kind: AttributeKind }
  | { readonly _tag: "Fact"; readonly fact: SetFact }
  | Unsupported;

const isNull = (attribute: string): Predicate => ({ _tag: "IsNull", attribute });
const present = (attribute: string): Expr => negation(isNull(attribute));
const member = (fact: SetFact): Predicate => ({
  _tag: "InSet",
  attribute: fact.attribute,
  set: fact.set,
});

/** The atom "`name` is present and equals `value`", or `false` when no value of `kind` can. */
const equalsAtom = (name: string, kind: AttributeKind, value: Entity.AttributeValue): Expr => {
  const atom = (scalar: Scalar): Expr => ({ _tag: "Eq", attribute: name, value: scalar });
  if (!P.isString(kind)) {
    return P.isObject(value) && Entity.isEntityValue(value) && value.__entity.type === kind.entity
      ? atom(text(value.__entity.id))
      : false;
  }
  return Match.value(kind).pipe(
    Match.when("Text", () => (P.isString(value) ? atom(text(value)) : false)),
    Match.when("Boolean", () => (P.isBoolean(value) ? atom(boolean(value)) : false)),
    Match.when("Integer", () =>
      P.isNumber(value) && Number.isInteger(value) ? atom(integer(value)) : false,
    ),
    Match.when("Double", () => (P.isNumber(value) ? atom(double(value)) : false)),
    Match.when("Instant", () => (P.isNumber(value) ? atom(instant(value)) : false)),
    Match.exhaustive,
  );
};

const numericScalar = (kind: AttributeKind, value: number): Scalar | null =>
  kind === "Integer"
    ? integer(value)
    : kind === "Double"
      ? double(value)
      : kind === "Instant"
        ? instant(value)
        : null;

interface Env {
  readonly binding: Binding;
  readonly request: Policy.PolicyRequest;
  readonly slice: Entity.EntitySlice;
}

const resolveOperand = (env: Env, operand: Condition.Operand): Operand =>
  Match.valueTags(operand, {
    Lit: ({ value }): Operand => ({ _tag: "Known", value }),
    SlotRef: ({ of }): Operand =>
      of === "resource"
        ? unsupported("the resource reference itself is not a bound attribute")
        : { _tag: "Known", value: Entity.entityValue(env.request[of]) },
    Attr: (attr): Operand => {
      if (attr.of === "resource") {
        const [name, ...rest] = attr.path;
        const kind = name === undefined ? undefined : env.binding.attributes[name];
        return kind === undefined || name === undefined || Arr.isReadonlyArrayNonEmpty(rest)
          ? unsupported(`resource.${attr.path.join(".")} is not a bound attribute`)
          : { _tag: "Attribute", name, kind };
      }
      const [head, ...rest] = attr.path;
      const fact =
        attr.of === "context" && head !== undefined ? env.binding.setFacts?.[head] : undefined;
      if (fact !== undefined) {
        // A set fact is a boolean: it has no fields to read.
        return Arr.isReadonlyArrayEmpty(rest) ? { _tag: "Fact", fact } : { _tag: "Absent" };
      }
      const evaluated = Condition.evaluateOperand(env.slice, env.request, attr);
      return evaluated.ok ? { _tag: "Known", value: evaluated.value } : { _tag: "Absent" };
    },
  });

const flip = (op: Compare["op"]): Compare["op"] =>
  op === "lt" ? "gt" : op === "gt" ? "lt" : op === "lte" ? "gte" : "lte";

/** `Eq` with one side bound to a row: the attribute or the set fact against a known value. */
const equalsRow = (row: Operand, value: Entity.AttributeValue): Partial => {
  if (P.isTagged(row, "Fact")) {
    const inSet = member(row.fact);
    return value === true
      ? decided({ t: inSet, f: negation(inSet), e: false })
      : value === false
        ? decided({ t: negation(inSet), f: inSet, e: false })
        : constant(false);
  }
  if (!P.isTagged(row, "Attribute")) return unsupported("internal: not a row operand");
  const atom = equalsAtom(row.name, row.kind, value);
  return decided({
    t: atom,
    f: conjunction([present(row.name), negation(atom)]),
    e: isNull(row.name),
  });
};

/** `Compare` with the attribute on the left: `attribute op value`. */
const compareRow = (row: Operand, op: Compare["op"], value: Entity.AttributeValue): Partial => {
  // A set fact is a boolean, never a number: the comparison errors.
  if (!P.isTagged(row, "Attribute")) return errored;
  const scalar = P.isNumber(value) ? numericScalar(row.kind, value) : null;
  if (scalar === null) return errored;
  const atom: Predicate = { _tag: "Compare", op, attribute: row.name, value: scalar };
  return decided({
    t: atom,
    f: conjunction([present(row.name), negation(atom)]),
    e: isNull(row.name),
  });
};

const isRow = (operand: Operand): boolean =>
  P.isTagged(operand, "Attribute") || P.isTagged(operand, "Fact");

const binary = (
  left: Operand,
  right: Operand,
  onRow: (row: Operand, value: Entity.AttributeValue, rowOnLeft: boolean) => Partial,
): Partial => {
  if (P.isTagged(left, "Unsupported")) return left;
  if (P.isTagged(right, "Unsupported")) return right;
  // Either side failing to evaluate makes the whole comparison an error, on every row.
  if (P.isTagged(left, "Absent") || P.isTagged(right, "Absent")) return errored;
  if (isRow(left) && isRow(right)) return unsupported("a comparison between two row values");
  if (P.isTagged(left, "Known") && isRow(right)) return onRow(right, left.value, false);
  if (P.isTagged(right, "Known") && isRow(left)) return onRow(left, right.value, true);
  return unsupported("internal: a comparison with no row operand");
};

/** Whether a condition reads anything of the row (a resource attribute or a set fact). */
const readsRow = (binding: Binding, condition: Condition.Condition): boolean => {
  const operandReads = (operand: Condition.Operand): boolean =>
    Match.valueTags(operand, {
      Lit: () => false,
      SlotRef: ({ of }) => of === "resource",
      Attr: ({ of, path }) =>
        of === "resource" ||
        (of === "context" && path[0] !== undefined && binding.setFacts?.[path[0]] !== undefined),
    });
  return Match.valueTags(condition, {
    And: ({ conditions }) => conditions.some((inner) => readsRow(binding, inner)),
    Or: ({ conditions }) => conditions.some((inner) => readsRow(binding, inner)),
    Not: ({ condition: inner }) => readsRow(binding, inner),
    Eq: ({ left, right }) => operandReads(left) || operandReads(right),
    Compare: ({ left, right }) => operandReads(left) || operandReads(right),
    Contains: ({ collection, value }) => operandReads(collection) || operandReads(value),
    In: ({ left, right }) => operandReads(left) || operandReads(right),
    Has: ({ of, path }) =>
      of === "resource" ||
      (of === "context" && path[0] !== undefined && binding.setFacts?.[path[0]] !== undefined),
  });
};

const combine = (
  parts: ReadonlyArray<Partial>,
  step: (acc: Outcomes, next: Outcomes) => Outcomes,
  initial: Outcomes,
): Partial => {
  const reasons = Arr.flatMap(parts, (part) =>
    P.isTagged(part, "Unsupported") ? part.reasons : [],
  );
  if (Arr.isReadonlyArrayNonEmpty(reasons)) return { _tag: "Unsupported", reasons };
  return decided(
    Arr.reduce(parts, initial, (acc, part) =>
      P.isTagged(part, "Ok") ? step(acc, part.outcomes) : acc,
    ),
  );
};

/**
 * Partially evaluate a condition over the unbound row. `And` and `Or` follow
 * the kernel's left-to-right short circuit: the first `false` (or `true`) or
 * the first error decides, so a later operand only counts on the rows where
 * every earlier one was true (or false).
 */
const partial = (env: Env, condition: Condition.Condition): Partial => {
  if (!readsRow(env.binding, condition)) {
    const result = Condition.evaluate(env.slice, env.request, condition);
    return result.ok ? constant(result.value) : errored;
  }
  return Match.valueTags(condition, {
    And: ({ conditions }) =>
      combine(
        Arr.map(conditions, (inner) => partial(env, inner)),
        (acc, next) => ({
          t: conjunction([acc.t, next.t]),
          f: disjunction([acc.f, conjunction([acc.t, next.f])]),
          e: disjunction([acc.e, conjunction([acc.t, next.e])]),
        }),
        { t: true, f: false, e: false },
      ),
    Or: ({ conditions }) =>
      combine(
        Arr.map(conditions, (inner) => partial(env, inner)),
        (acc, next) => ({
          t: disjunction([acc.t, conjunction([acc.f, next.t])]),
          f: conjunction([acc.f, next.f]),
          e: disjunction([acc.e, conjunction([acc.f, next.e])]),
        }),
        { t: false, f: true, e: false },
      ),
    Not: ({ condition: inner }): Partial => {
      const result = partial(env, inner);
      return P.isTagged(result, "Ok")
        ? decided({ t: result.outcomes.f, f: result.outcomes.t, e: result.outcomes.e })
        : result;
    },
    Eq: ({ left, right }) =>
      binary(resolveOperand(env, left), resolveOperand(env, right), (row, value) =>
        equalsRow(row, value),
      ),
    Compare: ({ op, left, right }) =>
      binary(resolveOperand(env, left), resolveOperand(env, right), (row, value, rowOnLeft) =>
        compareRow(row, rowOnLeft ? op : flip(op), value),
      ),
    Contains: () => unsupported("array `contains` over a row value"),
    In: () => unsupported("entity-hierarchy `in` over a row value"),
    Has: ({ of, path }): Partial => {
      const [head, ...rest] = path;
      if (of === "context") return constant(Arr.isReadonlyArrayEmpty(rest));
      const kind = head === undefined ? undefined : env.binding.attributes[head];
      return kind === undefined || head === undefined || Arr.isReadonlyArrayNonEmpty(rest)
        ? unsupported(`resource.${path.join(".")} is not a bound attribute`)
        : decided({ t: present(head), f: isNull(head), e: false });
    },
  });
};

/** The resource a compile stands in for the unbound row: never in the slice. */
const placeholder = (binding: Binding): Entity.EntityRef => Entity.ref(binding.resourceType, "");

/** Whether a policy's principal and action scopes apply, decided by the kernel itself. */
const scopesApply = (env: Env, policy: Policy.DeclarativePolicy): boolean =>
  Policy.decidePure(
    [{ ...Struct.omit(policy, ["when"]), resource: Policy.any }],
    env.request,
    env.slice,
  ).outcomes.some((outcome) => outcome.result === "matched");

/** Whether a policy's resource scope can apply to rows of the bound type: `null` when it is undecidable. */
const resourceScopeApplies = (binding: Binding, scope: Policy.Scope): boolean | null =>
  Match.valueTags(scope, {
    any: () => true,
    is: ({ entityType }) => entityType === binding.resourceType,
    // One named resource, or a hierarchy: neither is a column of the row.
    eq: ({ ref }) => (ref.type === binding.resourceType ? null : false),
    in: () => null,
  });

const policyOutcomes = (env: Env, policy: Policy.DeclarativePolicy): Partial => {
  const resourceScope = resourceScopeApplies(env.binding, policy.resource);
  if (resourceScope === false || !scopesApply(env, policy)) return constant(false);
  if (resourceScope === null) {
    return unsupported(`policy ${policy.id}: a resource scope naming one resource or a hierarchy`);
  }
  if (policy.when === undefined) return constant(true);
  const outcomes = partial(env, policy.when);
  return P.isTagged(outcomes, "Ok")
    ? outcomes
    : {
        _tag: "Unsupported",
        reasons: Arr.map(outcomes.reasons, (reason) => `policy ${policy.id}: ${reason}`),
      };
};

/**
 * Compile a declarative policy set into the read scope of one principal and
 * action over every resource of `binding.resourceType`.
 *
 * The scope admits exactly the rows `Policy.decidePure` would allow, with each
 * row's attributes in the resource entity and each set fact in the context.
 * When some applicable policy reads the row in a way a {@link Predicate} can't
 * express, the result is `Inexact` with the reasons, never an approximation.
 *
 * @since 1.0.0
 * @category compilation
 */
export const compile = (
  policies: ReadonlyArray<Policy.DeclarativePolicy>,
  binding: Binding,
  request: ScopeRequest,
): Compiled => {
  const env: Env = {
    binding,
    request: Policy.request({
      principal: request.principal,
      action: request.action,
      resource: placeholder(binding),
      context: request.context ?? {},
    }),
    slice: request.slice ?? Entity.emptySlice,
  };
  const evaluated = Arr.map(policies, (policy) => ({
    policy,
    outcome: policyOutcomes(env, policy),
  }));
  const reasons = Arr.flatMap(evaluated, ({ outcome }) =>
    P.isTagged(outcome, "Unsupported") ? outcome.reasons : [],
  );
  if (Arr.isReadonlyArrayNonEmpty(reasons)) return { _tag: "Inexact", reasons };
  const ok = Arr.flatMap(evaluated, ({ policy, outcome }) =>
    P.isTagged(outcome, "Ok") ? [{ effect: policy.effect, outcomes: outcome.outcomes }] : [],
  );
  // A matched permit grants; a matched or errored forbid denies, and wins.
  const permitted = disjunction(
    Arr.map(
      Arr.filter(ok, ({ effect }) => effect === "permit"),
      ({ outcomes }) => outcomes.t,
    ),
  );
  const forbidden = disjunction(
    Arr.map(
      Arr.filter(ok, ({ effect }) => effect === "forbid"),
      ({ outcomes }) => disjunction([outcomes.t, outcomes.e]),
    ),
  );
  return { _tag: "Exact", scope: toScope(conjunction([permitted, negation(forbidden)])) };
};

// ---------------------------------------------------------------------------
// Using a scope
// ---------------------------------------------------------------------------

/**
 * One row's attribute values, as a renderer binds them: a scalar's value, or
 * `null` / `undefined` for an absent attribute. An entity-valued attribute
 * holds the entity's id.
 *
 * @since 1.0.0
 * @category models
 */
export type Row = Readonly<Record<string, string | number | boolean | null | undefined>>;

const holds = (
  predicate: Predicate,
  row: Row,
  inSet: (set: string, value: string | number | boolean) => boolean,
): boolean =>
  Match.valueTags(predicate, {
    And: ({ predicates }) => predicates.every((inner) => holds(inner, row, inSet)),
    Or: ({ predicates }) => predicates.some((inner) => holds(inner, row, inSet)),
    Not: ({ predicate: inner }) => !holds(inner, row, inSet),
    IsNull: ({ attribute }) => row[attribute] === null || row[attribute] === undefined,
    Eq: ({ attribute, value }) => row[attribute] === value.value,
    Compare: ({ op, attribute, value }) => {
      const actual = row[attribute];
      if (!P.isNumber(actual) || !P.isNumber(value.value)) return false;
      return op === "lt"
        ? actual < value.value
        : op === "lte"
          ? actual <= value.value
          : op === "gt"
            ? actual > value.value
            : actual >= value.value;
    },
    InSet: ({ attribute, set }) => {
      const actual = row[attribute];
      return actual !== null && actual !== undefined && inSet(set, actual);
    },
  });

/**
 * The single-row form of a scope: whether it admits `row`, with each named set
 * answered by `inSet`. This is the same residual a list renders, so a row
 * check and a list filter compiled from one policy set cannot disagree.
 *
 * @since 1.0.0
 * @category evaluation
 */
export const matches = (
  scope: ReadScope,
  row: Row,
  inSet: (set: string, value: string | number | boolean) => boolean = () => false,
): boolean =>
  Match.valueTags(scope, {
    AllowAll: () => true,
    Deny: () => false,
    Filter: ({ predicate }) => holds(predicate, row, inSet),
  });

/**
 * Drop every named set `isAvailable` rejects, narrowing the scope: an
 * occurrence the predicate uses positively becomes false, and one under a
 * negation becomes true, so an unresolvable set can only remove rows. Never
 * widens, never drops a conjunct.
 *
 * @since 1.0.0
 * @category evaluation
 */
export const withoutSets = (scope: ReadScope, isAvailable: (set: string) => boolean): ReadScope => {
  const narrow = (predicate: Predicate, positive: boolean): Expr =>
    Match.valueTags(predicate, {
      And: ({ predicates }) => conjunction(Arr.map(predicates, (inner) => narrow(inner, positive))),
      Or: ({ predicates }) => disjunction(Arr.map(predicates, (inner) => narrow(inner, positive))),
      Not: ({ predicate: inner }) => negation(narrow(inner, !positive)),
      Eq: (atom): Expr => atom,
      Compare: (atom): Expr => atom,
      IsNull: (atom): Expr => atom,
      InSet: (atom): Expr => (isAvailable(atom.set) ? atom : !positive),
    });
  return P.isTagged(scope, "Filter") ? toScope(narrow(scope.predicate, true)) : scope;
};
