/**
 * The kernel's entity vocabulary, Cedar-shaped: principals, actions and
 * resources are entities with a typed reference (`User::"u1"`), an attribute
 * bag and parents. An {@link EntitySlice} is the pre-fetched part of the graph
 * a decision needs, so decisions stay pure and replayable from a logged slice.
 *
 * @module entity
 */
import * as HashMap from "effect/HashMap";
import * as MutableHashSet from "effect/MutableHashSet";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import * as Str from "effect/String";

// ---------------------------------------------------------------------------
// Entity references
// ---------------------------------------------------------------------------

/**
 * A typed reference to an entity: `{ type: "User", id: "u1" }`, formatted as
 * `User::"u1"`. Types are app-defined PascalCase names by convention;
 * `"Action"` and `"Role"` are the two types the library itself gives meaning
 * to (action entities name what can be done; role entities are principal
 * parents). `"System"` is reserved for non-human principals (background jobs,
 * cron handlers): construct one with `System.ref`, never by hand, and never
 * name an application's own principal type `"System"` (`Guard.make` refuses it).
 *
 * Neither the type nor the id is ever empty. Decoding refuses
 * `""` in either field, and a reference built with one by hand ({@link ref}
 * stays total) **names no entity**: it equals nothing, itself included
 * ({@link refEquals}, {@link attributeValueEquals}), it is in nothing
 * ({@link entityIn}), no type scope matches it, and a request naming one is
 * refused by `Policy.decidePure` / `Policy.decide` (reason
 * `"invalid-request"`) and compiles to `ReadScope.deny`. An empty id or type
 * is never an "anonymous" stand-in: a signed-out caller is a principal of its
 * own type, such as `Anonymous::"anonymous"`.
 */
export const EntityRef = Schema.Struct({
  type: Schema.NonEmptyString,
  id: Schema.NonEmptyString,
});
export type EntityRef = typeof EntityRef.Type;

/**
 * The reserved entity type of a system principal (`System::"<name>"`). See
 * the `System` module: a system principal is an entity like any other, decided
 * only by the policies that name it.
 */
export const systemType = "System";

/**
 * Construct an {@link EntityRef}. Total, like the rest of this module: an
 * empty `type` or `id` is not rejected here but yields a reference that names
 * no entity (see {@link EntityRef}), so it can never match.
 */
export const ref = (type: string, id: string): EntityRef => ({ type, id });

/**
 * Whether a reference names an entity: neither its type nor its id is empty.
 * A reference that names none is refused by the decision procedure and equals
 * nothing.
 */
export const namesEntity = (r: EntityRef): boolean =>
  Str.isNonEmpty(r.type) && Str.isNonEmpty(r.id);

/**
 * Structural equality on entity references. A reference with an empty type
 * or id names no entity, so it equals nothing, itself included.
 */
export const refEquals = (a: EntityRef, b: EntityRef): boolean =>
  namesEntity(a) && a.type === b.type && a.id === b.id;

const encodeJsonString = Schema.encodeSync(Schema.fromJsonString(Schema.String));

/** Format a reference in Cedar display syntax: `User::"u1"`. */
export const formatRef = (r: EntityRef): string => `${r.type}::${encodeJsonString(r.id)}`;

/** Stable map key for a reference. */
export const refKey = (r: EntityRef): string => `${r.type}\u0000${r.id}`;

// ---------------------------------------------------------------------------
// Attribute values
// ---------------------------------------------------------------------------

/**
 * An entity reference used as an attribute *value* (e.g. `document.owner`).
 * The `__entity` wrapper keeps entity values unambiguous next to plain
 * record values in stored JSON (the same convention Cedar's JSON format
 * uses).
 */
export const EntityValue = Schema.Struct({
  __entity: EntityRef,
});
export type EntityValue = typeof EntityValue.Type;

/** Wrap a reference as an attribute value. */
export const entityValue = (r: EntityRef): EntityValue => ({ __entity: r });

/**
 * The value space for entity attributes and request context: JSON values
 * plus {@link EntityValue} references. This is what condition expressions
 * compare over.
 */
export type AttributeValue =
  | string
  | number
  | boolean
  | null
  | EntityValue
  | ReadonlyArray<AttributeValue>
  | { readonly [key: string]: AttributeValue };

export const AttributeValue: Schema.Codec<AttributeValue> = Schema.Union([
  Schema.String,
  Schema.Finite,
  Schema.Boolean,
  Schema.Null,
  EntityValue,
  Schema.Array(Schema.suspend((): Schema.Codec<AttributeValue> => AttributeValue)),
  Schema.Record(
    Schema.String,
    Schema.suspend((): Schema.Codec<AttributeValue> => AttributeValue),
  ),
]);

/** Narrow an {@link AttributeValue} to an entity value. */
export const isEntityValue = (value: AttributeValue): value is EntityValue =>
  P.isObject(value) &&
  "__entity" in value &&
  // `typeof x === "object"`: an object, an array, or `null`.
  (value.__entity === null || P.isObjectOrArray(value.__entity));

/** The `typeof` of an attribute value: `"object"` for `null`, arrays and records. */
const typeName = (value: AttributeValue): string =>
  P.isString(value)
    ? "string"
    : P.isNumber(value)
      ? "number"
      : P.isBoolean(value)
        ? "boolean"
        : "object";

/** Whether a value is an entity value whose reference names no entity (an empty id). */
const namesNoEntity = (value: AttributeValue): boolean =>
  isEntityValue(value) && P.isObject(value.__entity) && !namesEntity(value.__entity);

// An entity value is a record too: one holding `__entity`.
const isAttributeRecord = (
  value: AttributeValue,
): value is { readonly [key: string]: AttributeValue } =>
  P.isObject(value) && !Array.isArray(value);

/**
 * Deep structural equality over {@link AttributeValue}s. An entity value
 * whose type or id is empty equals nothing, itself included, at
 * any depth.
 */
export const attributeValueEquals = (a: AttributeValue, b: AttributeValue): boolean => {
  if (namesNoEntity(a) || namesNoEntity(b)) return false;
  if (a === b) return true;
  if (typeName(a) !== typeName(b)) return false;
  if (!P.isObjectOrArray(a) || b === null) return false;
  const arrayA = Array.isArray(a);
  const arrayB = Array.isArray(b);
  if (arrayA !== arrayB) return false;
  if (arrayA && arrayB) {
    return (
      a.length === b.length &&
      Arr.every(Arr.zip(a, b), ([itemA, itemB]) => attributeValueEquals(itemA, itemB))
    );
  }
  if (!isAttributeRecord(a) || !isAttributeRecord(b)) return false;
  const recordA: { readonly [key: string]: AttributeValue } = a;
  const recordB: { readonly [key: string]: AttributeValue } = b;
  const entriesA = R.toEntries(recordA);
  if (entriesA.length !== R.keys(recordB).length) return false;
  return Arr.every(
    entriesA,
    // SAFETY: `recordB` owns `key`, so the read is defined.
    ([key, valueA]) => Object.hasOwn(recordB, key) && attributeValueEquals(valueA, recordB[key]),
  );
};

// ---------------------------------------------------------------------------
// Entities and slices
// ---------------------------------------------------------------------------

/**
 * One entity in a slice: its reference, attribute bag, and direct parents
 * (the hierarchy is a DAG; ancestors are computed transitively).
 */
export const Entity = Schema.Struct({
  ref: EntityRef,
  attributes: Schema.Record(Schema.String, AttributeValue),
  parents: Schema.Array(EntityRef),
});
export type Entity = typeof Entity.Type;

/** Construct an {@link Entity} with empty defaults. */
export const entity = (
  r: EntityRef,
  options: {
    readonly attributes?: Readonly<Record<string, AttributeValue>>;
    readonly parents?: ReadonlyArray<EntityRef>;
  } = {},
): Entity => ({
  ref: r,
  attributes: options.attributes ?? {},
  parents: options.parents ?? [],
});

/**
 * The pre-fetched fragment of the entity graph an authorization decision is
 * evaluated over. Pure data: build one with {@link slice}, look entities up
 * with {@link getEntity}, test hierarchy membership with {@link entityIn}.
 *
 * Entities absent from the slice are treated as existing with no attributes
 * and no parents (Cedar's semantics for unknown entities), so a slice only
 * needs the entities whose attributes/ancestry the policies actually read —
 * that is what "slicing" means.
 */
export interface EntitySlice {
  readonly entities: HashMap.HashMap<string, Entity>;
}

/** Build an {@link EntitySlice} from a list of entities (later wins on duplicate refs). */
export const slice = (entities: ReadonlyArray<Entity> = []): EntitySlice => ({
  entities: HashMap.fromIterable(Arr.map(entities, (e) => [refKey(e.ref), e] as const)),
});

/** An empty slice (every entity unknown: no attributes, no parents). */
export const emptySlice: EntitySlice = slice();

/** Look up an entity in the slice, or `None` when it is not present. */
export const getEntity = (s: EntitySlice, r: EntityRef): Option.Option<Entity> =>
  HashMap.get(s.entities, refKey(r));

/** Read an entity's attribute from the slice (`None` when absent). */
export const getAttribute = (
  s: EntitySlice,
  r: EntityRef,
  name: string,
): Option.Option<AttributeValue> =>
  Option.flatMap(getEntity(s, r), (found) =>
    Object.hasOwn(found.attributes, name)
      ? Option.fromUndefinedOr(found.attributes[name])
      : Option.none(),
  );

/**
 * Hierarchy membership: is `child` the same entity as `ancestor`, or a
 * transitive descendant of it in the slice's parent DAG? Reflexive, like
 * Cedar's `in`. Cycle-safe (a malformed cyclic hierarchy terminates and
 * never grants beyond the visited set). Never true when either side has an
 * empty type or id: such a reference names no entity, so it is in nothing.
 */
export const entityIn = (s: EntitySlice, child: EntityRef, ancestor: EntityRef): boolean => {
  if (!namesEntity(child) || !namesEntity(ancestor)) return false;
  if (refEquals(child, ancestor)) return true;
  const visited = MutableHashSet.empty<string>();
  // Depth-first over a stack of pending refs. Each step pops one ref and emits
  // whether one of its parents is `ancestor`; a hit empties the stack, ending
  // the walk.
  const steps = Arr.unfold([child], (queue) =>
    Option.map(Option.fromUndefinedOr(queue.pop()), (current): readonly [boolean, EntityRef[]] => {
      const key = refKey(current);
      if (MutableHashSet.has(visited, key)) return [false, queue];
      MutableHashSet.add(visited, key);
      const found = Option.getOrUndefined(HashMap.get(s.entities, key));
      if (found === undefined) return [false, queue];
      if (found.parents.some((parent) => refEquals(parent, ancestor))) return [true, []];
      queue.push(...found.parents);
      return [false, queue];
    }),
  );
  return steps.includes(true);
};
