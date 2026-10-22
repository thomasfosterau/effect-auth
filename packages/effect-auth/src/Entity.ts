/**
 * Entity vocabulary for the authorization kernel.
 *
 * The authorization model is Cedar-shaped (reviewed against docs.cedarpolicy.com;
 * see `docs/better-auth-parity.md` §2.5): every party to an authorization
 * decision — principals, resources, and actions alike — is an **entity**,
 * identified by a typed reference (`User::"u1"`-style), carrying an
 * attribute bag, and optionally belonging to parent entities (groups, roles,
 * organizations, action groups). Hierarchy membership (`in`) is what makes
 * RBAC (`principal in Role::"admin"`) and ReBAC plain data checks.
 *
 * Everything in this module is pure data + total functions: an
 * {@link EntitySlice} is the pre-fetched fragment of the entity graph that a
 * decision needs, and evaluation over it never performs IO. Resolving a
 * slice from stores is the Effect shell's job (`AttributeProvider` /
 * `EntityStore`), keeping decisions deterministic and replayable from a
 * logged slice.
 *
 * @module entity
 */
import { Array as Arr, MutableHashSet, Option, Predicate, Record as Rec, Schema } from "effect";

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
 */
export const EntityRef = Schema.Struct({
  type: Schema.String,
  id: Schema.String,
});
export type EntityRef = typeof EntityRef.Type;

/**
 * The reserved entity type of a system principal (`System::"<name>"`). See
 * the `System` module: a system principal is an entity like any other, decided
 * only by the policies that name it.
 */
export const systemType = "System";

/** Construct an {@link EntityRef}. */
export const ref = (type: string, id: string): EntityRef => ({ type, id });

/** Structural equality on entity references. */
export const refEquals = (a: EntityRef, b: EntityRef): boolean =>
  a.type === b.type && a.id === b.id;

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
  Schema.Number,
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
  Predicate.isObject(value) &&
  "__entity" in value &&
  // `typeof x === "object"`: an object, an array, or `null`.
  (value.__entity === null || Predicate.isObjectOrArray(value.__entity));

/** The `typeof` of an attribute value: `"object"` for `null`, arrays and records. */
const typeName = (value: AttributeValue): string =>
  Predicate.isString(value)
    ? "string"
    : Predicate.isNumber(value)
      ? "number"
      : Predicate.isBoolean(value)
        ? "boolean"
        : "object";

/** Deep structural equality over {@link AttributeValue}s. */
export const attributeValueEquals = (a: AttributeValue, b: AttributeValue): boolean => {
  if (a === b) return true;
  if (typeName(a) !== typeName(b)) return false;
  if (!Predicate.isObjectOrArray(a) || b === null) return false;
  const arrayA = Array.isArray(a);
  const arrayB = Array.isArray(b);
  if (arrayA !== arrayB) return false;
  if (arrayA && arrayB) {
    return (
      a.length === b.length &&
      Arr.every(Arr.zip(a, b), ([itemA, itemB]) => attributeValueEquals(itemA, itemB))
    );
  }
  // SAFETY: both are non-null, non-array objects of the AttributeValue domain:
  // records (an entity value is a record holding `__entity`).
  const recordA = a as { readonly [key: string]: AttributeValue };
  // SAFETY: as for `recordA`.
  const recordB = b as { readonly [key: string]: AttributeValue };
  const entriesA = Rec.toEntries(recordA);
  if (entriesA.length !== Rec.keys(recordB).length) return false;
  return Arr.every(
    entriesA,
    // SAFETY: `key in recordB` holds, so the read is defined.
    ([key, valueA]) =>
      key in recordB && attributeValueEquals(valueA, recordB[key] as AttributeValue),
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
  readonly entities: ReadonlyMap<string, Entity>;
}

/** Build an {@link EntitySlice} from a list of entities (later wins on duplicate refs). */
export const slice = (entities: ReadonlyArray<Entity> = []): EntitySlice => ({
  entities: new Map(entities.map((e) => [refKey(e.ref), e])),
});

/** An empty slice (every entity unknown: no attributes, no parents). */
export const emptySlice: EntitySlice = slice();

/** Look up an entity in the slice, or `null` when it is not present. */
export const getEntity = (s: EntitySlice, r: EntityRef): Entity | null =>
  s.entities.get(refKey(r)) ?? null;

/** Read an entity's attribute from the slice (`null` when absent). */
export const getAttribute = (s: EntitySlice, r: EntityRef, name: string): AttributeValue | null => {
  const found = getEntity(s, r);
  if (found === null) return null;
  return name in found.attributes ? (found.attributes[name] ?? null) : null;
};

/**
 * Hierarchy membership: is `child` the same entity as `ancestor`, or a
 * transitive descendant of it in the slice's parent DAG? Reflexive, like
 * Cedar's `in`. Cycle-safe (a malformed cyclic hierarchy terminates and
 * never grants beyond the visited set).
 */
export const entityIn = (s: EntitySlice, child: EntityRef, ancestor: EntityRef): boolean => {
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
      const found = s.entities.get(key);
      if (found === undefined) return [false, queue];
      if (found.parents.some((parent) => refEquals(parent, ancestor))) return [true, []];
      queue.push(...found.parents);
      return [false, queue];
    }),
  );
  return steps.includes(true);
};
