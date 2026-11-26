/**
 * Options objects spell an optional member `readonly x?: T` under
 * `exactOptionalPropertyTypes`, so a value that may be `undefined` (a decoded
 * wire field, a lookup) is forwarded by leaving its key out. `definedKeys`
 * does that for a whole object literal.
 *
 * @internal
 */
import * as P from "effect/Predicate";
import * as R from "effect/Record";

/** `A` with every key that may hold `undefined` made optional and `undefined`-free. */
export type DefinedKeys<A> = {
  [K in keyof A as undefined extends A[K] ? never : K]: A[K];
} & {
  [K in keyof A as undefined extends A[K] ? K : never]?: Exclude<A[K], undefined>;
} extends infer B
  ? { [K in keyof B]: B[K] }
  : never;

/** Drops the keys of `fields` whose value is `undefined`. */
export const definedKeys = <const A extends object>(fields: A): DefinedKeys<A> => {
  // SAFETY: an object's own enumerable properties, read as the record they are.
  const record = fields as R.ReadonlyRecord<string, unknown>;
  // SAFETY: the record without its `undefined` values is what `DefinedKeys<A>` describes.
  return R.filter(record, P.isNotUndefined) as DefinedKeys<A>;
};
