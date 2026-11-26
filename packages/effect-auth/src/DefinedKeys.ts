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
export function definedKeys<const A extends object>(fields: A): DefinedKeys<A>;
export function definedKeys(fields: R.ReadonlyRecord<string, unknown>): object {
  return R.filter(fields, P.isNotUndefined);
}
