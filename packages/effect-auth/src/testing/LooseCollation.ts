/**
 * An in-memory {@link IdentifierStore} whose `getByValue` compares the way a
 * MySQL column under the default `utf8mb4_0900_ai_ci` collation does: case-,
 * accent- and width-insensitive. The suites use it to show that the services
 * never act on a record the store matched loosely (#602).
 *
 * Internal test support: not exported from `./testing`.
 */
import * as Arr from "effect/Array";
import * as Effect from "effect/Effect";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Option from "effect/Option";
import { memoryIdentifierStore, type Identifier, type IdentifierStore } from "../Identifier.ts";

/** Fold a value the way an `_ai_ci` collation compares it. */
const fold = (value: string): string =>
  value.normalize("NFKD").replaceAll(/\p{M}/gu, "").toLowerCase();

/**
 * {@link memoryIdentifierStore} over `records`, except that `getByValue`
 * answers with the first record of the type whose value folds to the same
 * string, as a case- and accent-insensitive column would.
 */
export const looseCollationIdentifierStore = (
  records: MutableHashMap.MutableHashMap<string, Identifier>,
): typeof IdentifierStore.Service => ({
  ...memoryIdentifierStore(records),
  getByValue: (type, value) =>
    Effect.sync(() =>
      Option.getOrNull(
        Arr.findFirst(
          MutableHashMap.values(records),
          (record) => record.type === type && fold(record.value) === fold(value),
        ),
      ),
    ),
});
