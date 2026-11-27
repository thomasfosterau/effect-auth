/**
 * Reads the schema's `BIGINT` columns back as numbers, whatever the driver
 * returns (a `number`, a `bigint` or a decimal string). Only a safe integer is
 * accepted; anything else fails as an `AuthError`.
 *
 * @internal
 */

import * as Effect from "effect/Effect";
import * as Arr from "effect/Array";
import * as R from "effect/Record";
import * as Schema from "effect/Schema";
import * as SchemaTransformation from "effect/SchemaTransformation";
import * as Auth from "../index.ts";
import { schemaStatements } from "./Schema.ts";

/**
 * Every column the DDL declares `BIGINT`, by name. A name is `BIGINT` in
 * every table that has it (`Int8.test.ts` pins this), so a row's column of
 * that name is an `int8` on Postgres.
 */
export const bigintColumns: ReadonlyArray<string> = Arr.dedupe(
  schemaStatements.flatMap((statement) =>
    Array.from(statement.matchAll(/^\s*(\w+)\s+BIGINT\b/gm), (match) => match[1] ?? ""),
  ),
);

const SafeInteger = Schema.Int.check(
  Schema.isBetween({ minimum: Number.MIN_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER }),
);

/**
 * An `int8` as a driver returns it, read as a safe integer: a `number`, a
 * `bigint` or a canonical decimal string (no sign but `-`, no leading zero,
 * no exponent, no whitespace). A `bigint` or string past the safe range does
 * not decode, rather than round.
 */
const Int8 = Schema.Union([
  SafeInteger,
  Schema.BigInt.pipe(
    Schema.decodeTo(
      SafeInteger,
      SchemaTransformation.transform({ decode: Number, encode: globalThis.BigInt }),
    ),
  ),
  Schema.String.check(Schema.isPattern(/^-?(?:0|[1-9]\d*)$/)).pipe(
    Schema.decodeTo(
      SafeInteger,
      SchemaTransformation.transform({ decode: Number, encode: String }),
    ),
  ),
]);

const decodeInt8 = Schema.decodeUnknownEffect(Int8);

const decodeRow = Schema.decodeUnknownEffect(Schema.Record(Schema.String, Schema.Unknown));

/**
 * A row with each of its {@link bigintColumns} read as a `number` (`null`
 * stays `null`); a value that is not a safe integer fails the read as an
 * `AuthError` naming the column.
 */
export const decodeBigintColumns = <A extends object>(
  row: A,
  label: string,
): Effect.Effect<A, Auth.Errors.AuthError> => {
  const failure = (column: string) => (cause: unknown) =>
    new Auth.Errors.AuthError({
      message: `${label}: stored integer ${column} did not decode`,
      cause,
    });
  return decodeRow(row).pipe(
    Effect.mapError(failure("row")),
    Effect.flatMap((record) =>
      Effect.forEach(
        Arr.filter(
          R.toEntries(record),
          ([column, value]) => value != null && Arr.contains(bigintColumns, column),
        ),
        ([column, value]) =>
          decodeInt8(value).pipe(
            Effect.map((n) => [column, n] as const),
            Effect.mapError(failure(column)),
          ),
        { concurrency: 1 },
      ),
    ),
    Effect.map((entries): A => Object.assign({}, row, R.fromEntries(entries))),
  );
};
