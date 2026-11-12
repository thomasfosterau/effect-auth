/**
 * Reads the schema's `BIGINT` columns back as JavaScript numbers, whatever
 * the driver hands over (#766).
 *
 * The schema stores every epoch-millisecond instant and millisecond duration
 * as `BIGINT` (`Schema.ts`), and drivers disagree on how an `int8` comes back:
 * SQLite, D1 and PGlite return a `number`, `@effect/sql-pg` returns a
 * `bigint`, and node-postgres (`pg`) returns a decimal string. The stores
 * type those columns as `number`, so every row read normalizes them here,
 * strictly: only an integer in the safe range is accepted, from a `number`,
 * a `bigint` or a canonical decimal string; `NaN`, fractions, exponents and
 * out-of-range values fail as an `AuthError`.
 *
 * @internal
 */

import { Effect } from "effect";
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
): Effect.Effect<A, Auth.AuthError> => {
  const failure = (column: string) => (cause: unknown) =>
    new Auth.AuthError({ message: `${label}: stored integer ${column} did not decode`, cause });
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
