import { describe, expect, it } from "vite-plus/test";
import { Effect, Exit } from "effect";
import * as Arr from "effect/Array";
import { bigintColumns, decodeBigintColumns } from "./Int8.ts";
import { schemaStatements } from "./Schema.ts";

/** Each column the DDL declares, with its declared type, across every table. */
const declaredColumns = schemaStatements.flatMap((statement) =>
  Array.from(statement.matchAll(/^\s*([a-z_]+)\s+([A-Z]+)\b/gm), ([, name = "", type = ""]) => ({
    name,
    type,
  })),
);

const decode = <A extends object>(row: A) =>
  Effect.runSyncExit(decodeBigintColumns(row, "test.read"));

const millis = 1_767_225_660_000;

describe("bigintColumns (#766)", () => {
  it("is every column the DDL declares BIGINT, and no such name has another type anywhere", () => {
    const bigint = Arr.dedupe(
      declaredColumns.filter((column) => column.type === "BIGINT").map((column) => column.name),
    );
    expect([...bigintColumns].toSorted()).toEqual(bigint.toSorted());
    expect(bigintColumns).toContain("expires_at");
    expect(bigintColumns).toContain("rate_limit_window_ms");
    const clashing = declaredColumns.filter(
      (column) => column.type !== "BIGINT" && bigintColumns.includes(column.name),
    );
    expect(clashing).toEqual([]);
  });
});

describe("decodeBigintColumns (#766)", () => {
  it.for([millis, BigInt(millis), String(millis)])(
    "reads an int8 as each driver returns it: number (SQLite, D1, PGlite), bigint (@effect/sql-pg), string (node-postgres): %s",
    (value) => {
      expect(
        decode({ id: "s", expires_at: value, created_at: value, last_activity_at: value }),
      ).toEqual(
        Exit.succeed({
          id: "s",
          expires_at: millis,
          created_at: millis,
          last_activity_at: millis,
        }),
      );
    },
  );

  it.for([
    ["0", 0],
    ["-1", -1],
    [String(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER],
    [BigInt(Number.MIN_SAFE_INTEGER), Number.MIN_SAFE_INTEGER],
  ] as const)("reads zero, negatives and both ends of the safe range: %s", ([value, expected]) => {
    expect(decode({ reset_at: value })).toEqual(Exit.succeed({ reset_at: expected }));
  });

  it("keeps a null column null, and leaves every other column as the driver returned it", () => {
    const row = {
      key: "k",
      count: 3,
      blocked_until: null,
      name: "1767225660000",
      challenge: "AAEC",
      reset_at: String(millis),
    };
    expect(decode(row)).toEqual(Exit.succeed({ ...row, reset_at: millis }));
  });

  it.for<unknown>([
    Number.NaN,
    Number.POSITIVE_INFINITY,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    BigInt(Number.MAX_SAFE_INTEGER) + 2n,
    "9007199254740993",
    "",
    "abc",
    "1e12",
    "12.0",
    " 12",
    "12 ",
    "+12",
    "012",
    "0x10",
    true,
    {},
    new Uint8Array([1]),
  ])(
    "fails as an AuthError naming the column on a value that is not a safe integer: %s",
    (value) => {
      const exit = decode({ id: "x", expires_at: value });
      expect(Exit.isFailure(exit) ? exit.cause.toString() : "decoded").toContain(
        "test.read: stored integer expires_at did not decode",
      );
    },
  );
});
