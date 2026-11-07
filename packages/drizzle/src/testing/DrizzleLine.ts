/**
 * What the suites need to run unchanged on both drizzle-orm lines the peer
 * range admits: the classic `0.4x` line (`drizzle-orm`, what the suites
 * type-check against) and the 1.0 line (`drizzle-orm-effect`, the aliased
 * `1.0.0-rc.5` prerelease), which `vite.drizzle-1.config.ts` substitutes for
 * every `drizzle-orm` import (#544).
 *
 * The two lines differ in two ways a suite can observe, neither of them in
 * the stores' code:
 *
 * - **Rendered SQL.** 1.0 parenthesises each operand of `and(...)`, so a
 *   suite that pins statement text compares it through {@link normalizeSql}.
 * - **MySQL decoding.** 0.4x decodes a column's driver value in the column
 *   itself; 1.0 moved that into the driver's codecs, and `drizzle-orm/mysql-proxy`
 *   ships none (the proxy's owner decodes). The proxy fixtures emulate mysql2's
 *   wire shape, so they pass {@link mysqlProxyConfig}, mysql2's own decoders for
 *   the column types the suites use. 0.4x ignores the option.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { DateTime } from "effect";

/**
 * Drop the parentheses drizzle 1.0 puts around each comparison (`=`, `is null`,
 * `is not null`) inside a conjunction, nested ones included, so 1.0's
 * `((a = ?) and (b = ?))` reads as 0.4x's `(a = ? and b = ?)`.
 */
export const normalizeSql = (sql: string): string => {
  const unwrapped = sql.replaceAll(
    /\(((?:[`"]\w+[`"]\.)?[`"]\w+[`"] (?:= (?:\?|\$\d+)|is (?:not )?null))\)/g,
    "$1",
  );
  return unwrapped === sql ? sql : normalizeSql(unwrapped);
};

/** A MySQL `DATETIME` / `TIMESTAMP` wire value, `"YYYY-MM-DD hh:mm:ss.fff"` in UTC. */
const fromWireDateTime = (value: string): Date =>
  DateTime.toDateUtc(DateTime.makeUnsafe(`${value.replace(" ", "T")}Z`));

/**
 * mysql2's 1.0 decoders (`drizzle-orm/mysql2/codecs`) for the column types the
 * MySQL suites read: `boolean` (tinyint `1` / `0`), `datetime` and `timestamp`.
 */
const mysqlWireCodecs = {
  boolean: { normalize: (tinyint: number): boolean => tinyint === 1 },
  datetime: { normalize: fromWireDateTime },
  timestamp: { normalize: fromWireDateTime },
};

/**
 * The second argument of `drizzle-orm/mysql-proxy`'s `drizzle(callback, config)`.
 * Typed without `codecs` because 0.4x's config has no such key; 1.0 reads it.
 */
export const mysqlProxyConfig: { readonly logger: false } = Object.assign(
  { logger: false as const },
  { codecs: mysqlWireCodecs },
);
