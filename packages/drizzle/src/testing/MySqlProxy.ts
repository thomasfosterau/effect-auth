/**
 * The mysql2 decoders the MySQL suites pass `drizzle-orm/mysql-proxy`, which in
 * drizzle 1.0 decodes nothing itself, so the fixtures read values as mysql2
 * would. Never published.
 */

import { DateTime } from "effect";

/** A MySQL `DATETIME` / `TIMESTAMP` wire value, `"YYYY-MM-DD hh:mm:ss.fff"` in UTC. */
const fromWireDateTime = (value: string): Date =>
  DateTime.toDateUtc(DateTime.makeUnsafe(`${value.replace(" ", "T")}Z`));

/**
 * The second argument of `drizzle-orm/mysql-proxy`'s `drizzle(callback, config)`:
 * mysql2's decoders (`drizzle-orm/mysql2/codecs`) for the column types the
 * MySQL suites read, `boolean` (tinyint `1` / `0`), `datetime` and `timestamp`.
 */
export const mysqlProxyConfig = {
  logger: false,
  codecs: {
    boolean: { normalize: (tinyint: number): boolean => tinyint === 1 },
    datetime: { normalize: fromWireDateTime },
    timestamp: { normalize: fromWireDateTime },
  },
} as const;
