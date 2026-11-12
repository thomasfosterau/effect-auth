/**
 * The config the MySQL suites hand `drizzle-orm/mysql-proxy`.
 *
 * drizzle 1.0 decodes a column's driver value in the driver's codecs, not in
 * the column, and `drizzle-orm/mysql-proxy` ships none (the proxy's owner
 * decodes). The proxy fixtures emulate mysql2's wire shape, so they pass
 * {@link mysqlProxyConfig}: mysql2's own decoders for the column types the
 * suites read.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
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
