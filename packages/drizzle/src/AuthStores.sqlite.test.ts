/**
 * `EmailPasswordStore`, `ApiKeyStore`, `RateLimitStore` and the token stores on
 * SQLite (better-sqlite3, in-process, a synchronous driver): the same suite as
 * the PostgreSQL file, over `Sqlite.tables` and `migrationStatements()` (#675).
 */

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { Effect, Layer } from "effect";
import { afterAll } from "vite-plus/test";
import { databaseLayer } from "./Database.ts";
import { migrationStatements, tables } from "./SqliteSchema.ts";
import { authStoresContract, authStoresLayer } from "./testing/AuthStoresContract.ts";

/** One in-memory database for the file; every case mints its own ids. */
const client = new Database(":memory:");
migrationStatements().forEach((statement) => client.exec(statement));
const db = drizzle({ client });

afterAll(() => {
  client.close();
});

authStoresContract("SQLite", (effect) =>
  Effect.runPromise(
    effect.pipe(Effect.provide(authStoresLayer(tables).pipe(Layer.provide(databaseLayer(db))))),
  ),
);
