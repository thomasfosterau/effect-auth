/**
 * Test-side half of the PGlite template (#291): open databases from the
 * migrated data directory that `PgliteTemplate.setup.ts` built for this run.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { PGlite } from "@electric-sql/pglite";
import { getTableName } from "drizzle-orm";
import { readFile } from "node:fs/promises";
import { inject } from "vite-plus/test";
import { tables } from "../PgSchema.ts";

/**
 * A new in-memory Postgres with this package's tables already applied, started
 * from the run's template rather than from `initdb`.
 *
 * Each call is its own PGlite instance — its own WASM module and Postgres
 * backend — so nothing written through one is visible through another.
 */
export const migratedPglite = async (): Promise<PGlite> =>
  PGlite.create({ loadDataDir: new Blob([await readFile(inject("pgliteTemplate"))]) });

/** Empty every table {@link migratedPglite} created, keeping the schema. */
export const truncateTables = async (client: PGlite): Promise<void> => {
  const names = Object.values(tables).map((table) => `"${getTableName(table)}"`);
  await client.exec(`TRUNCATE ${names.join(", ")}`);
};
