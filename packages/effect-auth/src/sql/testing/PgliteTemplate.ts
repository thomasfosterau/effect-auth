/**
 * Test-side half of the PGlite template: open a database from the migrated
 * data directory that `PgliteTemplate.setup.ts` built for this run.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { PGlite, type PGliteOptions } from "@electric-sql/pglite";
import { readFile } from "node:fs/promises";
import { inject } from "vite-plus/test";

/**
 * A new in-memory Postgres started from the run's template rather than from
 * `initdb`. The auth schema is already applied; each call is its own instance,
 * so the file's tests share one database only through the instance it holds.
 * `parsers` overrides how a column type is read back (`Stores.test.ts` reads
 * `int8` as other Postgres drivers return it, #766).
 */
export const migratedPglite = async (parsers?: PGliteOptions["parsers"]): Promise<PGlite> =>
  PGlite.create({
    loadDataDir: new Blob([await readFile(inject("pgliteTemplate"))]),
    ...(parsers !== undefined && { parsers }),
  });
