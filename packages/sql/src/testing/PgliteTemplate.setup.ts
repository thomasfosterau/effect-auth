/**
 * Vitest `globalSetup`: build one migrated PGlite data directory per test run
 * and hand its path to the test files.
 *
 * `PGlite.create()` runs `initdb` inside the WASM module before it opens a
 * database, which costs seconds on a loaded machine. That cost belongs here, in
 * the main process, where no test or hook timeout applies, and it is paid once.
 * A test file then opens its database from this dump with `migratedPglite`,
 * which skips `initdb` and the migrations.
 *
 * Wired up in this package's `vite.config.ts`; never published (`tsconfig.json`
 * excludes `src/testing/`).
 */

import { PGlite } from "@electric-sql/pglite";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vite-plus/test/node";
import { schemaStatements } from "../Schema.ts";

declare module "vitest" {
  export interface ProvidedContext {
    /** Path of an uncompressed tarball of a migrated PGlite data directory. */
    readonly pgliteTemplate: string;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const directory = await mkdtemp(join(tmpdir(), "effect-auth-sql-pglite-"));
  const template = join(directory, "migrated.tar");

  try {
    // A 1 MB WAL segment (initdb's minimum) instead of the 16 MB default: the
    // template is unpacked into every instance's filesystem, and no test reads WAL.
    const client = await PGlite.create({ initDbStartParams: ["--wal-segsize=1"] });
    try {
      for (const statement of schemaStatements) {
        await client.exec(statement);
      }
      const dump = await client.dumpDataDir("none");
      await writeFile(template, new Uint8Array(await dump.arrayBuffer()));
    } finally {
      await client.close();
    }
  } catch (error) {
    // No teardown is returned on failure, so remove the directory here.
    await rm(directory, { recursive: true, force: true });
    throw error;
  }

  project.provide("pgliteTemplate", template);
  return () => rm(directory, { recursive: true, force: true });
}
