/**
 * Vitest `globalSetup`: build one migrated PGlite data directory per test run
 * and hand its path to the test files (#291).
 *
 * `PGlite.create()` runs `initdb` inside the WASM module before it opens a
 * database: seconds of CPU on an idle machine, and on a loaded one enough to
 * exceed the 10 s hook timeout that a test file's `beforeAll` runs under
 * (Vitest's default; this package sets neither `hookTimeout` nor `testTimeout`).
 * Vitest applies no timeout to `globalSetup`, so that cost belongs here, in the
 * main process, and is paid once. A test file then starts each database from
 * this dump with {@link migratedPglite}, which skips `initdb` (and the
 * migrations) entirely.
 *
 * Wired up in this package's `vite.config.ts`; never published (`tsconfig.json`
 * excludes `src/testing/`).
 */

import { PGlite } from "@electric-sql/pglite";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vite-plus/test/node";
import { migrationStatements } from "../PgSchema.ts";

declare module "vitest" {
  export interface ProvidedContext {
    /** Path of an uncompressed tarball of a migrated PGlite data directory. */
    readonly pgliteTemplate: string;
  }
}

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  const directory = await mkdtemp(join(tmpdir(), "effect-auth-drizzle-pglite-"));
  const template = join(directory, "migrated.tar");

  // A 1 MB WAL segment (initdb's minimum) instead of the 16 MB default: the
  // template is unpacked into every instance's filesystem, and the WAL file is
  // a large part of its bytes. No test reads WAL, so nothing observable changes (#324).
  const client = await PGlite.create({ initDbStartParams: ["--wal-segsize=1"] });
  const migrateAndDump = async (): Promise<void> => {
    for (const statement of migrationStatements()) {
      await client.exec(statement);
    }
    const dump = await client.dumpDataDir("none");
    await writeFile(template, new Uint8Array(await dump.arrayBuffer()));
  };
  await migrateAndDump().finally(() => client.close());

  project.provide("pgliteTemplate", template);
  return () => rm(directory, { recursive: true, force: true });
}
