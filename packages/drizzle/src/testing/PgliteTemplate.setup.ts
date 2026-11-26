/**
 * Vitest `globalSetup`: builds one migrated PGlite data directory per run, in
 * the main process where no hook timeout applies, so each test file opens its
 * database with {@link migratedPglite} and skips `initdb`. Never published.
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
  // a large part of its bytes. No test reads WAL, so nothing observable changes.
  const client = await PGlite.create({ initDbStartParams: ["--wal-segsize=1"] });
  const migrateAndDump = async (): Promise<void> => {
    await migrationStatements().reduce(async (previous, statement) => {
      await previous;
      await client.exec(statement);
    }, Promise.resolve());
    const dump = await client.dumpDataDir("none");
    await writeFile(template, new Uint8Array(await dump.arrayBuffer()));
  };
  await migrateAndDump().finally(() => client.close());

  project.provide("pgliteTemplate", template);
  return () => rm(directory, { recursive: true, force: true });
}
