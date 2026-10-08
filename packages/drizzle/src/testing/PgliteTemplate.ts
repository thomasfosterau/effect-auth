/**
 * Test-side half of the PGlite template (#291): open databases from the
 * migrated data directory that `PgliteTemplate.setup.ts` built for this run.
 *
 * Never published (`tsconfig.json` excludes `src/testing/`).
 */

import { PGlite } from "@electric-sql/pglite";
import { getTableName } from "drizzle-orm";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { inject } from "vite-plus/test";
import { tables } from "../PgSchema.ts";

/**
 * What every {@link migratedPglite} call shares: the Postgres WASM module
 * compiled, the filesystem bundle read, and the migrated data directory read,
 * each once per test file (the module graph is per file under Vitest's default
 * isolation). Each instance still gets its own memory, Postgres backend and
 * data directory; only these immutable inputs are shared.
 */
interface PgliteArtifacts {
  readonly wasmModule: WebAssembly.Module;
  readonly fsBundle: Blob;
  readonly template: Blob;
}

const pgliteDist = dirname(createRequire(import.meta.url).resolve("@electric-sql/pglite"));

let artifacts: Promise<PgliteArtifacts> | undefined;

// `WebAssembly.compile` is a value only the DOM lib declares (node's types give
// the namespace, not the functions), so tsconfig.test.json adds DOM to `lib`.
// The package's build excludes this directory.
const loadArtifacts = (): Promise<PgliteArtifacts> =>
  (artifacts ??= Promise.all([
    readFile(join(pgliteDist, "pglite.wasm")).then((bytes) => WebAssembly.compile(bytes)),
    readFile(join(pgliteDist, "pglite.data")),
    readFile(inject("pgliteTemplate")),
  ]).then(([wasmModule, fsBundle, template]) => ({
    wasmModule,
    fsBundle: new Blob([fsBundle]),
    template: new Blob([template]),
  })));

/**
 * A new in-memory Postgres started from the run's template rather than from
 * `initdb`. Each call is its own PGlite instance (its own WASM module and
 * Postgres backend), so nothing written through one is visible through
 * another. The package's tables are already applied; a file that needs other
 * tables applies its own DDL on top.
 *
 * Compiling the WASM module and unpacking the template dominate a boot on a
 * loaded machine (#324), so those are paid once per test file in
 * {@link loadArtifacts} and every call after the first only instantiates.
 */
export const migratedPglite = async (): Promise<PGlite> => {
  const { wasmModule, fsBundle, template } = await loadArtifacts();
  return PGlite.create({
    pgliteWasmModule: wasmModule,
    fsBundle,
    loadDataDir: template,
  });
};

/** Empty the named tables, keeping their schema. */
export const truncate = async (client: PGlite, names: ReadonlyArray<string>): Promise<void> => {
  await client.exec(`TRUNCATE ${names.map((name) => `"${name}"`).join(", ")}`);
};

/** Empty every package table {@link migratedPglite} created, keeping the schema. */
export const truncateTables = (client: PGlite): Promise<void> =>
  truncate(
    client,
    Object.values(tables).map((table) => getTableName(table)),
  );
