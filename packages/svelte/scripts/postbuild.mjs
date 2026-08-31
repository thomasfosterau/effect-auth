/**
 * Tidy up after `svelte-package`, which has no options for either of these.
 *
 * It copies everything under `src/` into `dist/`, so the colocated `*.test.ts`
 * suites this repo favours end up compiled into the published output — and the
 * test runner would then discover every suite twice, once from source and once
 * from `dist/`.
 *
 * It also leaves its staging directory, `.svelte-kit/__package__`, behind, which
 * is a second copy of the same files for the runner to trip over.
 */
import { readdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const isTest = (name) => /\.test\.(js|d\.ts|d\.ts\.map)$/.test(name);

const stripTests = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) stripTests(path);
    else if (isTest(entry.name)) rmSync(path);
  }
};

const resolve = (relative) => fileURLToPath(new URL(relative, import.meta.url));

stripTests(resolve("../dist"));
rmSync(resolve("../.svelte-kit"), { recursive: true, force: true });
