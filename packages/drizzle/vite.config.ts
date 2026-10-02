import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check: "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run",
  }),
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
    // Every test here boots its own PGlite instance — Postgres compiled to
    // WebAssembly. Cold-starting the WASM module can take several seconds on a
    // loaded machine, which is well inside vitest's 5s default and made the
    // first test of a run flaky. The `beforeAll` hooks that boot a shared
    // instance (OwnedListFilter.test.ts) take the same cold start, so they get
    // the same budget: vitest's 10s hookTimeout was exceeded on a 2-vCPU CI
    // runner now that the native (multi-threaded) TypeScript 7 `tsc` runs in
    // parallel with this suite.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
