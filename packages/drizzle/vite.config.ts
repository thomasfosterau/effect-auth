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
    // Booting PGlite (Postgres compiled to WebAssembly) runs `initdb` inside
    // the WASM module: seconds of CPU when idle, past these timeouts on a
    // loaded machine. This setup runs it once per test run, outside any
    // timeout, and provides a migrated data directory that test files open
    // with `migratedPglite` (src/testing/PgliteTemplate.ts), which skips
    // `initdb` (#291).
    globalSetup: ["./src/testing/PgliteTemplate.setup.ts"],
    // Files not yet on the template still boot their own PGlite instances in
    // tests and `beforeAll` hooks (OwnedListFilter.test.ts), so they keep the
    // raised budget: vitest's 5s/10s defaults were exceeded on a 2-vCPU CI
    // runner now that the native (multi-threaded) TypeScript 7 `tsc` runs in
    // parallel with this suite.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
