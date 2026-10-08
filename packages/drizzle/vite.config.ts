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
    // the WASM module: seconds of CPU when idle, and past vitest's default
    // timeouts on a loaded machine. This setup runs it once per test run,
    // outside any timeout, and provides a migrated data directory that test
    // files open with `migratedPglite` (src/testing/PgliteTemplate.ts), which
    // skips `initdb` (#291, #305). No test or hook boots PGlite itself, so
    // vitest's default `testTimeout` and `hookTimeout` apply.
    globalSetup: ["./src/testing/PgliteTemplate.setup.ts"],
  },
});
