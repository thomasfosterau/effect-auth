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
    // One migrated PGlite data directory per run, built outside any test or hook
    // timeout; the PostgreSQL suite opens its database from it (src/testing).
    globalSetup: ["./src/testing/PgliteTemplate.setup.ts"],
    // Vitest 5's file-system module cache is off for this package: a cached
    // module reaches the globalSetup's module runner as a Buffer, and Vite+
    // 1.4's stack-trace source mapping then throws `code.charCodeAt is not a
    // function` (the first Effect stack capture in the setup), so every run
    // after the first fails with "No test files found" (#502).
    fsModuleCache: false,
  },
});
