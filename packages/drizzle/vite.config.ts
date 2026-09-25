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
    // first test of a run flaky.
    testTimeout: 30_000,
  },
});
