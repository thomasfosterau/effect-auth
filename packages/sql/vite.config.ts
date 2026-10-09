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
  },
});
