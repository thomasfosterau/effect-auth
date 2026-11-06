import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

// `AuthSchema.test.ts` loads the alchemy runtime (the engine and its
// transitive clients), so it runs as `test:alchemy` in CI's separate `alchemy`
// job ("Alchemy runtime"), beside `Postgres.test.ts`, whose cases need a
// server (`DATABASE_URL`, which that job starts; without one they skip).
// `test:unit` runs neither: it has no other suite, so it passes with none.
const alchemySuites = "src/AuthSchema.test.ts src/Postgres.test.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check:
      "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run --exclude src/AuthSchema.test.ts",
    test: "vp test run --passWithNoTests --exclude src/AuthSchema.test.ts --exclude src/Postgres.test.ts",
    extra: { "test:alchemy": `vp test run ${alchemySuites}` },
  }),
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
