import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

// `AuthSchema.test.ts` loads the alchemy runtime (the engine and its
// transitive clients), so it runs as `test:alchemy` (the root `ci` task's last
// step), beside `Postgres.test.ts`, whose cases need a server
// (`DATABASE_URL`; without one they skip). CI starts a server, but a cached
// task sees only the environment variables it declares and this one declares
// none, so in CI those cases skip too (#766).
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
