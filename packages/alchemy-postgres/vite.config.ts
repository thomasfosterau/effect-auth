import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

// `AuthSchema.test.ts` loads the alchemy runtime (the engine and its
// transitive clients), so it runs as `test:alchemy` (the root `ci` task's last
// step), beside `Postgres.test.ts`, whose cases need a server (`DATABASE_URL`,
// which CI's `ci` job starts as a service). The task declares
// `DATABASE_URL` and `CI` as fingerprinted inputs: a cached task sees only the
// variables it declares, and without them the server cases silently skipped in
// CI (#766). Under `CI` a missing `DATABASE_URL` fails them; elsewhere they skip
// with a warning.
// `test:unit` and `check`'s `vp test --typecheck` run neither (`tsc -p
// tsconfig.test.json` still type-checks both): `test:unit` has no other suite,
// so it passes with none.
const alchemySuites = "src/AuthSchema.test.ts src/Postgres.test.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check:
      "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run --passWithNoTests --exclude src/AuthSchema.test.ts --exclude src/Postgres.test.ts",
    test: "vp test run --passWithNoTests --exclude src/AuthSchema.test.ts --exclude src/Postgres.test.ts",
    extra: {
      "test:alchemy": { command: `vp test run ${alchemySuites}`, env: ["DATABASE_URL", "CI"] },
    },
  }),
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
