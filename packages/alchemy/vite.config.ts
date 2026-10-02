import { resolve } from "path";
import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

// HELD PRIVATE UNTIL alchemy SHIPS AN EFFECT rc.118 BUILD (effect-auth#249, #250).
//
// The workspace builds against `effect` 4.0.0, but alchemy 2.0.0-beta.79 (the
// newest release) imports the removed `effect/unstable/*` paths, so anything
// that loads the alchemy runtime fails with ERR_MODULE_NOT_FOUND. `package.json`
// is therefore `"private": true` (changesets and pnpm neither version nor
// publish it) and it stays out of the `check:dist` smoke test. Everything that
// does not need the alchemy runtime still runs:
//
// - `build` and `check` (tsc over sources and tests) run as for any package;
// - `test:unit` runs every test except `AuthSchema.test.ts` (`Storage.test.ts`
//   only needs `AuthTables.ts`, which is alchemy-free);
// - `test:alchemy` runs `AuthSchema.test.ts`, the one suite that needs the
//   alchemy runtime. It is expected to FAIL until #250 lands, in its own,
//   non-required CI job. It is not skipped and not in `test:unit`.
const alchemyRuntimeSuite = "src/AuthSchema.test.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check: `tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run --exclude ${alchemyRuntimeSuite}`,
    test: `vp test run --exclude ${alchemyRuntimeSuite}`,
    extra: { "test:alchemy": `vp test run ${alchemyRuntimeSuite}` },
  }),
  resolve: {
    alias: {
      // packages/*/dist/ is gitignored; resolve the SQL stores this package
      // wires up to source so the suite runs without a separate build step.
      "@thomasfosterau/effect-auth-sql": resolve(__dirname, "../sql/src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
