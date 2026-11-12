import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

// `AuthSchema.test.ts` is the one suite that loads the alchemy engine (the
// engine, the `Cloudflare.D1.Database` resource and its transitive
// `@distilled.cloud/*` clients), so
// it runs as its own `test:alchemy` task, which the root `ci` task runs after
// the unit suites; the rest of the package is ordinary:
//
// - `build` and `check` (tsc over sources and tests) run as for any package;
// - `test:unit` runs every test except `AuthSchema.test.ts` (`Storage.test.ts`
//   needs `@thomasfosterau/effect-auth/sql`, the provider's `QueryDatabase`
//   module and alchemy's `RuntimeContext`, none of which loads the engine);
// - `test:alchemy` runs `AuthSchema.test.ts`. It is not skipped.
//
// alchemy 2.0.0-beta.80 is the first release that imports only `effect/*`
// paths (beta.79 still imported the removed `effect/unstable/*`; #250).
const alchemyRuntimeSuite = "src/AuthSchema.test.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check: `tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run --exclude ${alchemyRuntimeSuite}`,
    test: `vp test run --exclude ${alchemyRuntimeSuite}`,
    extra: { "test:alchemy": `vp test run ${alchemyRuntimeSuite}` },
  }),
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
