import { resolve } from "path";
import { defineConfig } from "vite-plus";

// NOT MIGRATED TO EFFECT rc.118 (effect-auth#249, follow-up #250).
//
// The workspace builds against `effect` rc.118, but alchemy 2.0.0-beta.79 (the
// newest release) imports the removed `effect/unstable/*` paths, so this
// package cannot be built, type-checked or tested against that catalog. It
// therefore declares no `build` / `check` / `test:unit` tasks: `vp run -r ...`
// and `vp run check` skip it, and `vp run check:dist` does not pack it. It
// keeps its `effect >=4.0.0-rc.115` peer floor (the `peers-alchemy` catalog)
// and ships no changeset. Restore `packageTasks` as below once alchemy ships
// an rc.118 build:
//
//   run: packageTasks({
//     build: "tsc",
//     check: "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run",
//   }),
export default defineConfig({
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
