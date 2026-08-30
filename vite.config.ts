import { resolve } from "path";
import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  fmt: {},
  lint: {
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: { "vite-plus/prefer-vite-plus-imports": "error" },
    // Type checking is owned by the per-project `typecheck` target (tsc), which
    // understands this nx monorepo's NodeNext tsconfigs/project references.
    // Keeping it out of lint avoids a single cross-repo program mis-resolving
    // per-project types (e.g. @types/node globals).
    options: { typeAware: false, typeCheck: false },
  },
  resolve: {
    alias: {
      // packages/*/dist/ is gitignored; resolve the core package to source so
      // packages/client tests work in CI without a separate build step.
      "@thomasfosterau/effect-auth": resolve(__dirname, "packages/effect-auth/src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
