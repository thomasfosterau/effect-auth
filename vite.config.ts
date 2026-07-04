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
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
