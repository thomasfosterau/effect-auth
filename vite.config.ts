import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  fmt: {},
  lint: {
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: { "vite-plus/prefer-vite-plus-imports": "error" },
    // Type checking is owned by each package's `check` task (tsc / vue-tsc /
    // svelte-check), which understands the per-package NodeNext tsconfigs.
    // Keeping it out of lint avoids one cross-package program mis-resolving
    // per-package types (e.g. @types/node globals).
    options: { typeAware: false, typeCheck: false },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
