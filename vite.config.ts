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
    // Type checking is owned by each package's `check` task (tsc / vue-tsc /
    // svelte-check), which understands the per-package NodeNext tsconfigs.
    // Keeping it out of lint avoids one cross-package program mis-resolving
    // per-package types (e.g. @types/node globals).
    options: { typeAware: false, typeCheck: false },
  },
  resolve: {
    alias: {
      // Resolves the core package to source for runs under this root config.
      // Each package's tasks already build their workspace dependencies first
      // (vite.tasks.ts), so whether anything still needs this is #258.
      "@thomasfosterau/effect-auth": resolve(__dirname, "packages/effect-auth/src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
