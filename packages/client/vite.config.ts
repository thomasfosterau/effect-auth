import { resolve } from "path";
import { defineConfig } from "vite-plus";

export default defineConfig({
  resolve: {
    alias: {
      // Point effect-auth to source so vitest doesn't need a compiled dist.
      "effect-auth": resolve(__dirname, "../../src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
