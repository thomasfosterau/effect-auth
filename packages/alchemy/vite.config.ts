import { resolve } from "path";
import { defineConfig } from "vite-plus";

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
