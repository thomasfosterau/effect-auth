import { resolve } from "node:path";
import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: "dist",
    sourcemap: true,
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      formats: ["es"],
      fileName: () => "index.js",
    },
    rollupOptions: {
      // Everything but this package's own sources stays external: `vue` is a
      // peer dependency and the client is a plain dependency.
      external: ["vue", /^@thomasfosterau\//],
    },
  },
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
    // Plain `tsc` cannot see through a `.vue` import; `vue-tsc` can.
    typecheck: { checker: "vue-tsc" },
  },
});
