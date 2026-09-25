import { resolve } from "node:path";
import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";
import solid from "vite-plugin-solid";

/**
 * Solid's JSX is compiled by `vite-plugin-solid` (babel-preset-solid), not by
 * tsc — plain `tsc` emit would leave the JSX in place and produce nothing that
 * runs. So the JS half of the package is a Vite library build, and tsc is left
 * to do only what Vite cannot: emit the declarations.
 */
export default defineConfig({
  run: packageTasks({
    build:
      "vp build && tsc --emitDeclarationOnly --incremental false && tsc --outDir dist/source --declaration false --declarationMap false --incremental false",
    check: "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run",
  }),
  plugins: [solid()],
  resolve: { conditions: ["browser"] },
  build: {
    target: "esnext",
    minify: false,
    sourcemap: true,
    lib: {
      entry: resolve(import.meta.dirname, "src/index.ts"),
      formats: ["es"],
      fileName: () => "index.js",
    },
    rollupOptions: {
      // Solid must stay a single instance in the consuming app, and the auth
      // client is a peer of this package, not a copy inside it.
      external: [/^solid-js(\/.*)?$/, "@thomasfosterau/effect-auth-client"],
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
  },
});
