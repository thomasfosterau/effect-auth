import { vitePlugin as remix } from "@remix-run/dev";
import { defineConfig } from "vite-plus";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [remix(), tsconfigPaths()],
  ssr: { external: ["better-sqlite3"] },
  // Prevent two React copies (root v19 + workspace v18) loading at once.
  resolve: { dedupe: ["react", "react-dom"] },
});
