import { reactRouter } from "@react-router/dev/vite";
import { defineConfig } from "vite-plus";
import tsconfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [reactRouter(), tsconfigPaths()],
  ssr: { external: ["better-sqlite3"] },
});
