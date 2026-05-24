import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [sveltekit()],
  ssr: {
    // better-sqlite3 is a native module; let Node require it at runtime
    external: ["better-sqlite3"],
  },
});
