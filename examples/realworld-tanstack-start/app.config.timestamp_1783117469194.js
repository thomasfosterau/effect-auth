// app.config.ts
import { defineConfig } from "@tanstack/react-start/config";
import tsConfigPaths from "vite-tsconfig-paths";
var app_config_default = defineConfig({
  tsr: { appDirectory: "app" },
  vite: {
    plugins: () => [tsConfigPaths({ projects: ["./tsconfig.json"] })],
    ssr: { external: ["better-sqlite3"] },
  },
});
export { app_config_default as default };
