// @ts-nocheck — see README; current @tanstack/react-start has moved away from
// the /config entrypoint. This file uses the v1.92 shape for reference. Update
// to TanStack Start's current Vite-only setup before running locally.
import { defineConfig } from "@tanstack/react-start/config";
import tsConfigPaths from "vite-tsconfig-paths";

export default defineConfig({
  tsr: { appDirectory: "app" },
  vite: {
    plugins: () => [tsConfigPaths({ projects: ["./tsconfig.json"] })],
    ssr: { external: ["better-sqlite3"] },
  },
});
