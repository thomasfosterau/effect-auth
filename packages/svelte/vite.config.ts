import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [svelte()],
  // Svelte 5 resolves to its server build without this, and `mount()` (which
  // `@testing-library/svelte` calls) is unavailable there.
  resolve: { conditions: ["browser"] },
  test: {
    globals: true,
    environment: "jsdom",
    // Scoped to the sources: `svelte-package` copies everything under `src/`
    // into `dist/`, tests included, so an unscoped scan would run each suite
    // twice.
    include: ["src/**/*.test.ts"],
  },
});
