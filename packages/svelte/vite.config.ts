import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

export default defineConfig({
  run: packageTasks({
    build: "svelte-package -i src -o dist && node ./scripts/postbuild.mjs",
    check:
      "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && svelte-check --tsconfig ./tsconfig.json --fail-on-warnings && vp test --typecheck --run",
  }),
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
