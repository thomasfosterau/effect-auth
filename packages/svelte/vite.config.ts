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
    // `@testing-library/svelte` ships `.svelte` sources. vite-plugin-svelte
    // marks them for transformation by crawling the dependencies of the
    // package vitest runs from, so the root `vp run test:coverage` run (which
    // starts from the workspace root, not this package) needs it inlined
    // explicitly.
    server: { deps: { inline: [/@testing-library\/svelte/] } },
  },
});
