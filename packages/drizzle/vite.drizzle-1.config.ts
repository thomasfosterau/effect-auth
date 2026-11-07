/**
 * The drizzle suite again, on drizzle-orm's 1.0 line (#544).
 *
 * The peer range admits the classic `0.4x` line and the 1.0 line. The suites
 * import `drizzle-orm`, which the catalog pins to the 0.4x line, so this
 * config resolves every `drizzle-orm` and `drizzle-orm/*` import to
 * `drizzle-orm-effect` (the aliased `1.0.0-rc.5` prerelease the applications
 * run) instead. `test:unit` runs both. Type checking stays on the 0.4x line;
 * this run proves the runtime behaviour. What differs between the lines is in
 * `src/testing/DrizzleLine.ts`.
 */
import { defineConfig, mergeConfig } from "vite-plus";
import base from "./vite.config.ts";

export default mergeConfig(
  base,
  defineConfig({
    resolve: {
      alias: [{ find: /^drizzle-orm(?=\/|$)/, replacement: "drizzle-orm-effect" }],
    },
  }),
);
