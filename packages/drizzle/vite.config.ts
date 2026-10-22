import { defineConfig } from "vite-plus";
import { packageTasks } from "../../vite.tasks.ts";

export default defineConfig({
  run: packageTasks({
    build: "tsc",
    check: "tsc --noEmit && tsc --noEmit -p tsconfig.test.json && vp test --typecheck --run",
  }),
  test: {
    globals: true,
    environment: "node",
    exclude: ["**/node_modules/**", "**/dist/**", "**/.reference/**"],
    // Booting PGlite (Postgres compiled to WebAssembly) runs `initdb` inside
    // the WASM module: seconds of CPU when idle, and past vitest's default
    // timeouts on a loaded machine. This setup runs it once per test run,
    // outside any timeout, and provides a migrated data directory that test
    // files open with `migratedPglite` (src/testing/PgliteTemplate.ts), which
    // skips `initdb` (#291, #305).
    globalSetup: ["./src/testing/PgliteTemplate.setup.ts"],
    // Opening that instance in a file's `beforeAll` still costs about 1 s idle
    // and has taken 10–18 s when every package's suite runs at once on a loaded
    // host, past vitest's 10 s default (#344). The raise is this package's
    // alone; `testTimeout` stays at the default.
    hookTimeout: 30_000,
  },
});
