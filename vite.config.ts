import { recommended } from "@effect/tsgo/oxlint-presets";
import effect from "@enfect/oxlint";
import { defineConfig } from "vite-plus";

// Code outside the published libraries' runtime: tests, test fixtures, build
// and check scripts, and tool configs. They run under Node and Vitest only.
const nonLibraryFiles = [
  "**/*.test.ts",
  "**/*.test.tsx",
  "**/testing/**",
  "**/scripts/**",
  "**/*.config.ts",
  "**/*.mjs",
];

export default defineConfig({
  // Pre-commit (`vp staged`): format with fixes, lint without. Type-aware
  // rules carry autofixes (even the ones at `warn`), so `vp check --fix` would
  // rewrite staged files at commit time and the commit would differ from the
  // tree the gates ran on.
  staged: {
    "*": ["vp check --fix --no-lint", "vp check --no-fmt --no-error-on-unmatched-pattern"],
  },
  fmt: {},
  lint: {
    // `@effect/tsgo`'s preset needs the Effect-patched oxlint and
    // oxlint-tsgolint (the root `prepare` script runs `effect-tsgo patch
    // --typescript --oxlint`). Its rules are type-aware, and so is lint here
    // (`typeAware` below). `@enfect/oxlint`'s `recommended` is the `effect/*`
    // rule set, every rule at `error` unless set below.
    extends: [recommended, effect.configs.recommended],
    plugins: ["eslint", "typescript", "unicorn", "oxc", "import", "promise", "vitest", "jsdoc"],
    categories: {
      correctness: "error",
      suspicious: "error",
      perf: "error",
    },
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",

      // ---- @effect/tsgo preset (type-aware, through oxlint-tsgolint) -------
      // tsconfig.base.json downgrades `unstableApiUsage` to a suggestion: the
      // HTTP tier is built on `effect/http-api` on purpose (#205), and the
      // patched `tsc` in `vp run check` owns that diagnostic. The preset would
      // re-report all ~560 call sites as warnings.
      "effecttsgo/unstable-api-usage": "off",
      // oxlint's `categories` below also cover the `effecttsgo` plugin's own
      // rules. These three are outside the preset's `recommended`, so they stay
      // at the level they report at without the categories: `strict` only
      // (500 `Effect.provide` sites), and two awareness warnings.
      "effecttsgo/strict-effect-provide": "off",
      "effecttsgo/any-unknown-in-error-context": "warn",
      "effecttsgo/unsafe-effect-type-assertion": "warn",

      // ---- oxlint plugins (`correctness` / `suspicious` / `perf`) ----------
      // `_tag` is the discriminant of every Effect tagged union and error
      // class; reading it is the point, so a leading underscore is not a smell.
      "eslint/no-underscore-dangle": "off",
      // docgen's tags (`@since`, `@category`), the module header's `@module`
      // and `@internal` are part of the doc-comment standard; the
      // `@effect-*` tags are the Effect language service's directives.
      "jsdoc/check-tag-names": [
        "error",
        {
          definedTags: [
            "since",
            "category",
            "module",
            "internal",
            "effect-expect-leaking",
            "effect-leakable-service",
          ],
        },
      ],
      // Vitest's `expect(value, message)` takes the failure message second.
      "vitest/valid-expect": ["error", { maxArgs: 2 }],
      // It reads every two-argument `.catch(…)` as `Promise.prototype.catch`,
      // so it fires on Effect's data-first `Effect.catch(self, f)`; no Promise
      // `.catch` here takes two arguments.
      "promise/valid-params": "off",

      // ---- oxlint plugins: adoption allowances ----------------------------
      // Sites that predate the `suspicious` / `perf` categories and the
      // type-aware rules (#503). Same contract as the ported-code
      // allowances below: each rule sits at `warn` so its sites stay
      // reported, a new site is a defect, and once a count reaches zero the
      // line is deleted so the rule is back at `error`. Counts are all sites
      // (sources and tests) when the categories were turned on.
      "unicorn/consistent-function-scoping": "warn", // 148
      "typescript/no-unsafe-type-assertion": "warn", // 124
      "eslint/no-shadow": "warn", // 120
      "typescript/no-unnecessary-type-arguments": "warn", // 59
      "typescript/consistent-return": "warn", // 45
      "vitest/require-mock-type-parameters": "warn", // 32
      // Type tests (expect-error directives) and tests that assert by running
      // an Effect that fails on a mismatch.
      "vitest/expect-expect": "warn", // 29
      "typescript/no-base-to-string": "warn", // 23
      "oxc/no-map-spread": "warn", // 10
      "typescript/no-unnecessary-type-parameters": "warn", // 7
      "typescript/no-unnecessary-type-assertion": "warn", // 7
      "vitest/require-to-throw-message": "warn", // 6
      "promise/always-return": "warn", // 5
      "typescript/no-unnecessary-type-conversion": "warn", // 4
      "typescript/no-useless-default-assignment": "warn", // 4
      "unicorn/no-array-sort": "warn", // 3
      "typescript/unbound-method": "warn", // 3
      "typescript/no-duplicate-type-constituents": "warn", // 4
      "typescript/no-unnecessary-boolean-literal-compare": "warn", // 2
      "typescript/no-misused-spread": "warn", // 2
      "typescript/restrict-template-expressions": "warn", // 2
      "promise/no-promise-in-callback": "warn", // 1
      "unicorn/require-post-message-target-origin": "warn", // 1
      "unicorn/prefer-add-event-listener": "warn", // 1

      // ---- Effect preset: rules this codebase's conventions cut across ----
      // DESIGN.md D4: domain errors are `Data.TaggedError`.
      "effect/avoid-data-tagged-error": "off",
      // Vendor adapters and the client use plain `fetch` to stay Workers-safe.
      "effect/avoid-native-fetch": "off",
      // Optional properties are `?: T | undefined`, and a conditional spread
      // is how a value is omitted under `exactOptionalPropertyTypes`.
      "effect/prefer-option-over-null": "off",
      "effect/no-conditional-empty-object-spread": "off",
      // Imports are `import { Effect } from "effect"` throughout, and
      // `prefer-namespace-imports` hard-codes abbreviations (`Arr`, `P`, …)
      // with no options.
      "effect/no-barrel-imports": "off",
      "effect/prefer-namespace-imports": "off",
      // Exported `make*` constructors are the composition style here.
      "effect/no-service-constructor-imports": "off",
      // Renaming these would change the published API or the wire format.
      "effect/require-is-prefix-for-boolean-schema-field": "off",
      "effect/no-shape-in-symbol-names": "off",
      "effect/no-object-parameters": "off",
      "effect/no-known-value-widening": "off",
      // `string & {}` (literal autocomplete) and `{} extends …` are type-level idioms.
      "effect/avoid-object-type": "off",
      // The remaining blanket catches fail closed on purpose (CAPTCHA,
      // policy evaluation, optional session resolution).
      "effect/effect-catchall-default": "off",
      // The only `makeFilter` calls probe config keys; they are not reusable checks.
      "effect/require-filter-metadata": "off",
      // An awareness prompt, not a defect rule: it fires on every `as`,
      // including the narrowings the DOM, Fetch and framework types
      // structurally require. Stays visible as a warning.
      "effect/casting-awareness": "warn",

      // ---- Effect preset: ported-code allowances --------------------------
      // Code that predates the preset. Each rule sits at `warn` so its sites
      // stay reported; a new site is a defect, not headroom. Once a rule's
      // count reaches zero its line is deleted, so it is back at the preset's
      // `error`. Counts (sources / tests) and the remaining sites:
      // #443.
      // Published types say `Record<string, unknown>` (session and user
      // attributes, metadata, JWT claims, drizzle column types); narrowing
      // them is an API change (60 / 0).
      "effect/no-unsafe-dictionary-type": "warn",
      // Exported `Map` parameters and `ReadonlyMap` results (14 / 292).
      "effect/avoid-native-object-helpers": "warn",
    },
    overrides: [
      {
        // Node-only code may use Node and run effects at the top level.
        files: nonLibraryFiles,
        rules: {
          "effect/avoid-node-imports": "off",
          "effect/effect-run-in-body": "off",
          "effect/use-command-executor-service": "off",
          "effect/use-console-service": "off",
          "effect/use-filesystem-service": "off",
          "effect/use-http-client-service": "off",
          "effect/use-path-service": "off",
          "effect/use-temp-file-scoped": "off",
        },
      },
      {
        // Type tests assert rejections with an expect-error directive, and
        // the barrel tests assert that a member is absent from a namespace.
        files: ["**/*.test.ts", "**/*.test.tsx"],
        rules: { "effect/avoid-ts-ignore": "off", "import/namespace": "off" },
      },
      {
        // The store conformance suites name each test from the typed case
        // record they run (`it(testCase.name, …)`), which is a string the
        // rule cannot see statically.
        files: [
          "packages/alchemy/src/Storage.test.ts",
          "packages/drizzle/src/testing/Conformance.ts",
          "packages/effect-auth/src/testing/MemoryStores.test.ts",
          "packages/effect-auth/src/testing/StoreConformance.test.ts",
          "packages/sql/src/Stores.test.ts",
        ],
        rules: { "vitest/valid-title": "off" },
      },
      {
        // Plain Node tooling that runs no Effect (the dist smoke test and the
        // task-graph builders): native loops, `.length`, `JSON`, `Error`,
        // `try`/`catch` and synchronous `fs` are the idiom there.
        files: ["**/scripts/**", "vite.tasks.ts", "**/vite.config.ts"],
        rules: {
          "effect/avoid-direct-json": "off",
          "effect/avoid-native-object-helpers": "off",
          "effect/avoid-sync-fs": "off",
          "effect/avoid-try-catch": "off",
          "effect/avoid-untagged-errors": "off",
          "effect/imperative-loops": "off",
          "effect/no-length-comparison": "off",
          "effect/no-runtime-typeof": "off",
          "effect/prefer-arr-match": "off",
          "effect/prefer-arr-sort": "off",
          "effect/prefer-effect-is": "off",
        },
      },
      {
        // Code that imports nothing from `effect`: the framework bindings peer
        // only their framework (AGENTS.md), the browser client's runtime is
        // plain `fetch` with no Effect in the bundle (`Client.ts`), and
        // `./ladder` imports nothing at all because browser bundles load it
        // (`ModuleGraph.test.ts`). The
        // rules that steer to an `effect` module (`Array`, `Predicate`,
        // `Match`, `HashSet`, `Schema`, `Clock`) have no satisfiable fix
        // there, and the bindings throw plain `Error`s to framework code that
        // has no typed error channel.
        files: [
          "packages/{react,svelte,solid,vue}/src/**",
          "packages/client/src/Client.ts",
          "packages/effect-auth/src/Ladder.ts",
        ],
        rules: {
          "effect/avoid-direct-json": "off",
          "effect/avoid-direct-tag-checks": "off",
          "effect/avoid-native-object-helpers": "off",
          "effect/avoid-try-catch": "off",
          "effect/avoid-untagged-errors": "off",
          "effect/imperative-loops": "off",
          "effect/no-length-comparison": "off",
          "effect/no-runtime-typeof": "off",
          "effect/prefer-arr-match": "off",
          "effect/prefer-arr-sort": "off",
          "effect/prefer-effect-is": "off",
          "effect/prefer-match-over-switch": "off",
          "effect/use-clock-service": "off",
          "effect/use-console-service": "off",
        },
      },
      {
        // The React binding is built on hooks, and the Vue binding on Vue's
        // `use*` composables, which the rule cannot tell apart from hooks.
        files: ["packages/{react,vue}/src/**"],
        rules: { "effect/avoid-react-hooks": "off" },
      },
      {
        // Direct `node:crypto` use is corralled in these three modules.
        files: [
          "packages/effect-auth/src/password/Password.ts",
          "packages/effect-auth/src/TokenHash.ts",
          "packages/effect-auth/src/Cipher.ts",
        ],
        rules: { "effect/avoid-node-imports": "off" },
      },
      {
        // Decoders, guards and sinks over untrusted input take `unknown`: that
        // is the convention, since narrowing the parameter would move the
        // parse to every caller (#443). Each file's sites: the policy and
        // template document decoders (`PolicyStore`), the owned-read
        // subquery's raw query value (`OwnedAccess.subquery`), the role-rung
        // guard (`Admin`), the cache-safety predicate over wire attributes
        // (`Cacheability.publiclyServeable`), the OAuth userinfo readers
        // (`str`, `nested`), SCIM patch values (`Scim`), the conformance
        // suite's record comparison (`StoreConformance`), the bindings'
        // `onError(cause)` and the client plugin's `request` body.
        files: [
          "packages/effect-auth/src/PolicyStore.ts",
          "packages/effect-auth/src/OwnedAccess.ts",
          "packages/effect-auth/src/Admin.ts",
          "packages/effect-auth/src/Cacheability.ts",
          "packages/effect-auth/src/oauth/OAuth.ts",
          "packages/effect-auth/src/Scim.ts",
          "packages/effect-auth/src/testing/StoreConformance.ts",
          "packages/{react,solid}/src/forms/internal.tsx",
          "packages/svelte/src/forms/internal.ts",
          "packages/svelte/src/forms/submission.svelte.ts",
          "packages/client/src/Client.ts",
        ],
        rules: {
          "effect/no-unknown-parameters": "off",
          "effect/no-unknown-returns": "off",
        },
      },
      {
        // The Promise-facing web handler is an entrypoint: it runs effects.
        files: ["packages/effect-auth/src/http/HttpServer.ts"],
        rules: { "effect/effect-run-in-body": "off" },
      },
      {
        // SvelteKit's `handle` is a Promise-facing entrypoint: it runs the
        // session resolution effect.
        files: ["packages/sveltekit/src/Handle.ts"],
        rules: { "effect/effect-run-in-body": "off" },
      },
    ],
    // Type-aware rules run through oxlint-tsgolint (bundled with Vite+,
    // patched by `@effect/tsgo`). They resolve each workspace import through
    // its `exports`, i.e. the sibling's built `dist/`, so `vp check` runs after
    // `vp run build` (CI's order; AGENTS.md, Verification): on an unbuilt tree
    // every sibling import types as an error and the `effecttsgo` rules report
    // false `missing-effect-context` errors.
    //
    // `typeCheck` stays off. Type checking is owned by each package's `check`
    // task (Effect-patched tsc / vue-tsc / svelte-check against both
    // tsconfig.json and tsconfig.test.json). tsgolint reads only each file's
    // nearest tsconfig.json, which here leaves out the colocated tests and the
    // per-package vite.config.ts: measured on a built tree it reported 70+
    // false errors (Solid tests checked as React JSX, `toSorted` outside the
    // test `lib`, the task-config types).
    options: { typeAware: true, typeCheck: false },
  },
  run: {
    tasks: {
      // Every package's unit suite under one Istanbul coverage map
      // (`coverage/coverage-final.json`), which `fallow audit` reads for exact
      // per-function CRAP scores (`health.coverage` in .fallowrc.json).
      // Without it fallow estimates every function as uncovered, and any
      // function with cyclomatic complexity ≥ 5 fails the gate on its own.
      // Run it before `fallow audit` (the PreToolUse fallow gate never
      // refreshes the map).
      //
      // One vitest process runs every package's suite (`test.projects`
      // below), so no `{ from: "dependencies" }` edge builds the siblings a
      // suite imports through `exports` (→ `dist/`): every package's `build`
      // is named explicitly (cached, so a warm tree pays nothing), and a new
      // package adds itself here. The alchemy runtime suite stays in its own
      // `test:alchemy` task, as in `test:unit`.
      "test:coverage": {
        command:
          "vp test run --coverage --exclude '**/node_modules/**' --exclude '**/dist/**' --exclude packages/alchemy/src/AuthSchema.test.ts",
        dependsOn: [
          "@thomasfosterau/effect-auth#build",
          "@thomasfosterau/effect-auth-alchemy#build",
          "@thomasfosterau/effect-auth-argon2#build",
          "@thomasfosterau/effect-auth-client#build",
          "@thomasfosterau/effect-auth-drizzle#build",
          "@thomasfosterau/effect-auth-react#build",
          "@thomasfosterau/effect-auth-resend#build",
          "@thomasfosterau/effect-auth-saml#build",
          "@thomasfosterau/effect-auth-solid#build",
          "@thomasfosterau/effect-auth-sql#build",
          "@thomasfosterau/effect-auth-svelte#build",
          "@thomasfosterau/effect-auth-sveltekit#build",
          "@thomasfosterau/effect-auth-twilio#build",
          "@thomasfosterau/effect-auth-vue#build",
        ],
        cache: false,
      },
    },
  },
  test: {
    // One entry per package: each package's own vite.config.ts is a vitest
    // project, so the root run and the root coverage map cover them all.
    projects: ["packages/*/vite.config.ts"],
    coverage: {
      provider: "istanbul",
      reporter: ["text-summary", "json-summary", "json"],
      reportsDirectory: "./coverage",
      include: ["packages/*/src/**/*.{ts,tsx,svelte,vue}"],
      exclude: ["**/*.d.ts", "**/*.test.{ts,tsx}", "**/testing/**"],
    },
  },
});
