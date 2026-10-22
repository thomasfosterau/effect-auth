import { recommended } from "@effect/tsgo/oxlint-presets";
import effect from "@mpsuesser/oxlint-plugin-effect";
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
  staged: {
    "*": "vp check --fix",
  },
  fmt: {},
  lint: {
    // `@effect/tsgo`'s preset needs the Effect-patched oxlint (the root
    // `prepare` script runs `effect-tsgo patch --typescript --oxlint`). Its
    // rules are type-aware, so with `typeAware: false` below only the
    // syntactic ones report.
    extends: [recommended, effect.configs.recommended],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",

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
      // `error`. Counts and the remaining sites: #ALLOWANCE_ISSUE.
      "effect/require-safety-comment-for-type-assertion": "warn",
      "effect/use-clock-service": "warn",
      "effect/avoid-native-object-helpers": "warn",
      "effect/imperative-loops": "warn",
      "effect/avoid-non-null-assertion": "warn",
      "effect/prefer-effect-fn": "warn",
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
        // Type tests assert rejections with an expect-error directive.
        files: ["**/*.test.ts", "**/*.test.tsx"],
        rules: { "effect/avoid-ts-ignore": "off" },
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
        // only their framework (AGENTS.md), and `./ladder` imports nothing at
        // all because browser bundles load it (`ModuleGraph.test.ts`). The
        // rules that steer to an `effect` module (`Array`, `Predicate`,
        // `Match`, `HashSet`, `Schema`, `Clock`) have no satisfiable fix
        // there, and the bindings throw plain `Error`s to framework code that
        // has no typed error channel.
        files: ["packages/{react,svelte,solid,vue}/src/**", "packages/effect-auth/src/Ladder.ts"],
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
        // The Promise-facing web handler is an entrypoint: it runs effects.
        files: ["packages/effect-auth/src/http/HttpServer.ts"],
        rules: { "effect/effect-run-in-body": "off" },
      },
    ],
    // Type checking is owned by each package's `check` task (tsc / vue-tsc /
    // svelte-check), which understands the per-package NodeNext tsconfigs.
    // Keeping it out of lint avoids one cross-package program mis-resolving
    // per-package types (e.g. @types/node globals).
    options: { typeAware: false, typeCheck: false },
  },
});
