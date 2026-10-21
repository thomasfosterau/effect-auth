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
    jsPlugins: [
      { name: "vite-plus", specifier: "vite-plus/oxlint-plugin" },
      { name: "effect", specifier: "@mpsuesser/oxlint-plugin-effect" },
    ],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",

      // @mpsuesser/oxlint-plugin-effect. Every rule of its recommended preset
      // is listed, so a plugin upgrade that adds one enables nothing until it
      // is listed here. Rules that are off are tracked in #438.

      // On: Effect v4 correctness and the platform services.
      "effect/avoid-mutable-state": "error",
      "effect/avoid-node-imports": "error",
      "effect/avoid-option-getorthrow": "error",
      "effect/avoid-platform-coupling": "error",
      "effect/avoid-process-env": "error",
      "effect/avoid-schema-suffix": "error",
      "effect/avoid-yield-ref": "error",
      "effect/context-tag-extends": "error",
      "effect/effect-run-in-body": "error",
      "effect/maybe-prefix-requires-option": "error",
      "effect/no-effect-ignore-then-as": "error",
      "effect/no-module-mocking": "error",
      "effect/no-opaque-instance-fields": "error",
      "effect/no-reflect-apply": "error",
      "effect/no-reflect-get": "error",
      "effect/no-unknown-type-aliases": "error",
      "effect/no-widen-then-assert": "error",
      "effect/prefer-array-fromoption-over-option-match-empty": "error",
      "effect/prefer-duration-constructors": "error",
      "effect/prefer-redacted-config": "error",
      "effect/require-schema-type-alias": "error",
      "effect/throw-in-effect-gen": "error",
      "effect/use-command-executor-service": "error",
      "effect/use-console-service": "error",
      "effect/use-filesystem-service": "error",
      "effect/use-http-client-service": "error",
      "effect/use-path-service": "error",
      "effect/use-random-service": "error",
      "effect/use-temp-file-scoped": "error",
      "effect/vm-in-wrong-file": "error",

      // Off: they contradict a documented convention.
      // DESIGN.md D4: domain errors are `Data.TaggedError`.
      "effect/avoid-data-tagged-error": "off",
      // Vendor adapters and the client use plain `fetch` to stay Workers-safe.
      "effect/avoid-native-fetch": "off",
      // The React binding is built on hooks.
      "effect/avoid-react-hooks": "off",
      // Optional properties are `?: T | undefined`, and a conditional spread
      // is how a value is omitted under `exactOptionalPropertyTypes`.
      "effect/prefer-option-over-null": "off",
      "effect/no-conditional-empty-object-spread": "off",
      // Imports are `import { Effect } from "effect"` throughout.
      "effect/no-barrel-imports": "off",
      "effect/prefer-namespace-imports": "off",
      // Exported `make*` constructors are the composition style here.
      "effect/no-service-constructor-imports": "off",
      // Renaming these would change the published API or the wire format.
      "effect/require-is-prefix-for-boolean-schema-field": "off",
      "effect/no-shape-in-symbol-names": "off",
      "effect/no-object-parameters": "off",
      "effect/no-known-value-widening": "off",
      // Type tests assert rejections with `@ts-expect-error`.
      "effect/avoid-ts-ignore": "off",
      // `string & {}` (literal autocomplete) and `{} extends …` are type-level idioms.
      "effect/avoid-object-type": "off",
      // The remaining blanket catches fail closed on purpose (CAPTCHA,
      // policy evaluation, optional session resolution).
      "effect/effect-catchall-default": "off",
      // The only `makeFilter` calls probe config keys; they are not reusable checks.
      "effect/require-filter-metadata": "off",

      // Off for now: worth adopting, but each is a large refactor (#438).
      "effect/avoid-any": "off",
      "effect/avoid-direct-json": "off",
      "effect/avoid-direct-tag-checks": "off",
      "effect/avoid-expect-in-if": "off",
      "effect/avoid-native-object-helpers": "off",
      "effect/avoid-non-null-assertion": "off",
      "effect/avoid-sync-fs": "off",
      "effect/avoid-try-catch": "off",
      "effect/avoid-untagged-errors": "off",
      "effect/casting-awareness": "off",
      "effect/effect-promise-vs-trypromise": "off",
      "effect/imperative-loops": "off",
      "effect/no-chained-type-assertions": "off",
      "effect/no-length-comparison": "off",
      "effect/no-runtime-typeof": "off",
      "effect/no-unknown-parameters": "off",
      "effect/no-unknown-returns": "off",
      "effect/no-unsafe-dictionary-type": "off",
      "effect/prefer-arr-match": "off",
      "effect/prefer-arr-sort": "off",
      "effect/prefer-effect-fn": "off",
      "effect/prefer-effect-is": "off",
      "effect/prefer-match-over-switch": "off",
      "effect/require-effect-concurrency": "off",
      "effect/require-safety-comment-for-type-assertion": "off",
      "effect/use-clock-service": "off",
      "effect/yield-in-for-loop": "off",
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
      {
        // The framework bindings import no `effect`, so there is no Console service.
        files: ["packages/{react,svelte,solid,vue}/src/**"],
        rules: { "effect/use-console-service": "off" },
      },
    ],
    // Type checking is owned by each package's `check` task (tsc / vue-tsc /
    // svelte-check), which understands the per-package NodeNext tsconfigs.
    // Keeping it out of lint avoids one cross-package program mis-resolving
    // per-package types (e.g. @types/node globals).
    options: { typeAware: false, typeCheck: false },
  },
});
