import { recommended } from "@effect/tsgo/oxlint-presets";
import effect from "@enfect/oxlint";
import { defineConfig } from "vite-plus";

// Code outside the published libraries' runtime: tests, test fixtures, build
// and check scripts, and tool configs. They run under Node and Vitest only.
const nonLibraryFiles = [
  "**/*.test.ts",
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
  // Changesets writes each package's CHANGELOG.md in the version PR, in its own
  // layout (blank lines that carry list indentation); formatting it here would
  // fail CI on every version PR's merge commit. It is generated, never edited.
  fmt: { ignorePatterns: ["**/CHANGELOG.md"] },
  lint: {
    // `@effect/tsgo`'s preset needs the Effect-patched oxlint and tsrs (the
    // root `prepare` script runs `effect-tsgo patch --typescript --oxlint
    // --tsrs`). Its rules are type-aware, and so is lint here
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

      // ---- @effect/tsgo preset (type-aware, through tsrs) -----------------
      // tsconfig.base.json downgrades `unstableApiUsage` to a suggestion: the
      // HTTP tier is built on `effect/http-api` on purpose, and the
      // patched `tsc` in `vp run check` owns that diagnostic. The preset would
      // re-report all ~560 call sites as warnings.
      "effecttsgo/unstable-api-usage": "off",
      // oxlint's `categories` below also cover the `effecttsgo` plugin's own
      // rules. These are outside the preset's `recommended`, so they stay at
      // the level they report at without the categories: `strict` only (500
      // `Effect.provide` sites).
      "effecttsgo/strict-effect-provide": "off",
      "effecttsgo/any-unknown-in-error-context": "error",
      "effecttsgo/unsafe-effect-type-assertion": "error",
      "effecttsgo/schema-number": "error",

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
      // Core and the Workers-safe adapters run outside Node, so the Node
      // `Buffer` global is off-limits outside the `node:crypto` corral and
      // Node-only code: use `effect/encoding`, `TextEncoder` and
      // `Uint8Array`.
      "eslint/no-restricted-globals": [
        "error",
        {
          name: "Buffer",
          message:
            "Use `effect/encoding` (Base64, Base64Url, Hex), `TextEncoder` or `Uint8Array`: `Buffer` is a Node global.",
        },
      ],
      // Vitest's `expect(value, message)` takes the failure message second.
      "vitest/valid-expect": ["error", { maxArgs: 2 }],
      // It reads every two-argument `.catch(…)` as `Promise.prototype.catch`,
      // so it fires on Effect's data-first `Effect.catch(self, f)`; no Promise
      // `.catch` here takes two arguments.
      "promise/valid-params": "off",

      // Assertion helpers are named `expect<What>` (`expectAgreement`,
      // `expectProviderError`, …) and assert inside.
      "vitest/expect-expect": ["error", { assertFunctionNames: ["expect", "expect*"] }],

      // ---- Effect preset: rules this codebase's conventions cut across ----
      // "Nothing" is an `Option`; an options-object member is `readonly x?: T`
      // and a value that may be `undefined` is forwarded by leaving its key
      // out, which `definedKeys` does.
      "effect/prefer-option-over-null": "error",
      // Owner decision (2026-11-11): the helper modules are namespace imports
      // under the rule's canonical aliases (`Arr`, `P`, `R`, `Str`, `Eq`,
      // `Bool`; `Option` and `Schema` by name), in sources and tests alike.
      "effect/prefer-namespace-imports": "error",
      "effect/casting-awareness": "error",
    },
    overrides: [
      {
        // Values whose absence a third party spells `null` or `undefined`:
        // JSON (`Types.Json`, the attribute values `Entity` reads from it),
        // SQL rows and the values bound to them (`./sql`), node-saml's parsed
        // XML (`./saml`), the JSON:API relationship the client reads
        // (`client/Wire.ts`) and Node's callback API (the scrypt suite).
        files: [
          "packages/effect-auth/src/Types.ts",
          "packages/effect-auth/src/Entity.ts",
          "packages/effect-auth/src/sql/Stores.ts",
          "packages/effect-auth/src/saml/Verifier.ts",
          "packages/effect-auth/src/client/Wire.ts",
          "packages/effect-auth/src/password/ScryptDefaults.test.ts",
        ],
        rules: { "effect/prefer-option-over-null": "off" },
      },
      {
        // The adapters' third-party shapes: SvelteKit serializes load and
        // action data with devalue, which cannot carry an `Option`, and its
        // event API answers `undefined`; Drizzle column and row types; Better
        // Auth's API objects; the D1 and `effect/sql` driver API; Node's
        // child-process API in the workerd suite.
        files: [
          "packages/sveltekit/src/**",
          "packages/drizzle/src/**",
          "packages/better-auth/src/**",
          "packages/alchemy-cloudflare/src/D1Client.ts",
          "packages/argon2/src/Workerd.test.ts",
        ],
        rules: { "effect/prefer-option-over-null": "off" },
      },
      {
        // Adoption allowance for `prefer-option-over-null`: these files still
        // answer "nothing" with `null` or `undefined` and report it as a
        // warning, a new site is
        // a defect, and a file leaves the list once its count reaches zero.
        files: [
          "packages/effect-auth/src/AccessParity.test.ts",
          "packages/effect-auth/src/Admin.test.ts",
          "packages/effect-auth/src/ApiKey.ts",
          "packages/effect-auth/src/AuthLifecycle.test.ts",
          "packages/effect-auth/src/AuthorizationModel.ts",
          "packages/effect-auth/src/BeforeAuthenticate.test.ts",
          "packages/effect-auth/src/Cacheability.test.ts",
          "packages/effect-auth/src/Cacheability.ts",
          "packages/effect-auth/src/Cipher.ts",
          "packages/effect-auth/src/ClientIP.test.ts",
          "packages/effect-auth/src/ClientIP.ts",
          "packages/effect-auth/src/CloudflareAccess.ts",
          "packages/effect-auth/src/Condition.ts",
          "packages/effect-auth/src/ConfigEmptyEnv.test.ts",
          "packages/effect-auth/src/Delivery.ts",
          "packages/effect-auth/src/Guard.test.ts",
          "packages/effect-auth/src/Guard.ts",
          "packages/effect-auth/src/Hooks.ts",
          "packages/effect-auth/src/HooksClientAddress.ts",
          "packages/effect-auth/src/IdpUrlPolicy.ts",
          "packages/effect-auth/src/Jwt.test.ts",
          "packages/effect-auth/src/Jwt.ts",
          "packages/effect-auth/src/KeyValueStores.ts",
          "packages/effect-auth/src/MagicLink.test.ts",
          "packages/effect-auth/src/ManagedUser.ts",
          "packages/effect-auth/src/Messages.ts",
          "packages/effect-auth/src/OidcProvider.test.ts",
          "packages/effect-auth/src/OidcProvider.ts",
          "packages/effect-auth/src/OptionalSecretConfig.ts",
          "packages/effect-auth/src/Organization.test.ts",
          "packages/effect-auth/src/Organization.ts",
          "packages/effect-auth/src/OrganizationEntities.ts",
          "packages/effect-auth/src/OutboundHttp.test.ts",
          "packages/effect-auth/src/OutboundHttp.ts",
          "packages/effect-auth/src/OwnedAccess.test.ts",
          "packages/effect-auth/src/OwnedAccess.ts",
          "packages/effect-auth/src/PhoneOtp.test.ts",
          "packages/effect-auth/src/PlatformCrypto.ts",
          "packages/effect-auth/src/Policy.ts",
          "packages/effect-auth/src/PolicyStore.ts",
          "packages/effect-auth/src/Protected.ts",
          "packages/effect-auth/src/RateLimitPersistence.ts",
          "packages/effect-auth/src/Rbac.ts",
          "packages/effect-auth/src/ReadScope.test.ts",
          "packages/effect-auth/src/ReadScope.ts",
          "packages/effect-auth/src/RecipientSendLimit.test.ts",
          "packages/effect-auth/src/RecipientSendLimit.ts",
          "packages/effect-auth/src/Redirect.ts",
          "packages/effect-auth/src/RemoteJwks.ts",
          "packages/effect-auth/src/Scim.test.ts",
          "packages/effect-auth/src/SessionContext.ts",
          "packages/effect-auth/src/SessionCookieCache.test.ts",
          "packages/effect-auth/src/SessionCookieCache.ts",
          "packages/effect-auth/src/SessionResolution.ts",
          "packages/effect-auth/src/SessionService.ts",
          "packages/effect-auth/src/Sso.test.ts",
          "packages/effect-auth/src/Sso.ts",
          "packages/effect-auth/src/System.test.ts",
          "packages/effect-auth/src/TrustedDevice.ts",
          "packages/effect-auth/src/User.ts",
          "packages/effect-auth/src/UserCredentials.ts",
          "packages/effect-auth/src/UserStore.test.ts",
          "packages/effect-auth/src/Username.test.ts",
          "packages/effect-auth/src/Workerd.test.ts",
          "packages/effect-auth/src/email/EmailOtp.test.ts",
          "packages/effect-auth/src/email/EmailPassword.test.ts",
          "packages/effect-auth/src/email/EmailPassword.ts",
          "packages/effect-auth/src/http/ApiKeyResolution.test.ts",
          "packages/effect-auth/src/http/CacheControl.ts",
          "packages/effect-auth/src/http/HttpMiddleware.test.ts",
          "packages/effect-auth/src/http/HttpServer.test.ts",
          "packages/effect-auth/src/http/HttpServer.ts",
          "packages/effect-auth/src/http/HttpServerModules.test.ts",
          "packages/effect-auth/src/http/RemoteSession.ts",
          "packages/effect-auth/src/multifactor/MultiFactor.ts",
          "packages/effect-auth/src/multifactor/WebAuthn.test.ts",
          "packages/effect-auth/src/multifactor/WebAuthn.ts",
          "packages/effect-auth/src/multifactor/WebAuthnCodec.ts",
          "packages/effect-auth/src/oauth/OAuth.test.ts",
          "packages/effect-auth/src/oauth/OAuth.ts",
          "packages/effect-auth/src/password/Argon2.ts",
          "packages/effect-auth/src/password/DecoyVerify.ts",
          "packages/effect-auth/src/password/Password.ts",
          "packages/effect-auth/src/password/Pbkdf2Defaults.test.ts",
          "packages/effect-auth/src/password/Scrypt.ts",
          "packages/effect-auth/src/plugins/AbusePlugins.test.ts",
          "packages/effect-auth/src/plugins/AccountLockout.test.ts",
          "packages/effect-auth/src/plugins/AccountLockout.ts",
          "packages/effect-auth/src/plugins/Captcha.ts",
          "packages/effect-auth/src/plugins/IPRateLimit.test.ts",
          "packages/effect-auth/src/plugins/IPRateLimit.ts",
          "packages/effect-auth/src/plugins/LastLoginMethod.test.ts",
          "packages/effect-auth/src/sql/ReadScope.test.ts",
          "packages/effect-auth/src/sql/Stores.test.ts",
          "packages/effect-auth/src/testing/GuardExpectations.ts",
          "packages/effect-auth/src/testing/Passwordless.ts",
          "packages/effect-auth/src/testing/RunAs.ts",
          "packages/effect-auth/src/testing/StoreConformance.ts",
          "packages/effect-auth/src/testing/TestJws.ts",
          "packages/effect-auth/src/testing/WireFormat.ts",
        ],
        rules: { "effect/prefer-option-over-null": "warn" },
      },
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
          "eslint/no-restricted-globals": "off",
        },
      },
      {
        // Type tests assert rejections with an expect-error directive, and
        // the barrel tests assert that a member is absent from a namespace.
        files: ["**/*.test.ts"],
        rules: { "effect/avoid-ts-ignore": "off", "import/namespace": "off" },
      },
      {
        // The alchemy engine suites run deploys outside alchemy's CLI: the
        // engine's types require services a schema deploy never reaches
        // (`Terminal` for plan approval, `ChildProcessSpawner`, `Interaction`),
        // which have no stand-in short of reimplementing them.
        files: [
          "packages/alchemy-cloudflare/src/AuthSchema.test.ts",
          "packages/alchemy-postgres/src/AuthSchema.test.ts",
        ],
        rules: { "effecttsgo/unsafe-effect-type-assertion": "off" },
      },
      {
        // Published wire contract: these schemas name JSON fields fixed by
        // the HTTP API (JSON:API attributes, SCIM 2.0, OAuth registration),
        // the captcha vendors' answers (`success`) and stored records
        // (`verified`), and the tests decode those same bodies.
        files: [
          "packages/effect-auth/src/http/HttpApiSchema.ts",
          "packages/effect-auth/src/http/HttpApi.ts",
          "packages/effect-auth/src/Identifier.ts",
          "packages/effect-auth/src/KeyValueStores.ts",
          "packages/effect-auth/src/plugins/Captcha.ts",
          "packages/sveltekit/src/Actions.ts",
          "packages/effect-auth/src/http/HttpServer.test.ts",
          "packages/effect-auth/src/http/HttpServerModules.test.ts",
          "packages/effect-auth/src/http/ApiKeyResolution.test.ts",
          "packages/effect-auth/src/OidcProvider.test.ts",
          "packages/effect-auth/src/Scim.test.ts",
        ],
        rules: { "effect/require-is-prefix-for-boolean-schema-field": "off" },
      },
      {
        // Third-party API boundary: `Context.ServiceClass.Shape` is Effect's
        // name for a service key's type, which the guard instance extends.
        files: ["packages/effect-auth/src/http/AuthorizationMiddleware.ts"],
        rules: { "effect/no-shape-in-symbol-names": "off" },
      },
      {
        // drizzle-orm types its Effect drivers' error channel as `unknown`
        // (`DrizzleResult`); `run` maps it to `AuthError` at the boundary.
        files: ["packages/drizzle/src/internal.ts"],
        rules: { "effecttsgo/any-unknown-in-error-context": "off" },
      },
      {
        // The store conformance suites name each test from the typed case
        // record they run (`it(testCase.name, …)`), which is a string the
        // rule cannot see statically.
        files: [
          "packages/alchemy-cloudflare/src/Storage.test.ts",
          "packages/drizzle/src/testing/Conformance.ts",
          "packages/effect-auth/src/sql/Stores.test.ts",
          "packages/effect-auth/src/testing/MemoryStores.test.ts",
          "packages/effect-auth/src/testing/StoreConformance.test.ts",
          "packages/better-auth/src/Users.test.ts",
        ],
        rules: { "vitest/valid-title": "off" },
      },
      {
        // Native `Map`s that are part of a published type, not storage: the
        // WebAuthn CBOR decoder returns a CBOR map as `CBORMap`, a public
        // `ReadonlyMap` that callers tell from an array with `instanceof Map`,
        // and `RbacConfig` takes `ReadonlyMap` as well as records, which its
        // test passes. Changing either is an API change.
        files: [
          "packages/effect-auth/src/multifactor/WebAuthnCodec.ts",
          "packages/effect-auth/src/Rbac.test.ts",
        ],
        rules: { "effect/avoid-native-object-helpers": "off" },
      },
      {
        // Plain Node tooling that runs no Effect (the dist smoke test and the
        // task-graph builders, the release script): native loops, `.length`,
        // `JSON`, `Error`, `try`/`catch`, synchronous `fs` and `fetch` are the
        // idiom there.
        files: ["**/scripts/**", "vite.tasks.ts", "**/vite.config.ts"],
        rules: {
          "effect/avoid-direct-json": "off",
          "effect/avoid-native-fetch": "off",
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
          "effect/prefer-option-over-null": "off",
        },
      },
      {
        // Code that imports nothing from `effect` at runtime: the Svelte
        // binding (`effect` types only), the browser client's runtime is
        // plain `fetch` with no Effect in the bundle (`client/Client.ts`), and
        // `./Ladder` imports nothing at all because browser bundles load it
        // (`ModuleGraph.test.ts`). The
        // rules that steer to an `effect` module (`Array`, `Predicate`,
        // `Match`, `HashSet`, `Schema`, `Clock`) have no satisfiable fix
        // there, and the binding throws plain `Error`s to framework code that
        // has no typed error channel.
        files: [
          "packages/svelte/src/**",
          "packages/effect-auth/src/client/Client.ts",
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
        // Direct `node:crypto` use is corralled in scrypt, which
        // `effect/crypto` lacks. It imports `Buffer` from `node:buffer` where
        // it needs it, so the global stays banned here too: `nodejs_compat`
        // sets no `Buffer` global on Workers dated before 2024-09-23.
        files: ["packages/effect-auth/src/password/Scrypt.ts"],
        rules: { "effect/avoid-node-imports": "off" },
      },
      {
        // Decoders, guards and sinks over untrusted input take `unknown`: that
        // is the convention, since narrowing the parameter would move the
        // parse to every caller. Each file's sites: the policy and
        // template document decoders (`PolicyStore`), the owned-read
        // subquery's raw query value (`OwnedAccess.subquery`), the role-rung
        // guard (`Admin`), the cache-safety predicate over wire attributes
        // (`Cacheability.publiclyServeable`), the OAuth userinfo readers
        // (`str`, `nested`), SCIM patch values (`Scim`), the conformance
        // suite's record comparison (`StoreConformance`), BetterAuth's thrown
        // `APIError` (`better-auth`'s `Convert.fromApiError`), the Svelte binding's
        // `onError(cause)`, the client plugin's `request` body, the
        // WebAuthn client-data JSON readers (`WebAuthnCodec`) and the
        // key-value stores' JSON writer (`KeyValueStores`).
        files: [
          "packages/effect-auth/src/PolicyStore.ts",
          "packages/effect-auth/src/OwnedAccess.ts",
          "packages/effect-auth/src/Admin.ts",
          "packages/effect-auth/src/Cacheability.ts",
          "packages/effect-auth/src/oauth/OAuth.ts",
          "packages/effect-auth/src/Scim.ts",
          "packages/effect-auth/src/testing/StoreConformance.ts",
          "packages/better-auth/src/Convert.ts",
          "packages/svelte/src/forms/internal.ts",
          "packages/svelte/src/forms/submission.svelte.ts",
          "packages/effect-auth/src/client/Client.ts",
          "packages/effect-auth/src/multifactor/WebAuthnCodec.ts",
          "packages/effect-auth/src/KeyValueStores.ts",
        ],
        rules: {
          "effect/no-unknown-parameters": "off",
          "effect/no-unknown-returns": "off",
        },
      },
      {
        // The conformance suite's record comparison maps any stored value to
        // a comparable one, so it answers `unknown` too, as above.
        files: ["packages/effect-auth/src/testing/StoreConformance.ts"],
        rules: { "effect/no-known-value-widening": "off" },
      },
      {
        // The edge, where plain `fetch` is the API being adapted: the
        // browser client has no Effect runtime, the test `HttpClient` defers
        // to the global a suite swaps, and the workerd and Web-handler suites
        // call the server they start. Core code goes through `HttpClient`.
        files: [
          "packages/effect-auth/src/client/Client.ts",
          "packages/effect-auth/src/testing/HttpClient.ts",
          "packages/effect-auth/src/http/DomainAttestation.test.ts",
          "packages/effect-auth/src/Workerd.test.ts",
          "packages/argon2/src/Workerd.test.ts",
        ],
        rules: { "effect/avoid-native-fetch": "off" },
      },
      {
        // Published wire contract: the bounds filter sits on each write
        // payload, and an `identifier` on it makes every one a named
        // component of the OpenAPI document instead of an inline body.
        files: ["packages/effect-auth/src/http/HttpApi.ts"],
        rules: { "effect/require-filter-metadata": "off" },
      },
      {
        // The Promise-facing web handler is an entrypoint: it runs effects.
        // `PlatformCrypto.context` builds its resource-free default layer
        // once, synchronously, for callers with no layer of their own.
        files: [
          "packages/effect-auth/src/http/HttpServer.ts",
          "packages/effect-auth/src/PlatformCrypto.ts",
        ],
        rules: { "effect/effect-run-in-body": "off" },
      },
      {
        // The session Atoms' cross-tab sync posts through
        // `BroadcastChannel#postMessage`, which takes no `targetOrigin` (a
        // channel never leaves its origin). The rule reads no types, so it
        // cannot tell it from `window.postMessage` (its docs say so), and its
        // fix (`channel.location.origin`) does not type-check.
        files: ["packages/effect-auth/src/client/SessionAtoms.ts"],
        rules: { "unicorn/require-post-message-target-origin": "off" },
      },
      {
        // `client/Client.ts` has no runtime imports, so it cannot decode the
        // wire: each call names the contract's own response type for the body
        // the server encodes. `./ladder` imports nothing, so it cannot map its
        // axes with `Record.map`.
        files: ["packages/effect-auth/src/client/Client.ts", "packages/effect-auth/src/Ladder.ts"],
        rules: {
          "effect/casting-awareness": "off",
          "typescript/no-unsafe-type-assertion": "off",
        },
      },
      {
        // drizzle's dialect table brands keep its three handles from sharing a
        // type, and a generic table's columns lose their value types, so the
        // adapter restates what `ColumnKey` checked at the caller. `effect/sql`
        // types `transformRows` over the row object its D1 client builds, and
        // the test shim fakes only the D1 binding members the suites reach.
        // Alchemy's `Stack.make` declares services an `AuthSchema` deploy never
        // reaches, which its suites cannot provide. The Release workflow's
        // `tag` job runs `scripts/release.ts` before any install, so it reads
        // its JSON with Node built-ins alone.
        files: [
          "scripts/release.ts",
          "packages/drizzle/src/Columns.ts",
          "packages/drizzle/src/Database.ts",
          "packages/drizzle/src/RateLimitStore.ts",
          "packages/drizzle/src/UserStore.ts",
          "packages/alchemy-cloudflare/src/D1Client.ts",
          "packages/alchemy-cloudflare/src/testShim.ts",
          "packages/alchemy-cloudflare/src/AuthSchema.test.ts",
          "packages/alchemy-postgres/src/AuthSchema.test.ts",
        ],
        rules: {
          "effect/casting-awareness": "off",
          "typescript/no-unsafe-type-assertion": "off",
        },
      },
      {
        // Third-party API boundaries: drizzle's dialect table brands leave
        // its three handles no shared type, so `databaseLayer`'s
        // implementation takes what its overloads checked as `unknown` and
        // erases it once; the D1 test shim hands its fake to Alchemy's client
        // as workerd's `D1Database`, which the fake implements only in part.
        files: ["packages/drizzle/src/Database.ts", "packages/alchemy-cloudflare/src/testShim.ts"],
        rules: { "effect/no-unknown-parameters": "off" },
      },
      {
        // SvelteKit's `handle` is a Promise-facing entrypoint: it runs the
        // session resolution effect.
        files: ["packages/sveltekit/src/Handle.ts"],
        rules: { "effect/effect-run-in-body": "off" },
      },
    ],
    // Type-aware rules resolve siblings through their built `dist/`, so run
    // `vp check` after `vp run build`. `typeCheck` stays off: `vp run check`
    // owns type checking, and tsrs (which reads only the nearest
    // tsconfig.json) misreports the colocated tests.
    options: { typeAware: true, typeCheck: false },
  },
  run: {
    tasks: {
      build: { command: "vp run -r build" },
      // The Release workflow's `build` job (.github/workflows/release.yml):
      // packs each public package whose version is not on npm into
      // `release/` (pnpm rewrites `catalog:` and `workspace:` specifiers) and
      // lists them in `release/manifest.json`. It publishes nothing, so it is
      // also the dry run.
      "release:pack": {
        command: "vpx scripts/release.ts pack",
        dependsOn: ["build"],
        cache: false,
      },
      check: {
        command: "tsc -p tsconfig.scripts.json",
        dependsOn: [
          "@thomasfosterau/effect-auth#check",
          "@thomasfosterau/effect-auth-alchemy-cloudflare#check",
          "@thomasfosterau/effect-auth-alchemy-postgres#check",
          "@thomasfosterau/effect-auth-argon2#check",
          "@thomasfosterau/effect-auth-better-auth#check",
          "@thomasfosterau/effect-auth-drizzle#check",
          "@thomasfosterau/effect-auth-svelte#check",
          "@thomasfosterau/effect-auth-sveltekit#check",
        ],
      },
      // The API reference for every package; only the core's examples run.
      docs: {
        command: "echo 'docs: every package documented'",
        dependsOn: [
          "@thomasfosterau/effect-auth#docs",
          "@thomasfosterau/effect-auth-alchemy-cloudflare#docs",
          "@thomasfosterau/effect-auth-alchemy-postgres#docs",
          "@thomasfosterau/effect-auth-argon2#docs",
          "@thomasfosterau/effect-auth-better-auth#docs",
          "@thomasfosterau/effect-auth-drizzle#docs",
          "@thomasfosterau/effect-auth-svelte#docs",
          "@thomasfosterau/effect-auth-sveltekit#docs",
        ],
      },
      "check:dist": { command: "vpx scripts/check-dist.ts", cache: false },
      fallow: { command: "vp exec fallow --summary", cache: false },
      // Run by the pre-commit hook; fallow scores complexity from the coverage map.
      "fallow:audit": {
        command: "vp exec fallow audit --base origin/trunk --quiet",
        dependsOn: ["test:coverage"],
        cache: false,
      },
      // Everything CI checks, fail-fast. Build first: lint reads siblings'
      // `dist/`. `check:dist` and `pnpm audit` need the network.
      ci: {
        command: [
          "vp run build",
          "vp check",
          "vp run docs",
          "vp run check:dist",
          "vp run check:dist -- --effect catalog",
          "vp run check",
          "vp run -r test:unit",
          "pnpm audit --audit-level high",
          "vp run --filter @thomasfosterau/effect-auth-alchemy-cloudflare --filter @thomasfosterau/effect-auth-alchemy-postgres test:alchemy",
        ].join(" && "),
        cache: false,
      },
      // One Istanbul map over every package's suite, for `fallow audit`. One
      // vitest process runs them all, so each package's `build` is listed
      // explicitly (suites import siblings through `dist/`).
      "test:coverage": {
        command:
          "vp test run --coverage --exclude '**/node_modules/**' --exclude '**/dist/**' --exclude 'packages/alchemy-*/src/AuthSchema.test.ts' --exclude packages/alchemy-postgres/src/Postgres.test.ts",
        dependsOn: [
          "@thomasfosterau/effect-auth#build",
          "@thomasfosterau/effect-auth-alchemy-cloudflare#build",
          "@thomasfosterau/effect-auth-alchemy-postgres#build",
          "@thomasfosterau/effect-auth-argon2#build",
          "@thomasfosterau/effect-auth-better-auth#build",
          "@thomasfosterau/effect-auth-drizzle#build",
          "@thomasfosterau/effect-auth-svelte#build",
          "@thomasfosterau/effect-auth-sveltekit#build",
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
      include: ["packages/*/src/**/*.{ts,svelte}"],
      exclude: ["**/*.d.ts", "**/*.test.ts", "**/testing/**"],
    },
  },
});
