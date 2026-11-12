/**
 * Ready-made service layers over the in-memory stores, so a test provides
 * `SessionService` or `ApiKeyService` in one line instead of assembling the
 * stores, hooks and config itself. Each layer starts from fresh state on every
 * build, and resolves its dependencies at construction (service methods carry
 * `R = never`).
 *
 * @module testing
 */
import { Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import { type ApiKey, type ApiKeyConfig, ApiKeyService, ApiKeyStore } from "../ApiKey.ts";
import { Hooks } from "../Hooks.ts";
import { layerMemoryKeyValueStore, RateLimitStoreKV } from "../KeyValueStores.ts";
import { RateLimiter, type RateLimitStore } from "../RateLimit.ts";
import { SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";
import {
  memoryApiKeyStore,
  memorySessionStore,
  memoryUserStore,
  memoryUserTable,
} from "./MemoryStores.ts";

/**
 * The {@link sessionServiceLayer} default: a session lives at most 24 hours
 * (`activePeriod`) and is rejected after 1 hour without activity
 * (`idlePeriod`); the refresh write is not throttled (`updateAge` unset).
 *
 * @since 0.1.0
 * @category constants
 */
export const defaultSessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 24 * 60 * 60 * 1000, idlePeriod: 60 * 60 * 1000 },
};

/**
 * Options for {@link sessionServiceLayer}.
 *
 * @since 0.1.0
 * @category models
 */
export interface SessionServiceLayerOptions {
  /** The users the layer's `UserStore` starts with, so `createSession` and `validateSession` find them. */
  readonly users: Iterable<Types.User>;
  /** Defaults to {@link defaultSessionConfig}. */
  readonly config?: Types.SessionConfig | undefined;
}

/**
 * `SessionService` over a `UserStore` seeded with `users`, an empty
 * `SessionStore` and `Hooks.Default` (no plugins). The `UserStore` and
 * `SessionStore` are provided too, so a test can read the stored sessions.
 * `config` defaults to {@link defaultSessionConfig}. Each build starts with
 * no sessions.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const ada = Testing.fixtureUser({ name: "Ada" })
 *
 * const program = Effect.gen(function* () {
 *   const sessions = yield* Auth.SessionService
 *   const created = yield* sessions.createSession(ada.id)
 *   const valid = yield* sessions.validateSession(created.token)
 *   assert.equal(valid.user.id, ada.id)
 *
 *   yield* sessions.invalidateSession(created.token)
 *   const revoked = yield* Effect.flip(sessions.validateSession(created.token))
 *   assert.equal(revoked._tag, "SessionNotFoundError")
 * })
 *
 * await Effect.runPromise(
 *   program.pipe(Effect.provide(Testing.sessionServiceLayer({ users: [ada] }))),
 * )
 * ```
 *
 * @since 0.1.0
 * @category layers
 */
export const sessionServiceLayer = (
  options: SessionServiceLayerOptions,
): Layer.Layer<SessionService | SessionStore | UserStore> => {
  const stores = Layer.unwrap(
    Effect.sync(() => {
      const table = memoryUserTable();
      Arr.forEach(Arr.fromIterable(options.users), (user) => {
        MutableHashMap.set(table.users, user.id, user);
      });
      return Layer.mergeAll(
        Layer.succeed(UserStore, memoryUserStore(table)),
        Layer.succeed(SessionStore, memorySessionStore()),
        Hooks.Default,
      );
    }),
  );
  return SessionService.layer(options.config ?? defaultSessionConfig).pipe(
    Layer.provideMerge(stores),
  );
};

/**
 * Options for {@link apiKeyServiceLayer}.
 *
 * @since 0.1.0
 * @category models
 */
export interface ApiKeyServiceLayerOptions {
  /** Records the layer's `ApiKeyStore` starts with (their `keyHash` is `hashApiKey` of the plaintext). */
  readonly keys?: Iterable<ApiKey> | undefined;
  /** The service's own config; the service defaults apply when omitted. */
  readonly config?: ApiKeyConfig | undefined;
}

/**
 * `ApiKeyService` over an `ApiKeyStore` seeded with `keys` (none by default)
 * and an in-memory `RateLimiter`, so `verifyWithRateLimit` works. The
 * `ApiKeyStore` and `RateLimitStore` are provided too. `config` is
 * `ApiKeyService.layer`'s own, with its defaults (prefix `ak_`, 32 random
 * bytes, ten keys per user, no expiry). Each build starts from fresh state.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const program = Effect.gen(function* () {
 *   const apiKeys = yield* Auth.ApiKeyService
 *   const created = yield* apiKeys.create("user-1", { name: "CI" })
 *   assert.equal((yield* apiKeys.verify(created.key)).valid, true)
 *
 *   yield* apiKeys.delete("user-1", created.apiKey.id)
 *   assert.equal((yield* apiKeys.verify(created.key)).valid, false)
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(Testing.apiKeyServiceLayer())))
 * ```
 *
 * @since 0.1.0
 * @category layers
 */
export const apiKeyServiceLayer = (
  options: ApiKeyServiceLayerOptions = {},
): Layer.Layer<ApiKeyService | ApiKeyStore | RateLimitStore> => {
  const store = Layer.unwrap(
    Effect.sync(() => {
      const keys = MutableHashMap.empty<string, ApiKey>();
      Arr.forEach(Arr.fromIterable(options.keys ?? []), (key) => {
        MutableHashMap.set(keys, key.id, key);
      });
      return Layer.succeed(ApiKeyStore, memoryApiKeyStore(keys));
    }),
  );
  const rateLimits = RateLimiter.layer().pipe(
    Layer.provideMerge(RateLimitStoreKV),
    Layer.provide(layerMemoryKeyValueStore),
  );
  return ApiKeyService.layer(options.config).pipe(
    Layer.provideMerge(Layer.merge(store, rateLimits)),
  );
};
