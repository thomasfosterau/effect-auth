import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import {
  ApiKeyStore,
  hashApiKey,
  makeApiKeyService,
  type ApiKey,
  type ApiKeyConfig,
  type ApiKeyServiceShape,
  type ApiKeyVerifyResult,
} from "./ApiKey.js";
import { makeRateLimiter, type RateLimitEntry, RateLimiter, RateLimitStore } from "./RateLimit.js";

const apiKeys = new Map<string, ApiKey>();
const rateLimitEntries = new Map<string, RateLimitEntry>();

const apiKeyStore = {
  create: (apiKey: ApiKey) =>
    Effect.sync(() => {
      apiKeys.set(apiKey.id, apiKey);
      return apiKey;
    }),

  get: (id: string) => Effect.sync(() => apiKeys.get(id) ?? null),

  getByHash: (keyHash: string) =>
    Effect.sync(() => {
      for (const apiKey of apiKeys.values()) {
        if (apiKey.keyHash === keyHash) {
          return apiKey;
        }
      }
      return null;
    }),

  update: (apiKey: ApiKey) =>
    Effect.sync(() => {
      apiKeys.set(apiKey.id, apiKey);
      return apiKey;
    }),

  delete: (id: string) =>
    Effect.sync(() => {
      apiKeys.delete(id);
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => [...apiKeys.values()].filter((apiKey) => apiKey.userId === userId)),
};

const rateLimitStore = {
  get: (key: string) => Effect.sync(() => rateLimitEntries.get(key) ?? null),

  set: (key: string, entry: RateLimitEntry, _ttl: number) =>
    Effect.sync(() => {
      rateLimitEntries.set(key, entry);
    }),

  increment: (key: string, _ttl: number) =>
    Effect.sync(() => {
      const entry = rateLimitEntries.get(key);
      const count = (entry?.count ?? 0) + 1;
      if (entry) {
        rateLimitEntries.set(key, { ...entry, count });
      }
      return count;
    }),

  delete: (key: string) =>
    Effect.sync(() => {
      rateLimitEntries.delete(key);
    }),
};

const storeContext = Context.make(ApiKeyStore, apiKeyStore);

const makeRateLimitContext = async () => {
  const rateLimiter = await Effect.runPromise(makeRateLimiter());
  return Context.merge(
    storeContext,
    Context.merge(
      Context.make(RateLimiter, rateLimiter),
      Context.make(RateLimitStore, rateLimitStore),
    ),
  );
};

const runService = <A, E>(
  program: (service: ApiKeyServiceShape) => Effect.Effect<A, E, ApiKeyStore>,
  config?: ApiKeyConfig,
) =>
  Effect.runPromise(
    Effect.provide(
      Effect.gen(function* () {
        const service = yield* makeApiKeyService(config);
        return yield* program(service);
      }),
      storeContext,
    ),
  );

describe("ApiKeyService", () => {
  beforeEach(() => {
    apiKeys.clear();
    rateLimitEntries.clear();
  });

  it("should create and verify an API key (happy path)", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const created = yield* service.create("user-1", {
          name: "CI key",
          metadata: { env: "test" },
        });
        const verified = yield* service.verify(created.key);
        return { created, verified };
      }),
    );

    expect(result.created.key.startsWith("ak_")).toBe(true);
    expect(result.created.apiKey.name).toBe("CI key");
    expect(result.created.apiKey.prefix).toBe("ak_");
    expect(result.created.apiKey.start).toHaveLength(6);
    expect(result.created.key).toContain(result.created.apiKey.start);
    expect(result.created.apiKey.metadata).toEqual({ env: "test" });

    // Only the sha256 digest is stored, never the plaintext
    expect(result.created.apiKey.keyHash).toBe(hashApiKey(result.created.key));
    expect(result.created.apiKey.keyHash).not.toContain(result.created.key);

    expect(result.verified.valid).toBe(true);
    expect(result.verified.apiKey?.id).toBe(result.created.apiKey.id);
    expect(result.verified.apiKey?.lastUsedAt).toBeDefined();
  });

  it("should reject unknown keys", async () => {
    const result = await runService((service) => service.verify("ak_does-not-exist"));
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid API key");
  });

  it("should honor a custom prefix", async () => {
    const result = await runService((service) => service.create("user-1", { prefix: "myapp_" }));
    expect(result.key.startsWith("myapp_")).toBe(true);
    expect(result.apiKey.prefix).toBe("myapp_");
  });

  it("should check permission subsets", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { key } = yield* service.create("user-1", {
          permissions: { posts: ["read", "write"] },
        });

        const subset = yield* service.verify(key, { posts: ["read"] });
        const missingAction = yield* service.verify(key, { posts: ["delete"] });
        const missingResource = yield* service.verify(key, { users: ["read"] });
        const superset = yield* service.verify(key, { posts: ["read", "write", "delete"] });

        return { subset, missingAction, missingResource, superset };
      }),
    );

    expect(result.subset.valid).toBe(true);
    expect(result.missingAction.valid).toBe(false);
    expect(result.missingAction.error).toBe("API key is missing required permissions");
    expect(result.missingResource.valid).toBe(false);
    expect(result.superset.valid).toBe(false);
  });

  it("should reject required permissions when the key has none", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { key } = yield* service.create("user-1");
        return yield* service.verify(key, { posts: ["read"] });
      }),
    );
    expect(result.valid).toBe(false);
  });

  it("should reject expired keys", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { key } = yield* service.create("user-1", { expiresIn: -1000 });
        return yield* service.verify(key);
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBe("API key has expired");
  });

  it("should decrement remaining uses to exhaustion", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { key } = yield* service.create("user-1", { remaining: 2 });
        const first = yield* service.verify(key);
        const second = yield* service.verify(key);
        const third = yield* service.verify(key);
        return { first, second, third };
      }),
    );

    expect(result.first.valid).toBe(true);
    expect(result.first.apiKey?.remaining).toBe(1);
    expect(result.second.valid).toBe(true);
    expect(result.second.apiKey?.remaining).toBe(0);
    expect(result.third.valid).toBe(false);
    expect(result.third.error).toBe("API key has no remaining uses");
  });

  it("should enforce maxKeysPerUser", async () => {
    const result = await runService(
      (service) =>
        Effect.gen(function* () {
          yield* service.create("user-1");
          yield* service.create("user-1");
          const third = yield* Effect.result(service.create("user-1"));
          // Other users are unaffected
          const otherUser = yield* Effect.result(service.create("user-2"));
          return { third, otherUser };
        }),
      { maxKeysPerUser: 2 },
    );

    expect(result.third._tag).toBe("Failure");
    if (result.third._tag === "Failure") {
      expect(result.third.failure._tag).toBe("ApiKeyError");
    }
    expect(result.otherUser._tag).toBe("Success");
  });

  it("should reject disabled keys", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { key, apiKey } = yield* service.create("user-1");
        yield* service.update("user-1", apiKey.id, { enabled: false });
        const disabled = yield* service.verify(key);
        yield* service.update("user-1", apiKey.id, { enabled: true });
        const reEnabled = yield* service.verify(key);
        return { disabled, reEnabled };
      }),
    );

    expect(result.disabled.valid).toBe(false);
    expect(result.disabled.error).toBe("API key is disabled");
    expect(result.reEnabled.valid).toBe(true);
  });

  it("should scope update and delete to the owning user", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { apiKey } = yield* service.create("user-1");

        const foreignUpdate = yield* Effect.result(
          service.update("user-2", apiKey.id, { name: "stolen" }),
        );
        const foreignDelete = yield* Effect.result(service.delete("user-2", apiKey.id));
        const ownedUpdate = yield* service.update("user-1", apiKey.id, { name: "renamed" });
        yield* service.delete("user-1", apiKey.id);
        const afterDelete = yield* service.list("user-1");

        return { foreignUpdate, foreignDelete, ownedUpdate, afterDelete };
      }),
    );

    expect(result.foreignUpdate._tag).toBe("Failure");
    if (result.foreignUpdate._tag === "Failure") {
      expect(result.foreignUpdate.failure._tag).toBe("ApiKeyError");
    }
    expect(result.foreignDelete._tag).toBe("Failure");
    expect(result.ownedUpdate.name).toBe("renamed");
    expect(result.afterDelete).toHaveLength(0);
  });

  it("should get and list keys", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        const { apiKey } = yield* service.create("user-1", { name: "a" });
        yield* service.create("user-1", { name: "b" });
        yield* service.create("user-2", { name: "c" });

        const fetched = yield* service.get(apiKey.id);
        const listed = yield* service.list("user-1");
        const missing = yield* Effect.result(service.get("nope"));

        return { fetched, listed, missing };
      }),
    );

    expect(result.fetched.name).toBe("a");
    expect(result.listed).toHaveLength(2);
    expect(result.missing._tag).toBe("Failure");
  });

  it("should delete all expired keys for a user", async () => {
    const result = await runService((service) =>
      Effect.gen(function* () {
        yield* service.create("user-1", { expiresIn: -1000 });
        yield* service.create("user-1", { expiresIn: -5000 });
        yield* service.create("user-1", { expiresIn: 60_000 });
        yield* service.create("user-1"); // never expires

        const deleted = yield* service.deleteAllExpired("user-1");
        const remaining = yield* service.list("user-1");
        return { deleted, remaining };
      }),
    );

    expect(result.deleted).toBe(2);
    expect(result.remaining).toHaveLength(2);
  });

  it("should enforce per-key rate limits in verifyWithRateLimit", async () => {
    const testContext = await makeRateLimitContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeApiKeyService();
          const { key } = yield* service.create("user-1", {
            rateLimit: { maxRequests: 2, windowMs: 60_000 },
          });

          const first = yield* service.verifyWithRateLimit(key);
          const second = yield* service.verifyWithRateLimit(key);
          const third = yield* service.verifyWithRateLimit(key);
          return { first, second, third };
        }),
        testContext,
      ),
    );

    expect(result.first.valid).toBe(true);
    expect(result.second.valid).toBe(true);
    expect(result.third.valid).toBe(false);
    expect(result.third.error).toBe("Rate limit exceeded");
  });

  it("should not rate limit keys without a rateLimit config", async () => {
    const testContext = await makeRateLimitContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeApiKeyService();
          const { key } = yield* service.create("user-1");
          const outcomes: ApiKeyVerifyResult[] = [];
          for (let i = 0; i < 5; i++) {
            outcomes.push(yield* service.verifyWithRateLimit(key));
          }
          return outcomes;
        }),
        testContext,
      ),
    );

    expect(result.every((outcome) => outcome.valid)).toBe(true);
    expect(rateLimitEntries.size).toBe(0);
  });
});
