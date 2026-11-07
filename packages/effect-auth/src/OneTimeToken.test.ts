import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, DateTime, Effect, MutableHashMap, Option, Predicate, Result } from "effect";
import { SecureRandom } from "effect/crypto";
import {
  make as makeOneTimeTokenService,
  OneTimeTokenStore,
  type OneTimeTokenRecord,
} from "./OneTimeToken.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { hashToken } from "./TokenHash.ts";

const oneTimeTokens = MutableHashMap.empty<string, OneTimeTokenRecord>();

const oneTimeTokenStore = {
  create: (record: OneTimeTokenRecord) =>
    Effect.sync(() => {
      MutableHashMap.set(oneTimeTokens, record.token, record);
      return record;
    }),

  get: (token: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(oneTimeTokens, token))),

  delete: (token: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(oneTimeTokens, token);
    }),
};

const makeTestContext = () =>
  Context.merge(
    Context.make(OneTimeTokenStore, oneTimeTokenStore),
    Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
  );

describe("OneTimeTokenService", () => {
  beforeEach(() => {
    MutableHashMap.clear(oneTimeTokens);
  });

  it("should generate and verify a token (happy path)", async () => {
    const testContext = makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});

          const rawToken = yield* service.generate("user-1", {
            metadata: { purpose: "invite" },
          });

          expect(Predicate.isString(rawToken)).toBe(true);
          expect(rawToken.length).toBeGreaterThan(0);

          const result = yield* service.verify(rawToken);
          expect(result.subject).toBe("user-1");
          expect(result.metadata).toEqual({ purpose: "invite" });
        }),
        testContext,
      ),
    );

    // Token is consumed — store should be empty.
    expect(MutableHashMap.size(oneTimeTokens)).toBe(0);
  });

  it("should generate without metadata", async () => {
    const testContext = makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});
          const rawToken = yield* service.generate("user-2");
          const result = yield* service.verify(rawToken);
          expect(result.subject).toBe("user-2");
          expect(result.metadata).toBeUndefined();
        }),
        testContext,
      ),
    );
  });

  it("should store only the hash, not the raw token", async () => {
    const testContext = makeTestContext();
    let rawToken = "";

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});
          rawToken = yield* service.generate("user-hash-check");
        }),
        testContext,
      ),
    );

    const stored = Array.from(MutableHashMap.values(oneTimeTokens))[0];
    expect(stored?.token).toBe(hashToken(rawToken));
    expect(stored?.token).not.toBe(rawToken);
  });

  it("should reject reuse of a verified token", async () => {
    const testContext = makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});
          const rawToken = yield* service.generate("user-reuse");

          // First use succeeds.
          yield* service.verify(rawToken);

          // Second use should fail.
          return yield* Effect.result(service.verify(rawToken));
        }),
        testContext,
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OneTimeTokenError");
    expect(result.failure.message).toBe("Invalid or expired token");
  });

  it("should reject an expired token", async () => {
    const testContext = makeTestContext();

    // Seed a pre-expired record directly into the store.
    const expiredHash = hashToken("expired-raw-token");
    MutableHashMap.set(oneTimeTokens, expiredHash, {
      token: expiredHash,
      subject: "user-expired",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 20_000,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 10_000,
    });

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});
          return yield* Effect.result(service.verify("expired-raw-token"));
        }),
        testContext,
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OneTimeTokenError");
    expect(result.failure.message).toBe("Invalid or expired token");
    // Expired token is consumed (deleted) on lookup — store must be empty.
    expect(MutableHashMap.size(oneTimeTokens)).toBe(0);
  });

  it("should reject a completely unknown token (anti-enumeration)", async () => {
    const testContext = makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({});
          return yield* Effect.result(service.verify("token-that-was-never-issued"));
        }),
        testContext,
      ),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OneTimeTokenError");
    // Same generic message for all failure cases — no hint of why it failed.
    expect(result.failure.message).toBe("Invalid or expired token");
  });

  it("should respect custom expiresIn config", async () => {
    const testContext = makeTestContext();

    // 1-second TTL — seed via generate so the record is in the store.

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({ expiresIn: 1_000 });
          const rawToken = yield* service.generate("user-ttl");
          // Check that the stored record has a short TTL.
          const hash = hashToken(rawToken);
          const stored = Option.getOrUndefined(MutableHashMap.get(oneTimeTokens, hash));
          assert(stored !== undefined, "the token is stored");
          expect(stored.expiresAt - stored.createdAt).toBe(1_000);
        }),
        testContext,
      ),
    );
  });

  it("should allow per-token expiresIn override", async () => {
    const testContext = makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* makeOneTimeTokenService({ expiresIn: 60_000 });
          const rawToken = yield* service.generate("user-override", { expiresIn: 5_000 });
          const hash = hashToken(rawToken);
          const stored = Option.getOrUndefined(MutableHashMap.get(oneTimeTokens, hash));
          assert(stored !== undefined, "the token is stored");
          expect(stored.expiresAt - stored.createdAt).toBe(5_000);
        }),
        testContext,
      ),
    );
  });
});
