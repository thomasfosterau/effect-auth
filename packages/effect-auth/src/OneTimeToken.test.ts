import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, DateTime, Effect, Layer, MutableHashMap, Result } from "effect";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import { SecureRandom } from "effect/crypto";
import { Hooks } from "./Hooks.ts";
import {
  make as makeOneTimeTokenService,
  OneTimeTokenService,
  OneTimeTokenStore,
  redeemOneTimeTokenForSession,
  type OneTimeTokenRecord,
} from "./OneTimeToken.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { hashToken } from "./TokenHash.ts";
import type * as Types from "./Types.ts";
import { UserStore } from "./UserStore.ts";

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

          expect(P.isString(rawToken)).toBe(true);
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

describe("redeemOneTimeTokenForSession", () => {
  const users = MutableHashMap.empty<string, Types.User>();
  const sessions = MutableHashMap.empty<string, Types.Session>();

  const services = Layer.mergeAll(
    OneTimeTokenService.layer(),
    SessionService.layer({ sessionExpiresIn: { activePeriod: 86_400_000, idlePeriod: 3_600_000 } }),
  ).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        Layer.succeed(OneTimeTokenStore)(oneTimeTokenStore),
        Layer.succeed(SessionStore)({
          create: (session) =>
            Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
          get: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, id))),
          update: (session) =>
            Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
          delete: (id) => Effect.sync(() => void MutableHashMap.remove(sessions, id)),
          deleteByUserId: () => Effect.void,
          listByUserId: () => Effect.succeed([]),
        }),
        Layer.succeed(UserStore)({
          get: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, id))),
        }),
        Hooks.Default,
      ),
    ),
  );

  beforeEach(() => {
    MutableHashMap.clear(oneTimeTokens);
    MutableHashMap.clear(users);
    MutableHashMap.clear(sessions);
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(users, "u-1", { id: "u-1", createdAt: now, updatedAt: now, attributes: {} });
  });

  it("mints a session for a token whose user exists", async () => {
    const subject = await Effect.runPromise(
      Effect.gen(function* () {
        const rawToken = yield* (yield* OneTimeTokenService).generate("u-1");
        return (yield* redeemOneTimeTokenForSession(rawToken)).subject;
      }).pipe(Effect.provide(services)),
    );
    expect(subject).toBe("u-1");
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("refuses a token whose user was deleted after issue, as an unknown token", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const rawToken = yield* (yield* OneTimeTokenService).generate("u-1");
        MutableHashMap.remove(users, "u-1");
        return yield* Effect.result(redeemOneTimeTokenForSession(rawToken));
      }).pipe(Effect.provide(services)),
    );
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OneTimeTokenError");
    expect(result.failure.message).toBe("Invalid or expired token");
    expect(MutableHashMap.size(sessions)).toBe(0);
    // The token was consumed: a recreated user cannot be signed in with it.
    expect(MutableHashMap.size(oneTimeTokens)).toBe(0);
  });
});
