import { describe, it, expect } from "vite-plus/test";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as MutableHashMap from "effect/MutableHashMap";
import * as Order from "effect/Order";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { TestClock } from "effect/testing";
import { KeyValueStore } from "effect/persistence";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  layerKVSingleProcess,
  OAuthStateStoreKV,
  ChallengeStoreKV,
  RateLimitStoreKV,
  EmailVerificationStoreKV,
  PasswordResetStoreKV,
  MagicLinkStoreKV,
  EmailOtpStoreKV,
  PendingMultiFactorStoreKV,
  GoogleOneTapNonceStoreKV,
  KeyValueStoreKeys,
  KeyValueStoreTake,
  layerMemoryKeyValueStore,
  purgeExpiredKV,
  purgeExpiredKVWith,
  type PurgeExpiredKVResult,
} from "./KeyValueStores.ts";
import { OAuthStateStore, type OAuthState } from "./oauth/OAuth.ts";
import { ChallengeStore, type WebAuthnChallenge } from "./multifactor/WebAuthn.ts";
import { RateLimitStore, type RateLimitEntry } from "./RateLimit.ts";
import {
  EmailVerificationStore,
  type EmailVerification as EmailVerificationRecord,
} from "./email/EmailVerification.ts";
import * as EmailVerification from "./email/EmailVerification.ts";
import { PasswordResetStore, type PasswordResetToken } from "./password/PasswordReset.ts";
import { MagicLinkStore, type MagicLinkToken } from "./MagicLink.ts";
import { EmailOtpStore, type EmailOtpRecord } from "./email/EmailOtp.ts";
import { PendingMultiFactorStore, type PendingMultiFactor } from "./multifactor/MultiFactor.ts";
import { Hooks } from "./Hooks.ts";
import { GoogleOneTapNonceStore } from "./GoogleOneTap.ts";
import * as Errors from "./Errors.ts";

/** Fresh in-memory KV per invocation so tests are isolated. */
const testLayer = () => layerKVSingleProcess.pipe(Layer.provide(KeyValueStore.layerMemory));

const run = <A, E>(
  effect: Effect.Effect<
    A,
    E,
    | OAuthStateStore
    | ChallengeStore
    | RateLimitStore
    | EmailVerificationStore
    | PasswordResetStore
    | MagicLinkStore
    | EmailOtpStore
    | PendingMultiFactorStore
  >,
): Promise<A> => Effect.runPromise(effect.pipe(Effect.provide(testLayer())));

/** A rate-limit entry as `RateLimitStore.set` takes it. */
const limit = (key: string, resetAt: number, blockedUntil?: number): RateLimitEntry => ({
  key,
  count: 3,
  resetAt,
  ...(blockedUntil !== undefined && { blockedUntil }),
});

describe("KeyValueStores", () => {
  it("exports individual layers", () => {
    expect(OAuthStateStoreKV).toBeDefined();
    expect(ChallengeStoreKV).toBeDefined();
    expect(RateLimitStoreKV).toBeDefined();
    expect(EmailVerificationStoreKV).toBeDefined();
    expect(PasswordResetStoreKV).toBeDefined();
    expect(MagicLinkStoreKV).toBeDefined();
    expect(EmailOtpStoreKV).toBeDefined();
    expect(PendingMultiFactorStoreKV).toBeDefined();
  });

  describe("a failing backend", () => {
    const backendError = new KeyValueStore.KeyValueStoreError({ message: "down", method: "get" });
    const failing = KeyValueStore.makeStringOnly({
      get: () => Effect.fail(backendError),
      set: () => Effect.void,
      remove: () => Effect.void,
      clear: Effect.void,
      size: Effect.succeed(0),
      keys: Effect.succeed([]),
    });
    const failingLayer = layerKVSingleProcess.pipe(
      Layer.provide(Layer.succeed(KeyValueStore.KeyValueStore, failing)),
    );
    const flip = <A>(
      effect: Effect.Effect<A, Errors.AuthError, Layer.Success<typeof failingLayer>>,
    ) => Effect.runPromise(Effect.flip(effect).pipe(Effect.provide(failingLayer)));

    it("fails a challenge read with an AuthError that keeps the cause", async () => {
      const error = await flip(ChallengeStore.use((store) => store.get(new Uint8Array([1]))));
      expect(error).toBeInstanceOf(Errors.AuthError);
      expect(error.cause).toBe(backendError);
    });

    it("fails a rate-limit read with an AuthError rather than a defect", async () => {
      const error = await flip(RateLimitStore.use((store) => store.get("k")));
      expect(error).toBeInstanceOf(Errors.AuthError);
      expect(error.cause).toBe(backendError);
    });
  });

  describe("OAuthStateStoreKV", () => {
    const state: OAuthState = {
      state: "state-1",
      provider: "google",
      codeVerifier: "verifier",
      returnTo: "/dashboard",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 600_000,
    };

    it("hands a state out once: consume returns it, then null", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* OAuthStateStore;
          yield* store.create(state);
          const consumed = yield* store.consume("state-1");
          const replayed = yield* store.consume("state-1");
          const unknown = yield* store.consume("never-issued");
          return { consumed, replayed, unknown };
        }),
      );
      expect(result.consumed).toEqual(Option.some(state));
      expect(Option.isNone(result.replayed)).toBe(true);
      expect(Option.isNone(result.unknown)).toBe(true);
    });

    it("gives a state to only one of two concurrent consumers", async () => {
      // A backend whose reads suspend, so two unguarded read-then-delete
      // consumes would both read the entry before either removed it.
      const entries = MutableHashMap.empty<string, string>();
      const slowKv = KeyValueStore.makeStringOnly({
        get: (key) =>
          Effect.andThen(
            Effect.yieldNow,
            Effect.sync(() => Option.getOrUndefined(MutableHashMap.get(entries, key))),
          ),
        set: (key, value) => Effect.sync(() => void MutableHashMap.set(entries, key, value)),
        remove: (key) => Effect.sync(() => void MutableHashMap.remove(entries, key)),
        clear: Effect.sync(() => void MutableHashMap.clear(entries)),
        size: Effect.sync(() => MutableHashMap.size(entries)),
        keys: Effect.sync(() => Arr.fromIterable(MutableHashMap.keys(entries))),
      });
      const results = await Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* OAuthStateStore;
          yield* store.create(state);
          return yield* Effect.all(
            Arr.makeBy(4, () => store.consume("state-1")),
            { concurrency: "unbounded" },
          );
        }).pipe(
          Effect.provide(
            OAuthStateStoreKV.pipe(
              Layer.provide(Layer.succeed(KeyValueStore.KeyValueStore)(slowKv)),
            ),
          ),
        ),
      );
      expect(Arr.getSomes(results)).toEqual([state]);
    });
  });

  describe("KeyValueStoreTake", () => {
    const state: OAuthState = {
      state: "state-1",
      provider: "google",
      codeVerifier: "verifier",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 600_000,
    };

    /**
     * One backend shared by two separately built stores, as two processes
     * would share Redis: a read suspends after it reads, so read-then-remove interleaves.
     */
    const sharedBackend = () => {
      const entries = MutableHashMap.empty<string, string>();
      const store = KeyValueStore.makeStringOnly({
        get: (key) =>
          Effect.sync(() => Option.getOrUndefined(MutableHashMap.get(entries, key))).pipe(
            Effect.tap(() => Effect.yieldNow),
          ),
        set: (key, value) => Effect.sync(() => void MutableHashMap.set(entries, key, value)),
        remove: (key) => Effect.sync(() => void MutableHashMap.remove(entries, key)),
        clear: Effect.sync(() => void MutableHashMap.clear(entries)),
        size: Effect.sync(() => MutableHashMap.size(entries)),
        keys: Effect.sync(() => Arr.fromIterable(MutableHashMap.keys(entries))),
      });
      let takes = 0;
      const take = Layer.succeed(KeyValueStoreTake, {
        take: (key) =>
          Effect.sync(() => {
            takes += 1;
            const value = Option.getOrUndefined(MutableHashMap.get(entries, key));
            MutableHashMap.remove(entries, key);
            return value;
          }),
      });
      return {
        entries,
        store: Layer.succeed(KeyValueStore.KeyValueStore)(store),
        take,
        takes: () => takes,
      };
    };

    /** Consume one state from two stores built apart over one backend. */
    const raceTwoInstances = (backend: Layer.Layer<KeyValueStore.KeyValueStore>) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const first = yield* Layer.build(OAuthStateStoreKV.pipe(Layer.provide(backend)));
          const second = yield* Layer.build(OAuthStateStoreKV.pipe(Layer.provide(backend)));
          const a = Context.get(first, OAuthStateStore);
          const b = Context.get(second, OAuthStateStore);
          yield* a.create(state);
          return yield* Effect.all([a.consume("state-1"), b.consume("state-1")], {
            concurrency: "unbounded",
          });
        }).pipe(Effect.scoped),
      );

    it("without it, two instances over one backend can both consume a state", async () => {
      const { store } = sharedBackend();
      const results = await raceTwoInstances(store);
      expect(Arr.getSomes(results)).toEqual([state, state]);
    });

    it("with it, only one of two instances over one backend consumes a state", async () => {
      const backend = sharedBackend();
      const results = await raceTwoInstances(Layer.merge(backend.store, backend.take));
      expect(Arr.getSomes(results)).toEqual([state]);
      expect(backend.takes()).toBe(2);
    });

    it("spends every single-use token through take and cleans its index", async () => {
      const backend = sharedBackend();
      const now = DateTime.toEpochMillis(DateTime.nowUnsafe());
      const result = await Effect.runPromise(
        Effect.gen(function* () {
          const links = yield* MagicLinkStore;
          const resets = yield* PasswordResetStore;
          const verifications = yield* EmailVerificationStore;
          const pending = yield* PendingMultiFactorStore;
          yield* links.create({
            token: "ml",
            email: "a@example.com",
            createdAt: now,
            expiresAt: now + 60_000,
          });
          yield* resets.create({
            token: "pr",
            userId: "u1",
            email: "a@example.com",
            createdAt: now,
            expiresAt: now + 60_000,
          });
          yield* verifications.create({
            token: "ev",
            userId: "u1",
            email: "a@example.com",
            createdAt: now,
            expiresAt: now + 60_000,
          });
          yield* pending.create({
            token: "mf",
            userId: "u1",
            createdAt: now,
            expiresAt: now + 60_000,
          });
          yield* pending.recordFailedAttempt("mf");
          return {
            link: yield* links.consume("ml"),
            reset: yield* resets.consume("pr"),
            verification: yield* verifications.consume("ev"),
            pending: yield* pending.consume("mf"),
            again: yield* links.consume("ml"),
          };
        }).pipe(
          Effect.provide(
            layerKVSingleProcess.pipe(Layer.provide(Layer.merge(backend.store, backend.take))),
          ),
        ),
      );
      expect(Option.getOrUndefined(result.link)?.token).toBe("ml");
      expect(Option.getOrUndefined(result.reset)?.token).toBe("pr");
      expect(Option.getOrUndefined(result.verification)?.token).toBe("ev");
      expect(result.pending).toEqual(
        Option.some({
          token: "mf",
          userId: "u1",
          createdAt: now,
          expiresAt: now + 60_000,
        }),
      );
      expect(Option.isNone(result.again)).toBe(true);
      expect(backend.takes()).toBe(5);
      expect(MutableHashMap.size(backend.entries)).toBe(0);
    });

    it("surfaces a failed take as its AuthError", async () => {
      const backend = sharedBackend();
      const failure = new Errors.AuthError({ message: "GETDEL failed" });
      const error = await Effect.runPromise(
        Effect.flip(OAuthStateStore.use((store) => store.consume("state-1"))).pipe(
          Effect.provide(
            OAuthStateStoreKV.pipe(
              Layer.provide(
                Layer.merge(
                  backend.store,
                  Layer.succeed(KeyValueStoreTake, { take: () => Effect.fail(failure) }),
                ),
              ),
            ),
          ),
        ),
      );
      expect(error).toBe(failure);
    });
  });

  describe("ChallengeStoreKV", () => {
    it("roundtrips challenge bytes", async () => {
      const challenge: WebAuthnChallenge = {
        challenge: new Uint8Array([1, 2, 3, 255, 0, 42]),
        ceremony: "authentication",
        expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
        userId: "user-1",
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* ChallengeStore;
          yield* store.create(challenge);
          const loaded = yield* store.get(challenge.challenge);
          yield* store.delete(challenge.challenge);
          const missing = yield* store.get(challenge.challenge);
          return { loaded, missing };
        }),
      );
      expect(Array.from(Option.getOrUndefined(result.loaded)?.challenge ?? [])).toEqual([
        1, 2, 3, 255, 0, 42,
      ]);
      expect(Option.getOrUndefined(result.loaded)?.userId).toBe("user-1");
      expect(Option.getOrUndefined(result.loaded)?.expiresAt).toBe(challenge.expiresAt);
      expect(Option.isNone(result.missing)).toBe(true);
    });

    it("stores anonymous challenges (no userId)", async () => {
      const challenge: WebAuthnChallenge = {
        challenge: new Uint8Array([9, 9, 9]),
        ceremony: "authentication",
        expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
      };
      const loaded = await run(
        Effect.gen(function* () {
          const store = yield* ChallengeStore;
          yield* store.create(challenge);
          return yield* store.get(challenge.challenge);
        }),
      );
      expect(Option.isNone(loaded)).toBe(false);
      expect(Option.getOrUndefined(loaded)?.userId).toBeUndefined();
      expect(Option.getOrUndefined(loaded)?.ceremony).toBe("authentication");
    });

    it("reads an entry with no known ceremony as missing", async () => {
      // An entry written before ceremonies were recorded, and one with a
      // ceremony the core does not know: neither ceremony may redeem them.
      const expiresAt = DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000;
      const loaded = await Effect.runPromise(
        Effect.gen(function* () {
          const kv = yield* KeyValueStore.KeyValueStore;
          const store = yield* ChallengeStore;
          yield* kv.set(
            "webauthn-challenge:AQID",
            `{"challenge":"AQID","expiresAt":${expiresAt},"userId":"victim"}`,
          );
          yield* kv.set(
            "webauthn-challenge:BAUG",
            `{"challenge":"BAUG","ceremony":"login","expiresAt":${expiresAt}}`,
          );
          return [
            yield* store.get(new Uint8Array([1, 2, 3])),
            yield* store.get(new Uint8Array([4, 5, 6])),
          ];
        }).pipe(
          Effect.provide(Layer.provideMerge(layerKVSingleProcess, KeyValueStore.layerMemory)),
        ),
      );
      expect(loaded.map(Option.isNone)).toEqual([true, true]);
    });
  });

  describe("RateLimitStoreKV", () => {
    it("roundtrips get/set/delete", async () => {
      const entry: RateLimitEntry = {
        key: "login:1.2.3.4",
        count: 3,
        resetAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
        blockedUntil: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 120_000,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* RateLimitStore;
          const before = yield* store.get("login:1.2.3.4");
          yield* store.set("login:1.2.3.4", entry, 60);
          const after = yield* store.get("login:1.2.3.4");
          yield* store.delete("login:1.2.3.4");
          const deleted = yield* store.get("login:1.2.3.4");
          return { before, after, deleted };
        }),
      );
      expect(Option.isNone(result.before)).toBe(true);
      expect(result.after).toEqual(Option.some(entry));
      expect(Option.isNone(result.deleted)).toBe(true);
    });

    it("increments within a window and restarts an expired window", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* RateLimitStore;
          const first = yield* store.increment("otp:me@example.com", 60);
          const second = yield* store.increment("otp:me@example.com", 60);
          const third = yield* store.increment("otp:me@example.com", 60);
          // Force an expired window, next increment starts over at 1.
          yield* store.set(
            "otp:me@example.com",
            { key: "otp:me@example.com", count: 99, resetAt: (yield* Clock.currentTimeMillis) - 1 },
            60,
          );
          const restarted = yield* store.increment("otp:me@example.com", 60);
          return { first, second, third, restarted };
        }),
      );
      expect(result.first).toBe(1);
      expect(result.second).toBe(2);
      expect(result.third).toBe(3);
      expect(result.restarted).toBe(1);
    });
  });

  describe("EmailVerificationStoreKV", () => {
    const verification = (token: string, userId: string): EmailVerificationRecord => ({
      token,
      userId,
      email: `${userId}@example.com`,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 86_400_000,
    });

    it("roundtrips create/get/delete", async () => {
      const record = verification("tok-1", "user-1");
      const result = await run(
        Effect.gen(function* () {
          const store = yield* EmailVerificationStore;
          yield* store.create(record);
          const loaded = yield* store.get("tok-1");
          yield* store.delete("tok-1");
          const deleted = yield* store.get("tok-1");
          return { loaded, deleted };
        }),
      );
      expect(result.loaded).toEqual(Option.some(record));
      expect(Option.isNone(result.deleted)).toBe(true);
    });

    it("deleteByUserId removes only that user's tokens", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* EmailVerificationStore;
          yield* store.create(verification("tok-a", "user-1"));
          yield* store.create(verification("tok-b", "user-1"));
          yield* store.create(verification("tok-c", "user-2"));
          yield* store.deleteByUserId("user-1");
          const a = yield* store.get("tok-a");
          const b = yield* store.get("tok-b");
          const c = yield* store.get("tok-c");
          return { a, b, c };
        }),
      );
      expect(Option.isNone(result.a)).toBe(true);
      expect(Option.isNone(result.b)).toBe(true);
      expect(Option.getOrUndefined(result.c)?.userId).toBe("user-2");
    });
  });

  describe("PasswordResetStoreKV", () => {
    const reset = (token: string, userId: string): PasswordResetToken => ({
      token,
      userId,
      email: `${userId}@example.com`,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 3_600_000,
    });

    it("roundtrips and deletes by user id", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* PasswordResetStore;
          yield* store.create(reset("pr-1", "user-1"));
          yield* store.create(reset("pr-2", "user-1"));
          yield* store.create(reset("pr-3", "user-2"));
          const loaded = yield* store.get("pr-1");
          yield* store.delete("pr-1");
          const afterDelete = yield* store.get("pr-1");
          yield* store.deleteByUserId("user-1");
          const two = yield* store.get("pr-2");
          const three = yield* store.get("pr-3");
          return { loaded, afterDelete, two, three };
        }),
      );
      expect(Option.getOrUndefined(result.loaded)?.token).toBe("pr-1");
      expect(Option.isNone(result.afterDelete)).toBe(true);
      expect(Option.isNone(result.two)).toBe(true);
      expect(Option.getOrUndefined(result.three)?.userId).toBe("user-2");
    });
  });

  describe("MagicLinkStoreKV", () => {
    const link = (token: string, email: string): MagicLinkToken => ({
      token,
      email,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 300_000,
    });

    it("roundtrips and deletes by email", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* MagicLinkStore;
          yield* store.create(link("ml-1", "a@example.com"));
          yield* store.create(link("ml-2", "a@example.com"));
          yield* store.create(link("ml-3", "b@example.com"));
          const loaded = yield* store.get("ml-1");
          yield* store.delete("ml-1");
          const afterDelete = yield* store.get("ml-1");
          yield* store.deleteByEmail("a@example.com");
          const two = yield* store.get("ml-2");
          const three = yield* store.get("ml-3");
          return { loaded, afterDelete, two, three };
        }),
      );
      expect(Option.getOrUndefined(result.loaded)?.email).toBe("a@example.com");
      expect(Option.isNone(result.afterDelete)).toBe(true);
      expect(Option.isNone(result.two)).toBe(true);
      expect(Option.getOrUndefined(result.three)?.email).toBe("b@example.com");
    });

    it("getByEmail returns the newest token for the address", async () => {
      const latest = await run(
        Effect.gen(function* () {
          const store = yield* MagicLinkStore;
          yield* store.create(link("ml-old", "a@example.com"));
          yield* store.create(link("ml-new", "a@example.com"));
          return yield* store.getByEmail("a@example.com");
        }),
      );
      expect(Option.getOrUndefined(latest)?.token).toBe("ml-new");
    });
  });

  describe("EmailOtpStoreKV", () => {
    const record: EmailOtpRecord = {
      email: "otp@example.com",
      otpHash: "hash",
      purpose: "sign-in",
      attempts: 0,
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 300_000,
    };

    it("upserts per email+purpose and increments attempts", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* EmailOtpStore;
          yield* store.upsert(record);
          // Same email, different purpose is a separate record.
          yield* store.upsert({ ...record, purpose: "forget-password", otpHash: "other" });
          const loaded = yield* store.get("otp@example.com", "sign-in");
          const attempts1 = yield* store.incrementAttempts("otp@example.com", "sign-in");
          const attempts2 = yield* store.incrementAttempts("otp@example.com", "sign-in");
          // Replaced by upsert (attempts reset).
          yield* store.upsert({ ...record, otpHash: "new-hash" });
          const replaced = yield* store.get("otp@example.com", "sign-in");
          const other = yield* store.get("otp@example.com", "forget-password");
          yield* store.delete("otp@example.com", "sign-in");
          const deleted = yield* store.get("otp@example.com", "sign-in");
          const missingIncrement = yield* store.incrementAttempts("otp@example.com", "sign-in");
          return { loaded, attempts1, attempts2, replaced, other, deleted, missingIncrement };
        }),
      );
      expect(Option.getOrUndefined(result.loaded)?.otpHash).toBe("hash");
      expect(result.attempts1).toEqual(Option.some(1));
      expect(result.attempts2).toEqual(Option.some(2));
      expect(Option.getOrUndefined(result.replaced)?.otpHash).toBe("new-hash");
      expect(Option.getOrUndefined(result.replaced)?.attempts).toBe(0);
      expect(Option.getOrUndefined(result.other)?.otpHash).toBe("other");
      expect(Option.isNone(result.deleted)).toBe(true);
      // A pair with no code counts nothing.
      expect(Option.isNone(result.missingIncrement)).toBe(true);
    });
  });

  describe("PendingMultiFactorStoreKV", () => {
    it("roundtrips create/get/delete", async () => {
      const pending: PendingMultiFactor = {
        token: "2fa-1",
        userId: "user-1",
        createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
        expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 300_000,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* PendingMultiFactorStore;
          yield* store.create(pending);
          const loaded = yield* store.get("2fa-1");
          yield* store.delete("2fa-1");
          const deleted = yield* store.get("2fa-1");
          return { loaded, deleted };
        }),
      );
      expect(result.loaded).toEqual(Option.some(pending));
      expect(Option.isNone(result.deleted)).toBe(true);
    });
  });

  describe("integration: EmailVerificationService over EmailVerificationStoreKV", () => {
    it("creates, resends and verifies tokens end-to-end", async () => {
      const sent: Array<{ to: string; token: string }> = [];

      const layer = Layer.mergeAll(
        EmailVerificationStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        RateLimitStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        Hooks.Default,
        PlatformCrypto.layer,
      );
      // The flipped verifications leave failure types in the error channel;
      // any unexpected failure should crash the test, so treat them as defects.
      const outcome = await Effect.runPromise(
        Effect.gen(function* () {
          const service = yield* EmailVerification.make({
            sendEmail: (to, token) => Effect.sync(() => void sent.push({ to, token })),
            resendCooldown: 0,
          });
          const first = yield* service.createVerification("user-1", "user-1@example.com");
          // Resend invalidates the first token and issues a new one.
          const second = yield* service.resendVerification("user-1", "user-1@example.com");
          const staleResult = yield* Effect.flip(service.verifyToken(first.token));
          const result = yield* service.verifyToken(second.token);
          // One-time use: verifying again fails.
          const reused = yield* Effect.flip(service.verifyToken(second.token));
          return { staleResult, result, reused };
        }).pipe(Effect.provide(layer), Effect.orDie),
      );

      expect(sent).toHaveLength(2);
      expect(outcome.staleResult._tag).toBe("EmailVerificationError");
      expect(outcome.result).toEqual({
        userId: "user-1",
        email: "user-1@example.com",
        verified: true,
      });
      expect(outcome.reused._tag).toBe("EmailVerificationError");
    });

    it("holds a resend back for the default 60 s from the newest token, then sends", async () => {
      const sent: Array<string> = [];
      const layer = Layer.mergeAll(
        EmailVerificationStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        RateLimitStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        Hooks.Default,
        PlatformCrypto.layer,
        TestClock.layer(),
      );
      const outcome = await Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* EmailVerification.EmailVerificationStore;
          const service = yield* EmailVerification.make({
            sendEmail: (_to, token) => Effect.sync(() => void sent.push(token)),
          });
          yield* TestClock.setTime(1_000_000);
          // An older token for the user, then the sign-up's.
          yield* store.create({
            token: "older",
            userId: "user-1",
            email: "user-1@example.com",
            createdAt: 900_000,
            expiresAt: 2_000_000,
          });
          const first = yield* service.createVerification("user-1", "user-1@example.com");
          const latest = yield* store.getLatestByUserId("user-1");
          yield* TestClock.adjust("59 seconds");
          const early = yield* Effect.flip(
            service.resendVerification("user-1", "user-1@example.com"),
          );
          const stillValid = yield* service.peekToken(first.token);
          yield* TestClock.adjust("1 second");
          const later = yield* service.resendVerification("user-1", "user-1@example.com");
          return { latest, early, stillValid, later, none: yield* store.getLatestByUserId("x") };
        }).pipe(Effect.provide(layer), Effect.orDie),
      );

      expect(Option.getOrUndefined(outcome.latest)?.createdAt).toBe(1_000_000);
      expect(outcome.early._tag).toBe("ResendTooSoonError");
      expect(outcome.stillValid.userId).toBe("user-1");
      expect(sent).toEqual([expect.any(String), outcome.later.token]);
      expect(Option.isNone(outcome.none)).toBe(true);
    });
  });

  describe("purgeExpiredKV", () => {
    const now = 1_000_000;
    const nothingPurged: PurgeExpiredKVResult = {
      oauthStates: 0,
      webauthnChallenges: 0,
      pendingMultiFactor: 0,
      emailVerifications: 0,
      passwordResets: 0,
      magicLinks: 0,
      emailOtps: 0,
      emailOtpFailures: 0,
      rateLimits: 0,
      googleOneTapNonces: 0,
    };
    const runPurge = <A, E>(
      effect: Effect.Effect<
        A,
        E,
        | MagicLinkStore
        | EmailOtpStore
        | OAuthStateStore
        | RateLimitStore
        | KeyValueStore.KeyValueStore
        | KeyValueStoreKeys
        | TestClock.TestClock
      >,
    ): Promise<A> =>
      Effect.runPromise(
        effect.pipe(
          Effect.provide(
            Layer.merge(
              Layer.provideMerge(
                Layer.mergeAll(
                  MagicLinkStoreKV,
                  EmailOtpStoreKV,
                  OAuthStateStoreKV,
                  RateLimitStoreKV,
                ),
                layerMemoryKeyValueStore,
              ),
              TestClock.layer(),
            ),
          ),
        ),
      );
    const link = (token: string, email: string, expiresAt: number): MagicLinkToken => ({
      token,
      email,
      createdAt: 0,
      expiresAt,
    });
    const otp = (
      email: string,
      purpose: EmailOtpRecord["purpose"],
      expiresAt: number,
    ): EmailOtpRecord => ({
      email,
      otpHash: "hash",
      purpose,
      attempts: 0,
      createdAt: 0,
      expiresAt,
    });

    it("deletes expired magic links and OTPs and keeps live ones", async () => {
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const links = yield* MagicLinkStore;
          const otps = yield* EmailOtpStore;
          yield* links.create(link("old", "a@example.com", now - 1));
          yield* links.create(link("new", "a@example.com", now + 60_000));
          yield* links.create(link("gone", "b@example.com", now - 60_000));
          yield* otps.upsert(otp("a@example.com", "sign-in", now - 1));
          yield* otps.upsert(otp("a@example.com", "forget-password", now + 60_000));
          yield* otps.upsert(otp("c@example.com", "email-verification", now - 60_000));
          const purged = yield* purgeExpiredKV;
          return {
            purged,
            old: yield* links.get("old"),
            fresh: yield* links.get("new"),
            gone: yield* links.get("gone"),
            byEmailA: yield* links.getByEmail("a@example.com"),
            byEmailB: yield* links.getByEmail("b@example.com"),
            signIn: yield* otps.get("a@example.com", "sign-in"),
            reset: yield* otps.get("a@example.com", "forget-password"),
            verify: yield* otps.get("c@example.com", "email-verification"),
            remaining: yield* (yield* KeyValueStoreKeys).list(""),
          };
        }),
      );
      expect(result.purged).toEqual({ ...nothingPurged, magicLinks: 2, emailOtps: 2 });
      expect(Option.isNone(result.old)).toBe(true);
      expect(Option.isNone(result.gone)).toBe(true);
      expect(Option.getOrUndefined(result.fresh)?.token).toBe("new");
      // The purged token left its address's index; the empty index went.
      expect(Option.getOrUndefined(result.byEmailA)?.token).toBe("new");
      expect(Option.isNone(result.byEmailB)).toBe(true);
      expect(Option.isNone(result.signIn)).toBe(true);
      expect(Option.isNone(result.verify)).toBe(true);
      expect(Option.getOrUndefined(result.reset)?.expiresAt).toBe(now + 60_000);
      expect(Arr.sort(result.remaining, Order.String)).toEqual([
        "email-otp:forget-password:a@example.com",
        "magic-link:email:a@example.com",
        "magic-link:token:new",
      ]);
    });

    it("deletes rate-limit entries whose window and block have both passed", async () => {
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const limits = yield* RateLimitStore;
          yield* limits.set("window-over", limit("window-over", now - 1), 0);
          // `RateLimiter` opens a fresh window once `now >= resetAt` and lifts a
          // block once `now >= blockedUntil`, so both edges are spent at `now`.
          yield* limits.set("edges-now", limit("edges-now", now, now), 0);
          yield* limits.set("block-over", limit("block-over", now - 60_000, now - 1), 0);
          yield* limits.set("in-window", limit("in-window", now + 1), 0);
          yield* limits.set("still-blocked", limit("still-blocked", now - 60_000, now + 1), 0);
          const purged = yield* purgeExpiredKV;
          const again = yield* purgeExpiredKV;
          return {
            purged,
            again,
            inWindow: yield* limits.get("in-window"),
            stillBlocked: yield* limits.get("still-blocked"),
            remaining: yield* (yield* KeyValueStoreKeys).list(""),
            // A purged key counts as one never seen: the next hit opens a window.
            restarted: yield* limits.increment("window-over", 60),
          };
        }),
      );
      expect(result.purged).toEqual({ ...nothingPurged, rateLimits: 3 });
      expect(result.again).toEqual({ ...nothingPurged });
      expect(result.inWindow).toEqual(Option.some(limit("in-window", now + 1)));
      expect(result.stillBlocked).toEqual(
        Option.some(limit("still-blocked", now - 60_000, now + 1)),
      );
      expect(Arr.sort(result.remaining, Order.String)).toEqual([
        "rate-limit:in-window",
        "rate-limit:still-blocked",
      ]);
      expect(result.restarted).toBe(1);
    });

    it("keeps a record that expires exactly now, which the services still accept", async () => {
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          yield* (yield* MagicLinkStore).create(link("edge", "a@example.com", now));
          yield* (yield* EmailOtpStore).upsert(otp("a@example.com", "sign-in", now));
          return yield* purgeExpiredKV;
        }),
      );
      expect(result).toEqual({ ...nothingPurged });
    });

    it("leaves keys outside the stores' prefixes alone", async () => {
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const kv = yield* KeyValueStore.KeyValueStore;
          yield* kv.set("app:session", '{"expiresAt":0}');
          const purged = yield* purgeExpiredKV;
          return { purged, kept: yield* kv.get("app:session") };
        }),
      );
      expect(result.purged).toEqual(nothingPurged);
      expect(result.kept).toBeDefined();
    });

    it("deletes every store's expired records, their indexes with them, and keeps live ones", async () => {
      const result = await Effect.runPromise(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const states = yield* OAuthStateStore;
          const challenges = yield* ChallengeStore;
          const pending = yield* PendingMultiFactorStore;
          const verifications = yield* EmailVerificationStore;
          const resets = yield* PasswordResetStore;
          const nonces = yield* GoogleOneTapNonceStore;
          yield* Effect.forEach(
            [
              ["stale", now - 1],
              ["live", now + 60_000],
            ] as const,
            ([id, expiresAt]) =>
              Effect.gen(function* () {
                yield* states.create({
                  state: `state-${id}`,
                  provider: "p",
                  createdAt: 0,
                  expiresAt,
                });
                yield* challenges.create({
                  challenge: new TextEncoder().encode(`challenge-${id}`),
                  ceremony: "registration",
                  userId: "u",
                  expiresAt,
                });
                yield* pending.create({
                  token: `pending-${id}`,
                  userId: "u",
                  createdAt: 0,
                  expiresAt,
                });
                yield* pending.recordFailedAttempt(`pending-${id}`);
                yield* verifications.create({
                  token: `verify-${id}`,
                  userId: "u",
                  email: "a@example.com",
                  createdAt: 0,
                  expiresAt,
                });
                yield* resets.create({
                  token: `reset-${id}`,
                  userId: "u",
                  email: "a@example.com",
                  createdAt: 0,
                  expiresAt,
                });
                yield* nonces.create(`nonce-${id}`, expiresAt);
              }),
            { concurrency: 1, discard: true },
          );
          const purged = yield* purgeExpiredKV;
          const again = yield* purgeExpiredKV;
          const kv = yield* KeyValueStore.KeyValueStore;
          return {
            purged,
            again,
            remaining: Arr.sort(yield* (yield* KeyValueStoreKeys).list(""), Order.String),
            verificationIndex: yield* kv.get("email-verification:user:u"),
            resetIndex: yield* kv.get("password-reset:user:u"),
          };
        }).pipe(
          Effect.provide(
            Layer.merge(
              Layer.provideMerge(
                Layer.merge(layerKVSingleProcess, GoogleOneTapNonceStoreKV),
                layerMemoryKeyValueStore,
              ),
              TestClock.layer(),
            ),
          ),
        ),
      );
      expect(result.purged).toEqual({
        ...nothingPurged,
        oauthStates: 1,
        webauthnChallenges: 1,
        pendingMultiFactor: 1,
        emailVerifications: 1,
        passwordResets: 1,
        googleOneTapNonces: 1,
      });
      expect(result.again).toEqual(nothingPurged);
      // The live record of each of the six stores (a challenge's key is its
      // bytes in base64), and the two user indexes.
      expect(result.remaining.length).toBe(8);
      expect(result.remaining.every((key) => !key.includes("stale"))).toBe(true);
      expect(result.verificationIndex).toBe('["verify-live"]');
      expect(result.resetIndex).toBe('["reset-live"]');
    });

    it("keeps a rate-limit entry until the TTL it was set with has passed", async () => {
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const limits = yield* RateLimitStore;
          yield* limits.set("ttl", limit("ttl", now - 1), 60);
          const within = yield* purgeExpiredKV;
          yield* TestClock.setTime(now + 60_000);
          const after = yield* purgeExpiredKV;
          return { within, after };
        }),
      );
      expect(result.within).toEqual(nothingPurged);
      expect(result.after).toEqual({ ...nothingPurged, rateLimits: 1 });
    });

    it("drops an OTP failure budget once its latest wrong code is older than the retention", async () => {
      const hour = 60 * 60 * 1000;
      const start = 100 * hour;
      const result = await runPurge(
        Effect.gen(function* () {
          yield* TestClock.setTime(start);
          const otps = yield* EmailOtpStore;
          yield* otps.recordFailure("old@example.com", "sign-in", start - 26 * hour);
          yield* otps.recordFailure("recent@example.com", "sign-in", start - 2 * hour);
          const byDefault = yield* purgeExpiredKV;
          const shorter = yield* purgeExpiredKVWith({ otpFailureRetention: "1 hour" });
          const refused = yield* Effect.flip(purgeExpiredKVWith({ otpFailureRetention: -1 }));
          return {
            byDefault,
            shorter,
            refused: refused._tag,
            recent: yield* otps.getFailures("recent@example.com", "sign-in"),
          };
        }),
      );
      expect(result.byDefault).toEqual({ ...nothingPurged, emailOtpFailures: 1 });
      expect(result.shorter).toEqual({ ...nothingPurged, emailOtpFailures: 1 });
      expect(result.refused).toBe("AuthError");
      expect(Option.isNone(result.recent)).toBe(true);
    });

    it("skips a listed key that is gone by the time it is read", async () => {
      const purged = await Effect.runPromise(
        purgeExpiredKV.pipe(
          Effect.provide(
            Layer.merge(
              KeyValueStore.layerMemory,
              Layer.succeed(KeyValueStoreKeys, {
                list: (prefix) => Effect.succeed([`${prefix}missing`]),
              }),
            ),
          ),
        ),
      );
      expect(purged).toEqual({ ...nothingPurged });
    });

    it("surfaces a listing failure as the AuthError it is", async () => {
      const failure = await Effect.runPromise(
        Effect.flip(purgeExpiredKV).pipe(
          Effect.provide(
            Layer.merge(
              KeyValueStore.layerMemory,
              Layer.succeed(KeyValueStoreKeys, {
                list: () => Effect.fail(new Errors.AuthError({ message: "list failed" })),
              }),
            ),
          ),
        ),
      );
      expect(failure.message).toBe("list failed");
    });

    it("reads the store's own keys when no KeyValueStoreKeys is provided", async () => {
      const result = await Effect.runPromise(
        Effect.gen(function* () {
          yield* TestClock.setTime(now);
          const links = yield* MagicLinkStore;
          const otps = yield* EmailOtpStore;
          yield* links.create(link("old", "a@example.com", now - 1));
          yield* links.create(link("new", "a@example.com", now + 60_000));
          yield* otps.upsert(otp("a@example.com", "sign-in", now - 1));
          const purged = yield* purgeExpiredKV;
          return {
            purged,
            old: yield* links.get("old"),
            fresh: yield* links.get("new"),
            remaining: yield* (yield* KeyValueStore.KeyValueStore).keys,
          };
        }).pipe(
          Effect.provide(
            Layer.merge(
              Layer.provideMerge(
                Layer.merge(MagicLinkStoreKV, EmailOtpStoreKV),
                // Effect's own in-memory store: no listing seam beside it.
                KeyValueStore.layerMemory,
              ),
              TestClock.layer(),
            ),
          ),
        ),
      );
      expect(result.purged).toEqual({ ...nothingPurged, magicLinks: 1, emailOtps: 1 });
      expect(Option.isNone(result.old)).toBe(true);
      expect(Option.getOrUndefined(result.fresh)?.token).toBe("new");
      expect(Arr.sort(result.remaining, Order.String)).toEqual([
        "magic-link:email:a@example.com",
        "magic-link:token:new",
      ]);
    });

    it("surfaces a failing store keys read as an AuthError", async () => {
      const failing = KeyValueStore.makeStringOnly({
        get: () => Effect.undefined,
        set: () => Effect.void,
        remove: () => Effect.void,
        clear: Effect.void,
        size: Effect.succeed(0),
        keys: Effect.fail(
          new KeyValueStore.KeyValueStoreError({ message: "keys failed", method: "keys" }),
        ),
      });
      const failure = await Effect.runPromise(
        Effect.flip(purgeExpiredKV).pipe(
          Effect.provideService(KeyValueStore.KeyValueStore, failing),
        ),
      );
      expect(failure).toBeInstanceOf(Errors.AuthError);
      expect(failure.message).toBe("KeyValueStore keys failed");
    });
  });
});
