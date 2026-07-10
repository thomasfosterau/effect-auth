import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { KeyValueStore } from "effect/unstable/persistence";
import * as PlatformCrypto from "./PlatformCrypto.js";
import {
  layerKV,
  OAuthStateStoreKV,
  ChallengeStoreKV,
  RateLimitStoreKV,
  EmailVerificationStoreKV,
  PasswordResetStoreKV,
  MagicLinkStoreKV,
  EmailOTPStoreKV,
  PendingTwoFactorStoreKV,
} from "./KeyValueStores.js";
import { OAuthStateStore, type OAuthState } from "./oauth/OAuth.js";
import { ChallengeStore, type WebAuthnChallenge } from "./WebAuthn.js";
import { RateLimitStore, type RateLimitEntry } from "./RateLimit.js";
import {
  EmailVerificationStore,
  makeEmailVerificationService,
  type EmailVerification,
} from "./email/EmailVerification.js";
import { PasswordResetStore, type PasswordResetToken } from "./password/PasswordReset.js";
import { MagicLinkStore, type MagicLinkToken } from "./MagicLink.js";
import { EmailOTPStore, type EmailOTPRecord } from "./email/EmailOTP.js";
import { PendingTwoFactorStore, type PendingTwoFactor } from "./TwoFactor.js";
import { Hooks } from "./Hooks.js";

/** Fresh in-memory KV per invocation so tests are isolated. */
const testLayer = () => layerKV.pipe(Layer.provide(KeyValueStore.layerMemory));

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
    | EmailOTPStore
    | PendingTwoFactorStore
  >,
): Promise<A> => Effect.runPromise(effect.pipe(Effect.provide(testLayer())) as Effect.Effect<A, E>);

describe("KeyValueStores", () => {
  it("exports individual layers", () => {
    expect(OAuthStateStoreKV).toBeDefined();
    expect(ChallengeStoreKV).toBeDefined();
    expect(RateLimitStoreKV).toBeDefined();
    expect(EmailVerificationStoreKV).toBeDefined();
    expect(PasswordResetStoreKV).toBeDefined();
    expect(MagicLinkStoreKV).toBeDefined();
    expect(EmailOTPStoreKV).toBeDefined();
    expect(PendingTwoFactorStoreKV).toBeDefined();
  });

  describe("OAuthStateStoreKV", () => {
    const state: OAuthState = {
      state: "state-1",
      provider: "google",
      codeVerifier: "verifier",
      returnTo: "/dashboard",
      createdAt: Date.now(),
      expiresAt: Date.now() + 600_000,
    };

    it("roundtrips create/get/delete", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* OAuthStateStore;
          yield* store.create(state);
          const loaded = yield* store.get("state-1");
          yield* store.delete("state-1");
          const missing = yield* store.get("state-1");
          return { loaded, missing };
        }),
      );
      expect(result.loaded).toEqual(state);
      expect(result.missing).toBeNull();
    });
  });

  describe("ChallengeStoreKV", () => {
    it("roundtrips challenge bytes", async () => {
      const challenge: WebAuthnChallenge = {
        challenge: new Uint8Array([1, 2, 3, 255, 0, 42]),
        expiresAt: Date.now() + 60_000,
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
      expect(Array.from(result.loaded?.challenge ?? [])).toEqual([1, 2, 3, 255, 0, 42]);
      expect(result.loaded?.userId).toBe("user-1");
      expect(result.loaded?.expiresAt).toBe(challenge.expiresAt);
      expect(result.missing).toBeNull();
    });

    it("stores anonymous challenges (no userId)", async () => {
      const challenge: WebAuthnChallenge = {
        challenge: new Uint8Array([9, 9, 9]),
        expiresAt: Date.now() + 60_000,
      };
      const loaded = await run(
        Effect.gen(function* () {
          const store = yield* ChallengeStore;
          yield* store.create(challenge);
          return yield* store.get(challenge.challenge);
        }),
      );
      expect(loaded).not.toBeNull();
      expect(loaded?.userId).toBeUndefined();
    });
  });

  describe("RateLimitStoreKV", () => {
    it("roundtrips get/set/delete", async () => {
      const entry: RateLimitEntry = {
        key: "login:1.2.3.4",
        count: 3,
        resetAt: Date.now() + 60_000,
        blockedUntil: Date.now() + 120_000,
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
      expect(result.before).toBeNull();
      expect(result.after).toEqual(entry);
      expect(result.deleted).toBeNull();
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
            { key: "otp:me@example.com", count: 99, resetAt: Date.now() - 1 },
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
    const verification = (token: string, userId: string): EmailVerification => ({
      token,
      userId,
      email: `${userId}@example.com`,
      createdAt: Date.now(),
      expiresAt: Date.now() + 86_400_000,
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
      expect(result.loaded).toEqual(record);
      expect(result.deleted).toBeNull();
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
      expect(result.a).toBeNull();
      expect(result.b).toBeNull();
      expect(result.c?.userId).toBe("user-2");
    });
  });

  describe("PasswordResetStoreKV", () => {
    const reset = (token: string, userId: string): PasswordResetToken => ({
      token,
      userId,
      email: `${userId}@example.com`,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3_600_000,
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
      expect(result.loaded?.token).toBe("pr-1");
      expect(result.afterDelete).toBeNull();
      expect(result.two).toBeNull();
      expect(result.three?.userId).toBe("user-2");
    });
  });

  describe("MagicLinkStoreKV", () => {
    const link = (token: string, email: string): MagicLinkToken => ({
      token,
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
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
      expect(result.loaded?.email).toBe("a@example.com");
      expect(result.afterDelete).toBeNull();
      expect(result.two).toBeNull();
      expect(result.three?.email).toBe("b@example.com");
    });
  });

  describe("EmailOTPStoreKV", () => {
    const record: EmailOTPRecord = {
      email: "otp@example.com",
      otpHash: "hash",
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    };

    it("upserts per email+purpose and increments attempts", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* EmailOTPStore;
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
          const missingIncrement = yield* Effect.flip(
            store.incrementAttempts("otp@example.com", "sign-in"),
          );
          return { loaded, attempts1, attempts2, replaced, other, deleted, missingIncrement };
        }),
      );
      expect(result.loaded?.otpHash).toBe("hash");
      expect(result.attempts1).toBe(1);
      expect(result.attempts2).toBe(2);
      expect(result.replaced?.otpHash).toBe("new-hash");
      expect(result.replaced?.attempts).toBe(0);
      expect(result.other?.otpHash).toBe("other");
      expect(result.deleted).toBeNull();
      expect(result.missingIncrement._tag).toBe("AuthError");
    });
  });

  describe("PendingTwoFactorStoreKV", () => {
    it("roundtrips create/get/delete", async () => {
      const pending: PendingTwoFactor = {
        token: "2fa-1",
        userId: "user-1",
        createdAt: Date.now(),
        expiresAt: Date.now() + 300_000,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* PendingTwoFactorStore;
          yield* store.create(pending);
          const loaded = yield* store.get("2fa-1");
          yield* store.delete("2fa-1");
          const deleted = yield* store.get("2fa-1");
          return { loaded, deleted };
        }),
      );
      expect(result.loaded).toEqual(pending);
      expect(result.deleted).toBeNull();
    });
  });

  describe("integration: EmailVerificationService over EmailVerificationStoreKV", () => {
    it("creates, resends and verifies tokens end-to-end", async () => {
      const sent: Array<{ to: string; token: string }> = [];
      const program = Effect.gen(function* () {
        const service = yield* makeEmailVerificationService({
          sendEmail: (to, token) => Effect.sync(() => void sent.push({ to, token })),
        });
        const first = yield* service.createVerification("user-1", "user-1@example.com");
        // Resend invalidates the first token and issues a new one.
        const second = yield* service.resendVerification("user-1", "user-1@example.com");
        const staleResult = yield* Effect.flip(service.verifyToken(first.token));
        const result = yield* service.verifyToken(second.token);
        // One-time use: verifying again fails.
        const reused = yield* Effect.flip(service.verifyToken(second.token));
        return { staleResult, result, reused };
      });

      const layer = Layer.mergeAll(
        EmailVerificationStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
        Hooks.Default,
        PlatformCrypto.layer,
      );
      // The flipped verifications leave failure types in the error channel;
      // any unexpected failure should crash the test, so treat them as defects.
      const outcome = await Effect.runPromise(program.pipe(Effect.provide(layer), Effect.orDie));

      expect(sent).toHaveLength(2);
      expect(outcome.staleResult._tag).toBe("EmailVerificationError");
      expect(outcome.result).toEqual({
        userId: "user-1",
        email: "user-1@example.com",
        verified: true,
      });
      expect(outcome.reused._tag).toBe("EmailVerificationError");
    });
  });
});
