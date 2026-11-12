import { describe, it, expect, beforeEach, assert } from "vite-plus/test";
import { type RateLimitEntry, RateLimitStore } from "../RateLimit.ts";
import { memoryRateLimitStore } from "../testing/MemoryStores.ts";
import { Context, DateTime, Effect, Layer, MutableHashMap, Result } from "effect";
import * as Option from "effect/Option";
import { SecureRandom } from "effect/crypto";
import { Hooks } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import {
  type PasswordResetToken,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./PasswordReset.ts";
import * as PasswordReset from "./PasswordReset.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import { make, SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import { PasswordHasher } from "./Password.ts";
import * as Password from "./Password.ts";
import { hashToken } from "../TokenHash.ts";
import type { Session, User, SessionConfig } from "../Types.ts";
import { inlineDeliveryScheduler } from "../testing/Delivery.ts";
import { looseCollationIdentifierStore } from "../testing/LooseCollation.ts";

/** The no-op hooks, with the detached sends run in place so a test reads them on return. */
const TestHooks = Layer.merge(Hooks.Default, inlineDeliveryScheduler);

const users = MutableHashMap.empty<string, User>();
const identifierRecords = MutableHashMap.empty<string, Identifier>();
const passwordHashes = MutableHashMap.empty<string, string>();
const resetTokens = MutableHashMap.empty<string, PasswordResetToken>();
const sessions = MutableHashMap.empty<string, Session>();
const sentEmails: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

/** Seed an email identifier for a user (the old `email`/`emailVerified` fields). */
const seedEmailIdentifier = (userId: string, email: string, verified: boolean): Identifier => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifierRecords, identifier.id, identifier);
  return identifier;
};

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),

  update: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(sessions, sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(sessions, (session, id) => {
        if (session.userId === userId) {
          MutableHashMap.remove(sessions, id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(sessions)).filter((session) => session.userId === userId),
    ),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
};

const passwordResetUserStore = {
  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      MutableHashMap.set(passwordHashes, userId, hash);
    }),
};

const passwordResetStore = {
  create: (reset: PasswordResetToken) =>
    Effect.sync(() => {
      MutableHashMap.set(resetTokens, reset.token, reset);
      return reset;
    }),

  get: (token: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(resetTokens, token))),

  delete: (token: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(resetTokens, token);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(resetTokens, (reset, token) => {
        if (reset.userId === userId) {
          MutableHashMap.remove(resetTokens, token);
        }
      });
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

const makeTestContext = async (
  rateLimits: MutableHashMap.MutableHashMap<string, RateLimitEntry> = MutableHashMap.empty(),
) => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(TestHooks)),
  );

  return Context.add(
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.make(SessionStore, sessionStore),
        Context.merge(
          Context.make(UserStore, userStore),
          Context.merge(
            Context.make(PasswordResetStore, passwordResetStore),
            Context.merge(
              Context.merge(
                Context.make(PasswordResetUserStore, passwordResetUserStore),
                Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
              ),
              Context.merge(
                Context.make(IdentifierStore, identifierStore),
                Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
              ),
            ),
          ),
        ),
      ),
    ),
    RateLimitStore,
    memoryRateLimitStore(rateLimits),
  );
};

describe("PasswordResetService", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(resetTokens);
    MutableHashMap.clear(sessions);
    sentEmails.splice(0, sentEmails.length);
  });

  it("should issue a password reset token and send email for existing users", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-reset-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, user.id, user);
    seedEmailIdentifier(user.id, "reset@example.com", false);

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            sendResetPassword: (email, token) =>
              Effect.sync(() => {
                sentEmails.push({ email, token });
              }),
          });

          yield* service.requestPasswordReset("reset@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentEmails.length).toBe(1);
    expect(sentEmails[0]?.email).toBe("reset@example.com");
    expect(MutableHashMap.size(resetTokens)).toBe(1);
  });

  it("sends nothing for a look-alike address a loose store matches to another account (#602)", async () => {
    const testContext = await makeTestContext();
    const bob: User = {
      id: "user-bob",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, bob.id, bob);
    seedEmailIdentifier(bob.id, "bob@example.com", true);

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            sendResetPassword: (email, token) =>
              Effect.sync(() => {
                sentEmails.push({ email, token });
              }),
          });
          // A store under a case- and accent-insensitive collation answers
          // these with Bob's record; none of them may reach Bob's account.
          yield* service.requestPasswordReset("bob@exämple.com");
          yield* service.requestPasswordReset("ｂｏｂ@example.com");
          expect(sentEmails).toEqual([]);
          expect(MutableHashMap.size(resetTokens)).toBe(0);

          // Bob's own address still gets Bob's link, at the stored address.
          yield* service.requestPasswordReset("  Bob@Example.com ");
        }).pipe(
          Effect.provideService(IdentifierStore, looseCollationIdentifierStore(identifierRecords)),
        ),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentEmails.map((sent) => sent.email)).toEqual(["bob@example.com"]);
    const [reset] = MutableHashMap.values(resetTokens);
    expect(reset?.userId).toBe(bob.id);
    expect(reset?.email).toBe("bob@example.com");
  });

  it("should not reveal whether an email exists", async () => {
    const testContext = await makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            sendResetPassword: () => Effect.void,
          });

          yield* service.requestPasswordReset("missing@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentEmails.length).toBe(0);
    expect(MutableHashMap.size(resetTokens)).toBe(0);
  });

  it("should revoke sessions by default on password reset", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const oldHash = await Effect.runPromise(hasher.hash("old-password-123"));

    const user: User = {
      id: "user-reset-2",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    MutableHashMap.set(users, user.id, user);
    seedEmailIdentifier(user.id, "session-reset@example.com", false);
    MutableHashMap.set(passwordHashes, user.id, oldHash.hash);

    // Seed with the hash as key (the service looks up by hash).
    const resetToken: PasswordResetToken = {
      token: hashToken("token-123"),
      userId: user.id,
      email: "session-reset@example.com",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
    };

    MutableHashMap.set(resetTokens, resetToken.token, resetToken);
    MutableHashMap.set(sessions, "session-1", {
      id: "session-1",
      userId: user.id,
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      lastActivityAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 })),
      attributes: {},
    });

    // No revokeSessionsOnPasswordReset option — default should revoke sessions.

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            sendResetPassword: () => Effect.void,
          });

          return yield* service.resetPassword("token-123", "new-password-123");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    const updatedHash = Option.getOrUndefined(MutableHashMap.get(passwordHashes, user.id));
    expect(result.userId).toBe(user.id);
    expect(result.reset).toBe(true);
    expect(updatedHash).toBeDefined();
    expect(updatedHash).not.toBe(oldHash.hash);
    expect(MutableHashMap.size(resetTokens)).toBe(0);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("should not revoke sessions when revokeSessionsOnPasswordReset is false", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const oldHash = await Effect.runPromise(hasher.hash("old-password-123"));

    const user: User = {
      id: "user-reset-3",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    MutableHashMap.set(users, user.id, user);
    seedEmailIdentifier(user.id, "session-keep@example.com", false);
    MutableHashMap.set(passwordHashes, user.id, oldHash.hash);

    const resetToken: PasswordResetToken = {
      token: hashToken("token-456"),
      userId: user.id,
      email: "session-keep@example.com",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60_000,
    };

    MutableHashMap.set(resetTokens, resetToken.token, resetToken);
    MutableHashMap.set(sessions, "session-2", {
      id: "session-2",
      userId: user.id,
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      lastActivityAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      expiresAt: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 3600_000 })),
      attributes: {},
    });

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            revokeSessionsOnPasswordReset: false,
            sendResetPassword: () => Effect.void,
          });

          return yield* service.resetPassword("token-456", "new-password-123");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    const updatedHash = Option.getOrUndefined(MutableHashMap.get(passwordHashes, user.id));
    expect(result.userId).toBe(user.id);
    expect(result.reset).toBe(true);
    expect(updatedHash).toBeDefined();
    expect(updatedHash).not.toBe(oldHash.hash);
    expect(MutableHashMap.size(resetTokens)).toBe(0);
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("should fail for invalid reset tokens", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* PasswordReset.make({
            sendResetPassword: () => Effect.void,
          });

          return yield* Effect.result(service.resetPassword("missing-token", "new-password-123"));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("PasswordResetError");
  });
});
