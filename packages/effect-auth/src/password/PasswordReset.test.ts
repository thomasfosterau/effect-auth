import { describe, it, expect, beforeEach, assert } from "vite-plus/test";
import { Context, Crypto, Effect, Layer, Result } from "effect";
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

/** The no-op hooks, with the detached sends run in place so a test reads them on return. */
const TestHooks = Layer.merge(Hooks.Default, inlineDeliveryScheduler);

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
const resetTokens = new Map<string, PasswordResetToken>();
const sessions = new Map<string, Session>();
const sentEmails: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

/** Seed an email identifier for a user (the old `email`/`emailVerified` fields). */
const seedEmailIdentifier = (userId: string, email: string, verified: boolean): Identifier => {
  const identifier = makeIdentifier({ userId, type: "email", value: email, verified });
  identifierRecords.set(identifier.id, identifier);
  return identifier;
};

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),

  update: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      sessions.delete(sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      sessions.forEach((session, id) => {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),
};

const passwordResetUserStore = {
  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const passwordResetStore = {
  create: (reset: PasswordResetToken) =>
    Effect.sync(() => {
      resetTokens.set(reset.token, reset);
      return reset;
    }),

  get: (token: string) => Effect.sync(() => resetTokens.get(token) ?? null),

  delete: (token: string) =>
    Effect.sync(() => {
      resetTokens.delete(token);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      resetTokens.forEach((reset, token) => {
        if (reset.userId === userId) {
          resetTokens.delete(token);
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

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(TestHooks)),
  );

  return Context.merge(
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
              Context.make(Crypto.Crypto, PlatformCrypto.instance),
            ),
          ),
        ),
      ),
    ),
  );
};

describe("PasswordResetService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    resetTokens.clear();
    sessions.clear();
    sentEmails.splice(0, sentEmails.length);
  });

  it("should issue a password reset token and send email for existing users", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-reset-1",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
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
    expect(resetTokens.size).toBe(1);
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
    expect(resetTokens.size).toBe(0);
  });

  it("should revoke sessions by default on password reset", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const oldHash = await Effect.runPromise(hasher.hash("old-password-123"));

    const user: User = {
      id: "user-reset-2",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    seedEmailIdentifier(user.id, "session-reset@example.com", false);
    passwordHashes.set(user.id, oldHash.hash);

    // Seed with the hash as key (the service looks up by hash).
    const resetToken: PasswordResetToken = {
      token: hashToken("token-123"),
      userId: user.id,
      email: "session-reset@example.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    };

    resetTokens.set(resetToken.token, resetToken);
    sessions.set("session-1", {
      id: "session-1",
      userId: user.id,
      createdAt: new Date(),
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
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

    const updatedHash = passwordHashes.get(user.id);
    expect(result.userId).toBe(user.id);
    expect(result.reset).toBe(true);
    expect(updatedHash).toBeDefined();
    expect(updatedHash).not.toBe(oldHash.hash);
    expect(resetTokens.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should not revoke sessions when revokeSessionsOnPasswordReset is false", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const oldHash = await Effect.runPromise(hasher.hash("old-password-123"));

    const user: User = {
      id: "user-reset-3",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    seedEmailIdentifier(user.id, "session-keep@example.com", false);
    passwordHashes.set(user.id, oldHash.hash);

    const resetToken: PasswordResetToken = {
      token: hashToken("token-456"),
      userId: user.id,
      email: "session-keep@example.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    };

    resetTokens.set(resetToken.token, resetToken);
    sessions.set("session-2", {
      id: "session-2",
      userId: user.id,
      createdAt: new Date(),
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
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

    const updatedHash = passwordHashes.get(user.id);
    expect(result.userId).toBe(user.id);
    expect(result.reset).toBe(true);
    expect(updatedHash).toBeDefined();
    expect(updatedHash).not.toBe(oldHash.hash);
    expect(resetTokens.size).toBe(0);
    expect(sessions.size).toBe(1);
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
