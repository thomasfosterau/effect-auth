import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import {
  makePasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
  type PasswordResetToken,
} from "./PasswordReset.js";
import { makeSessionManager, SessionStore, SessionManager, UserStore } from "./Session.js";
import { PasswordHasherLive, makePasswordHasher } from "./Password.js";
import type { Session, User, SessionConfig } from "./Types.js";
import * as Errors from "./Errors.js";

const users = new Map<string, User>();
const usersByEmail = new Map<string, string>();
const passwordHashes = new Map<string, string>();
const resetTokens = new Map<string, PasswordResetToken>();
const sessions = new Map<string, Session>();
const sentEmails: Array<{ email: string; token: string }> = [];

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.gen(function* () {
      const session = sessions.get(sessionId);
      if (!session) {
        return yield* Effect.fail(
          new Errors.SessionNotFoundError({
            message: "Session not found",
            sessionId,
          }),
        );
      }
      return session;
    }),

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
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),
};

const userStore = {
  get: (userId: string) =>
    Effect.gen(function* () {
      const user = users.get(userId);
      if (!user) {
        return yield* Effect.fail(
          new Errors.UserNotFoundError({
            message: "User not found",
            userId,
          }),
        );
      }
      return user;
    }),

  getCredentials: (userId: string) =>
    Effect.gen(function* () {
      const hash = passwordHashes.get(userId);
      if (!hash) {
        return yield* Effect.fail(
          new Errors.UserNotFoundError({
            message: "User credentials not found",
            userId,
          }),
        );
      }
      return hash;
    }),
};

const passwordResetUserStore = {
  getUserByEmail: (email: string) =>
    Effect.sync(() => {
      const userId = usersByEmail.get(email);
      return userId ? (users.get(userId) ?? null) : null;
    }),

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
      for (const [token, reset] of resetTokens.entries()) {
        if (reset.userId === userId) {
          resetTokens.delete(token);
        }
      }
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
      makeSessionManager(sessionConfig),
      Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
    ),
  );

  return Context.merge(
    Context.make(SessionManager, sessionManager),
    Context.merge(
      Context.make(SessionStore, sessionStore),
      Context.merge(
        Context.make(UserStore, userStore),
        Context.merge(
          Context.make(PasswordResetStore, passwordResetStore),
          Context.merge(
            Context.make(PasswordResetUserStore, passwordResetUserStore),
            PasswordHasherLive,
          ),
        ),
      ),
    ),
  );
};

describe("PasswordResetService", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    resetTokens.clear();
    sessions.clear();
    sentEmails.splice(0, sentEmails.length);
  });

  it("should issue a password reset token and send email for existing users", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-reset-1",
      attributes: {
        email: "reset@example.com",
      },
    };
    users.set(user.id, user);
    usersByEmail.set("reset@example.com", user.id);

    const program = Effect.gen(function* () {
      const service = yield* makePasswordResetService({
        sendResetPassword: (email, token) =>
          Effect.sync(() => {
            sentEmails.push({ email, token });
          }),
      });

      yield* service.requestPasswordReset("reset@example.com");
    });

    await Effect.runPromise(Effect.provide(program, testContext));

    expect(sentEmails.length).toBe(1);
    expect(sentEmails[0]?.email).toBe("reset@example.com");
    expect(resetTokens.size).toBe(1);
  });

  it("should not reveal whether an email exists", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makePasswordResetService({
        sendResetPassword: () => Effect.void,
      });

      yield* service.requestPasswordReset("missing@example.com");
    });

    await Effect.runPromise(Effect.provide(program, testContext));

    expect(sentEmails.length).toBe(0);
    expect(resetTokens.size).toBe(0);
  });

  it("should reset password and revoke sessions when configured", async () => {
    const testContext = await makeTestContext();

    const hasher = makePasswordHasher();
    const oldHash = await Effect.runPromise(hasher.hash("old-password-123"));

    const user: User = {
      id: "user-reset-2",
      attributes: {
        email: "session-reset@example.com",
      },
    };

    users.set(user.id, user);
    usersByEmail.set("session-reset@example.com", user.id);
    passwordHashes.set(user.id, oldHash.hash);

    const resetToken: PasswordResetToken = {
      token: "token-123",
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

    const program = Effect.gen(function* () {
      const service = yield* makePasswordResetService({
        revokeSessionsOnPasswordReset: true,
        sendResetPassword: () => Effect.void,
      });

      return yield* service.resetPassword("token-123", "new-password-123");
    });

    const result = await Effect.runPromise(Effect.provide(program, testContext));

    const updatedHash = passwordHashes.get(user.id);
    expect(result.userId).toBe(user.id);
    expect(result.reset).toBe(true);
    expect(updatedHash).toBeDefined();
    expect(updatedHash).not.toBe(oldHash.hash);
    expect(resetTokens.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should fail for invalid reset tokens", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makePasswordResetService({
        sendResetPassword: () => Effect.void,
      });

      return yield* Effect.either(service.resetPassword("missing-token", "new-password-123"));
    });

    const result = await Effect.runPromise(Effect.provide(program, testContext));

    expect(result._tag).toBe("Left");
    if (result._tag === "Left") {
      expect(result.left._tag).toBe("PasswordResetError");
    }
  });
});
