import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import { Hooks } from "./Hooks.js";
import { makeEmailPasswordService, EmailPasswordStore } from "./EmailPassword.js";
import { makeSessionManager, SessionStore, UserStore, SessionManager } from "./Session.js";
import { PasswordHasher, makePBKDF2Hasher } from "./Password.js";
import type { Session, User, SessionConfig } from "./Types.js";

const users = new Map<string, User>();
const usersByEmail = new Map<string, string>();
const passwordHashes = new Map<string, string>();
const sessions = new Map<string, Session>();

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
      for (const [id, session] of sessions.entries()) {
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),

  getCredentials: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),
};

const emailPasswordStore = {
  getUserByEmail: (email: string) =>
    Effect.sync(() => {
      const userId = usersByEmail.get(email);
      return userId ? (users.get(userId) ?? null) : null;
    }),

  createUser: ({
    email,
    name,
    attributes,
  }: {
    email: string;
    name?: string;
    attributes?: Record<string, unknown>;
  }) =>
    Effect.sync(() => {
      const id = `user-${users.size + 1}`;
      const user: User = {
        id,
        email,
        emailVerified: false,
        ...(name !== undefined && { name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: attributes ?? {},
      };
      users.set(id, user);
      usersByEmail.set(email, id);
      return user;
    }),

  getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
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
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.make(PasswordHasher, makePBKDF2Hasher()),
        ),
      ),
    ),
  );
};

describe("EmailPasswordService", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  it("should sign up and create a session by default", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();

      const result = yield* service.signUp({
        email: "Test@Example.com",
        password: "strong-password-123",
        name: "Tester",
      });

      expect(result.user.email).toBe("test@example.com");
      expect(result.user.emailVerified).toBe(false);
      expect(result.session).toBeDefined();

      return result;
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.session?.userId).toBe(result.user.id);
  });

  it("should sign in an existing user", async () => {
    const testContext = await makeTestContext();

    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("sign-in-password"));

    const user: User = {
      id: "user-existing",
      email: "existing@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    usersByEmail.set("existing@example.com", user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService({
        requireEmailVerification: true,
      });
      return yield* service.signIn({
        email: "existing@example.com",
        password: "sign-in-password",
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session).toBeDefined();
  });

  it("should reject invalid credentials", async () => {
    const testContext = await makeTestContext();

    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("correct-password"));

    const user: User = {
      id: "user-invalid-cred",
      email: "invalid@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    usersByEmail.set("invalid@example.com", user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* Effect.result(
        service.signIn({
          email: "invalid@example.com",
          password: "wrong-password",
        }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("InvalidCredentialsError");
    }
  });

  it("should block sign-in for unverified email when required", async () => {
    const testContext = await makeTestContext();

    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("password-123"));

    const user: User = {
      id: "user-unverified",
      email: "unverified@example.com",
      emailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    usersByEmail.set("unverified@example.com", user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService({
        requireEmailVerification: true,
      });
      return yield* Effect.result(
        service.signIn({
          email: "unverified@example.com",
          password: "password-123",
        }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailNotVerifiedError");
    }
  });
});

describe("EmailPasswordService second-factor gate", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  it("returns a second-factor challenge instead of a session when the gate requires it", async () => {
    const { SecondFactorGate } = await import("./EmailPassword.js");
    const testContext = await makeTestContext();

    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("gate-password"));

    const user: User = {
      id: "user-gated",
      email: "gated@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const gate = {
      required: (candidate: User) => Effect.succeed(candidate.id === user.id),
      begin: () => Effect.succeed({ token: "pending-token", expiresAt: Date.now() + 60_000 }),
    };

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* service.signIn({ email: user.email, password: "gate-password" });
    });

    const result = await Effect.runPromise(
      Effect.provide(
        program,
        Context.merge(testContext, Context.make(SecondFactorGate, gate)),
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.session).toBeUndefined();
    expect(result.secondFactor).toEqual({
      token: "pending-token",
      expiresAt: expect.any(Number),
    });
    // No session may be created until the second factor is redeemed.
    expect(sessions.size).toBe(0);
  });

  it("creates a session normally when the gate does not require a second factor", async () => {
    const { SecondFactorGate } = await import("./EmailPassword.js");
    const testContext = await makeTestContext();

    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("no-gate-password"));

    const user: User = {
      id: "user-ungated",
      email: "ungated@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const gate = {
      required: () => Effect.succeed(false),
      begin: () => Effect.succeed({ token: "unused", expiresAt: Date.now() + 60_000 }),
    };

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* service.signIn({ email: user.email, password: "no-gate-password" });
    });

    const result = await Effect.runPromise(
      Effect.provide(
        program,
        Context.merge(testContext, Context.make(SecondFactorGate, gate)),
      ).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.secondFactor).toBeUndefined();
    expect(result.session).toBeDefined();
  });
});
