import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect, Layer } from "effect";
import * as nodeCrypto from "node:crypto";
import { Hooks, makePlugin, composePlugins } from "./Hooks.js";
import * as Errors from "./Errors.js";
import { makeEmailPasswordService, EmailPasswordStore } from "./EmailPassword.js";
import { makeSessionManager, SessionStore, UserStore, SessionManager } from "./Session.js";
import {
  MultiAlgorithmVerifier,
  PasswordHasher,
  makePBKDF2Hasher,
  makeScryptHasher,
  makeMultiAlgorithmVerifier,
} from "./Password.js";
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

describe("EmailPasswordService — migration and security hardening", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  /** Build an old-style PBKDF2 hash (210 000 iterations, 64-byte key). */
  const makeOldPbkdf2Hash = (password: string): Promise<string> => {
    const salt = nodeCrypto.randomBytes(16);
    return new Promise<string>((resolve, reject) =>
      nodeCrypto.pbkdf2(password, salt, 210000, 64, "sha256", (err, key) =>
        err
          ? reject(err)
          : resolve(`pbkdf2-sha256$210000$${salt.toString("hex")}$${key.toString("hex")}`),
      ),
    );
  };

  it("verifies an old PBKDF2 hash and rehashes it to current params on sign-in", async () => {
    const testContext = await makeTestContext();

    // Seed user with an old-style hash (fewer iterations, larger key).
    const oldHash = await makeOldPbkdf2Hash("migration-password");
    const user: User = {
      id: "user-migration",
      email: "migration@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    passwordHashes.set(user.id, oldHash);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* service.signIn({ email: user.email, password: "migration-password" });
    });

    // Use the current PBKDF2 hasher — it detects the outdated hash via needsRehash.
    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session).toBeDefined();

    // The stored hash must have been silently upgraded to the current params.
    const updatedHash = passwordHashes.get(user.id)!;
    expect(updatedHash).not.toBe(oldHash);
    expect(updatedHash.startsWith("pbkdf2-sha256$600000$")).toBe(true);
  });

  it("signs in with old PBKDF2 hash after switching default hasher to scrypt via MultiAlgorithmVerifier", async () => {
    const testContext = await makeTestContext();

    const oldHash = await makeOldPbkdf2Hash("switch-password");
    const user: User = {
      id: "user-switch",
      email: "switch@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    passwordHashes.set(user.id, oldHash);

    const scryptHasher = makeScryptHasher({ cost: 16384 });
    const verifier = makeMultiAlgorithmVerifier([makePBKDF2Hasher(), scryptHasher]);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* service.signIn({ email: user.email, password: "switch-password" });
    });

    // testContext has PBKDF2 as PasswordHasher; override with scrypt + add verifier.
    // Context.merge(a, b) → b wins on conflict, so place the overrides second.
    const ctx = Context.merge(
      Context.merge(testContext, Context.make(PasswordHasher, scryptHasher)),
      Context.make(MultiAlgorithmVerifier, verifier),
    );

    const result = await Effect.runPromise(
      Effect.provide(program, ctx).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session).toBeDefined();

    // Hash must have been rehashed to scrypt by the active hasher.
    const updatedHash = passwordHashes.get(user.id)!;
    expect(updatedHash.startsWith("scrypt$")).toBe(true);
  });

  it("returns InvalidCredentialsError (not a defect) when hash format is malformed on sign-in", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-malformed",
      email: "malformed@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    // Malformed hash: non-numeric iteration count — would previously cause a RangeError defect.
    passwordHashes.set(user.id, "pbkdf2-sha256$notanumber$aabbcc$ddeeff");

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* Effect.result(service.signIn({ email: user.email, password: "any-password" }));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("InvalidCredentialsError");
    }
  });

  it("returns InvalidCredentialsError (not defect) for an excessively long password on sign-in", async () => {
    const testContext = await makeTestContext();
    const hasher = makePBKDF2Hasher();
    const hashResult = await Effect.runPromise(hasher.hash("real-password"));

    const user: User = {
      id: "user-long-pw",
      email: "longpw@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    usersByEmail.set(user.email, user.id);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* Effect.result(
        service.signIn({
          email: user.email,
          // 2000 'a' chars — well over MAX_PASSWORD_BYTES (1024)
          password: "a".repeat(2000),
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
});

describe("EmailPasswordService - dangling session protection", () => {
  // Shared in-memory stores for these tests.
  const localUsers = new Map<string, User>();
  const localUsersByEmail = new Map<string, string>();
  const localPasswordHashes = new Map<string, string>();
  const localSessions = new Map<string, Session>();

  const localSessionStore = {
    create: (session: Session) =>
      Effect.sync(() => {
        localSessions.set(session.id, session);
        return session;
      }),
    get: (sessionId: string) => Effect.sync(() => localSessions.get(sessionId) ?? null),
    update: (session: Session) =>
      Effect.sync(() => {
        localSessions.set(session.id, session);
        return session;
      }),
    delete: (sessionId: string) =>
      Effect.sync(() => {
        localSessions.delete(sessionId);
      }),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        for (const [id, session] of localSessions.entries()) {
          if (session.userId === userId) localSessions.delete(id);
        }
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() => Array.from(localSessions.values()).filter((s) => s.userId === userId)),
  };

  const localUserStore = {
    get: (userId: string) => Effect.sync(() => localUsers.get(userId) ?? null),
    getCredentials: (userId: string) => Effect.sync(() => localPasswordHashes.get(userId) ?? null),
  };

  const localEmailPasswordStore = {
    getUserByEmail: (email: string) =>
      Effect.sync(() => {
        const id = localUsersByEmail.get(email);
        return id ? (localUsers.get(id) ?? null) : null;
      }),
    createUser: ({
      email,
      attributes,
    }: {
      email: string;
      name?: string;
      attributes?: Record<string, unknown>;
    }) =>
      Effect.sync(() => {
        const id = `user-${localUsers.size + 1}`;
        const user: User = {
          id,
          email,
          emailVerified: false,
          createdAt: new Date(),
          updatedAt: new Date(),
          attributes: attributes ?? {},
        };
        localUsers.set(id, user);
        localUsersByEmail.set(email, id);
        return user;
      }),
    getPasswordHash: (userId: string) => Effect.sync(() => localPasswordHashes.get(userId) ?? null),
    setPasswordHash: (userId: string, hash: string) =>
      Effect.sync(() => {
        localPasswordHashes.set(userId, hash);
      }),
  };

  const makeLocalContext = async () => {
    const sessionManager = await Effect.runPromise(
      Effect.provide(
        makeSessionManager({
          sessionExpiresIn: { activePeriod: 3_600_000, idlePeriod: 1_800_000 },
        }),
        Context.merge(
          Context.make(SessionStore, localSessionStore),
          Context.make(UserStore, localUserStore),
        ),
      ),
    );
    return Context.merge(
      Context.make(SessionManager, sessionManager),
      Context.merge(
        Context.make(EmailPasswordStore, localEmailPasswordStore),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );
  };

  beforeEach(() => {
    localUsers.clear();
    localUsersByEmail.clear();
    localPasswordHashes.clear();
    localSessions.clear();
  });

  it("signIn succeeds and returns the session even when afterSignIn hook fails (no dangling session)", async () => {
    const ctx = await makeLocalContext();

    // First, register a user.
    const signUpResult = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* makeEmailPasswordService();
        return yield* svc.signUp({ email: "alice@example.com", password: "hunter2!" });
      }).pipe(Effect.provide(ctx), Effect.provide(Hooks.Default)),
    );
    expect(signUpResult.session).toBeDefined();

    localSessions.clear(); // clear sign-up session so we can inspect sign-in session cleanly

    // A failing afterSignIn hook.
    const failingAfterSignIn = makePlugin({
      afterSignIn: () => Effect.fail(new Errors.AuthError({ message: "hook boom" })),
    });

    const signInResult = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* makeEmailPasswordService();
        return yield* svc.signIn({ email: "alice@example.com", password: "hunter2!" });
      }).pipe(
        Effect.provide(ctx),
        Effect.provide(composePlugins([failingAfterSignIn]).pipe(Layer.provide(Hooks.Default))),
      ),
    );

    // signIn must succeed (no error propagated) even though the hook failed.
    expect(signInResult.session).toBeDefined();
    expect(signInResult.user.email).toBe("alice@example.com");

    // The session is live in the store — no dangling session.
    expect(signInResult.session && localSessions.has(signInResult.session.id)).toBe(true);
  });

  it("signUp succeeds and returns the session even when afterSignUp hook fails (no dangling session)", async () => {
    const ctx = await makeLocalContext();

    const failingAfterSignUp = makePlugin({
      afterSignUp: () => Effect.fail(new Errors.AuthError({ message: "hook boom" })),
    });

    const signUpResult = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* makeEmailPasswordService();
        return yield* svc.signUp({ email: "bob@example.com", password: "hunter2!" });
      }).pipe(
        Effect.provide(ctx),
        Effect.provide(composePlugins([failingAfterSignUp]).pipe(Layer.provide(Hooks.Default))),
      ),
    );

    // signUp must succeed (no error propagated) even though the hook failed.
    expect(signUpResult.session).toBeDefined();
    expect(signUpResult.user.email).toBe("bob@example.com");

    // The session is live in the store — no dangling session.
    expect(signUpResult.session && localSessions.has(signUpResult.session.id)).toBe(true);
  });
});
