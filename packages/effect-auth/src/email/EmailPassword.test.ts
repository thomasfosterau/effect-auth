import { describe, it, expect, beforeEach, assert } from "vite-plus/test";
import { Array as Arr, Context, Crypto, Effect, Layer, Order, Result } from "effect";
import { Hooks, makePlugin, composePlugins } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import * as Errors from "../Errors.ts";
import { EmailPasswordStore, type CreateUserInput } from "./EmailPassword.ts";
import * as EmailPassword from "./EmailPassword.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import { make, SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import { hashToken } from "../TokenHash.ts";
import { MultiAlgorithmVerifier, PasswordHasher } from "../password/Password.ts";
import * as Password from "../password/Password.ts";
import type { Session, User, SessionConfig } from "../Types.ts";

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
const sessions = new Map<string, Session>();
/** The `identifier` each `createUser` call was given. */
const createdWith: Array<CreateUserInput["identifier"]> = [];

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
};

const emailPasswordStore = {
  createUser: ({ name, image, attributes, identifier }: CreateUserInput) =>
    Effect.sync(() => {
      createdWith.push(identifier);
      const id = `user-${users.size + 1}`;
      const user: User = {
        id,
        ...(name !== undefined && { name }),
        ...(image !== undefined && { image }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: attributes ?? {},
      };
      users.set(id, user);
      return { user, created: true };
    }),

  getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

  clearPasswordHash: (userId: string) => Effect.sync(() => void passwordHashes.delete(userId)),
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

const makeTestContext = async (
  store: typeof EmailPasswordStore.Service = emailPasswordStore,
  hasher: typeof PasswordHasher.Service = Password.pbkdf2Hasher({ iterations: 1000 }),
) => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  return Context.merge(
    Context.make(SessionService, sessionManager),
    Context.merge(
      Context.make(SessionStore, sessionStore),
      Context.merge(
        Context.make(UserStore, userStore),
        Context.merge(
          Context.merge(
            Context.make(EmailPasswordStore, store),
            Context.make(PasswordHasher, hasher),
          ),
          Context.merge(
            Context.make(IdentifierStore, identifierStore),
            Context.make(Crypto.Crypto, PlatformCrypto.instance),
          ),
        ),
      ),
    ),
  );
};

describe("EmailPasswordService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
    createdWith.length = 0;
  });

  it("should sign up and create a session by default", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();

      const result = yield* service.signUp({
        email: "Test@Example.com",
        password: "strong-password-123",
        name: "Tester",
      });

      expect(result.identifier).toEqual({ type: "email", value: "test@example.com" });
      expect(result.session).toBeDefined();

      return result;
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.session?.userId).toBe(result.user.id);

    // The claimed email identifier belongs to the new user and starts unverified.
    const stored = Array.from(identifierRecords.values()).find(
      (identifier) => identifier.type === "email" && identifier.value === "test@example.com",
    );
    expect(stored?.userId).toBe(result.user.id);
    expect(stored?.verified).toBe(false);
    // The store was handed the address to create the user with (#380).
    expect(createdWith).toEqual([{ type: "email", value: "test@example.com", verified: false }]);
  });

  it("fails with EmailInUseError when the store's writer returns the existing owner, and leaves the owner untouched (#380)", async () => {
    // A writer that upserts on the address. The owner's row lands between the
    // sign-up's pre-check and its insert, so the upsert returns the owner and
    // reports that it inserted nothing.
    const owner: User = {
      id: "owner",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const upsertingStore: typeof EmailPasswordStore.Service = {
      ...emailPasswordStore,
      createUser: () =>
        Effect.sync(() => {
          users.set(owner.id, owner);
          seedEmailIdentifier(owner.id, "owner@example.com", false);
          passwordHashes.set(owner.id, "owner-hash");
          return { user: owner, created: false };
        }),
    };
    const testContext = await makeTestContext(upsertingStore);

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* EmailPassword.make();
        return yield* Effect.result(
          service.signUp({ email: "owner@example.com", password: "attacker-password-123" }),
        );
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailInUseError");
    // No password, session or second identifier landed on the owner.
    expect(passwordHashes.get(owner.id)).toBe("owner-hash");
    expect(sessions.size).toBe(0);
    expect(
      Array.from(identifierRecords.values()).map(({ userId, verified }) => ({ userId, verified })),
    ).toEqual([{ userId: owner.id, verified: false }]);
  });

  it("should sign in an existing user", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("sign-in-password"));

    const user: User = {
      id: "user-existing",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    seedEmailIdentifier(user.id, "existing@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make({
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

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("correct-password"));

    const user: User = {
      id: "user-invalid-cred",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    seedEmailIdentifier(user.id, "invalid@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
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
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("InvalidCredentialsError");
  });

  it("should block sign-in for unverified email when required", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("password-123"));

    const user: User = {
      id: "user-unverified",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    seedEmailIdentifier(user.id, "unverified@example.com", false);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make({
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
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailNotVerifiedError");
  });
});

describe("EmailPasswordService constant-work sign-in", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  it("calls passwordHasher.verify even when the email does not exist", async () => {
    let verifyCalls = 0;
    const realHasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const spyHasher: typeof PasswordHasher.Service = {
      algorithm: realHasher.algorithm,
      hash: (password) => realHasher.hash(password),
      verify: (password, hash) => {
        verifyCalls++;
        return realHasher.verify(password, hash);
      },
    };

    const sessionManager = await Effect.runPromise(
      Effect.provide(
        make({ sessionExpiresIn: { activePeriod: 86400000, idlePeriod: 43200000 } }),
        Context.merge(
          Context.merge(
            Context.make(SessionStore, sessionStore),
            Context.make(UserStore, userStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ).pipe(Effect.provide(Hooks.Default)),
    );

    const ctx = Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.merge(
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.make(PasswordHasher, spyHasher),
        ),
        Context.merge(
          Context.merge(
            Context.make(UserStore, userStore),
            Context.make(IdentifierStore, identifierStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ),
    );

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* Effect.result(
        service.signIn({ email: "ghost@example.com", password: "any-password" }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, ctx).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    expect(verifyCalls).toBeGreaterThanOrEqual(1);
  });

  it("calls passwordHasher.verify even when the user has no password hash", async () => {
    let verifyCalls = 0;
    const realHasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const spyHasher: typeof PasswordHasher.Service = {
      algorithm: realHasher.algorithm,
      hash: (password) => realHasher.hash(password),
      verify: (password, hash) => {
        verifyCalls++;
        return realHasher.verify(password, hash);
      },
    };

    const user: User = {
      id: "user-nohash",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "nohash@example.com", true);
    // Intentionally no password hash stored for this user.

    const sessionManager = await Effect.runPromise(
      Effect.provide(
        make({ sessionExpiresIn: { activePeriod: 86400000, idlePeriod: 43200000 } }),
        Context.merge(
          Context.merge(
            Context.make(SessionStore, sessionStore),
            Context.make(UserStore, userStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ).pipe(Effect.provide(Hooks.Default)),
    );

    const ctx = Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.merge(
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.make(PasswordHasher, spyHasher),
        ),
        Context.merge(
          Context.merge(
            Context.make(UserStore, userStore),
            Context.make(IdentifierStore, identifierStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ),
    );

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* Effect.result(
        service.signIn({ email: "nohash@example.com", password: "any-password" }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, ctx).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    expect(verifyCalls).toBeGreaterThanOrEqual(1);
  });
});

describe("EmailPasswordService second-factor gate", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  it("returns a second-factor challenge instead of a session when the gate requires it", async () => {
    const { SecondFactorGate } = await import("./EmailPassword.ts");
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("gate-password"));

    const user: User = {
      id: "user-gated",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "gated@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const gate = {
      required: (candidate: User) => Effect.succeed(candidate.id === user.id),
      begin: () => Effect.succeed({ token: "pending-token", expiresAt: Date.now() + 60_000 }),
    };

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* service.signIn({ email: "gated@example.com", password: "gate-password" });
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
    const { SecondFactorGate } = await import("./EmailPassword.ts");
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("no-gate-password"));

    const user: User = {
      id: "user-ungated",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "ungated@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const gate = {
      required: () => Effect.succeed(false),
      begin: () => Effect.succeed({ token: "unused", expiresAt: Date.now() + 60_000 }),
    };

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* service.signIn({ email: "ungated@example.com", password: "no-gate-password" });
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
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  // Both counts are low on purpose: the test is about the rehash-on-sign-in
  // path, not the KDF cost, and a real 600,000-iteration derivation made it
  // race the 5 s test timeout under host load (#346). The production default
  // is pinned, without running the KDF, in password/Pbkdf2Defaults.test.ts.
  const OLD_PBKDF2_ITERATIONS = 1000;
  const CURRENT_PBKDF2_ITERATIONS = 2000;

  /** Build an old-style PBKDF2 hash (fewer iterations than the hasher under test, 64-byte key). */
  const makeOldPbkdf2Hash = async (password: string): Promise<string> => {
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: OLD_PBKDF2_ITERATIONS, hash: "SHA-256" },
      keyMaterial,
      64 * 8,
    );
    const key = Buffer.from(bits);
    return `pbkdf2-sha256$${OLD_PBKDF2_ITERATIONS}$${Buffer.from(salt).toString("hex")}$${key.toString("hex")}`;
  };

  it("verifies an old PBKDF2 hash and rehashes it to current params on sign-in", async () => {
    // A configured count above the old one, so the stored hash is outdated and
    // the upgrade must land on this configured count, not on the old one.
    const testContext = Context.merge(
      await makeTestContext(),
      Context.make(
        PasswordHasher,
        Password.pbkdf2Hasher({ iterations: CURRENT_PBKDF2_ITERATIONS }),
      ),
    );

    // Seed user with an old-style hash (fewer iterations, larger key).
    const oldHash = await makeOldPbkdf2Hash("migration-password");
    const user: User = {
      id: "user-migration",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "migration@example.com", true);
    passwordHashes.set(user.id, oldHash);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* service.signIn({
        email: "migration@example.com",
        password: "migration-password",
      });
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
    expect(updatedHash.startsWith(`pbkdf2-sha256$${CURRENT_PBKDF2_ITERATIONS}$`)).toBe(true);
    // ...including the current 32-byte key, not the seed's 64-byte one.
    expect(Buffer.from(updatedHash.split("$")[3]!, "hex").length).toBe(32);
  });

  it("signs in with old PBKDF2 hash after switching default hasher to scrypt via MultiAlgorithmVerifier", async () => {
    const testContext = await makeTestContext();

    const oldHash = await makeOldPbkdf2Hash("switch-password");
    const user: User = {
      id: "user-switch",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "switch@example.com", true);
    passwordHashes.set(user.id, oldHash);

    const scryptHasher = Password.scryptHasher({ cost: 1024 });
    const verifier = Password.multiAlgorithmVerifier([
      Password.pbkdf2Hasher({ iterations: 1000 }),
      scryptHasher,
    ]);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* service.signIn({ email: "switch@example.com", password: "switch-password" });
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
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "malformed@example.com", true);
    // Malformed hash: non-numeric iteration count — would previously cause a RangeError defect.
    passwordHashes.set(user.id, "pbkdf2-sha256$notanumber$aabbcc$ddeeff");

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* Effect.result(
        service.signIn({ email: "malformed@example.com", password: "any-password" }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("InvalidCredentialsError");
  });

  it("returns InvalidCredentialsError (not defect) for an excessively long password on sign-in", async () => {
    const testContext = await makeTestContext();
    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("real-password"));

    const user: User = {
      id: "user-long-pw",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(user.id, user);
    seedEmailIdentifier(user.id, "longpw@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      return yield* Effect.result(
        service.signIn({
          email: "longpw@example.com",
          // 2000 'a' chars — well over MAX_PASSWORD_BYTES (1024)
          password: "a".repeat(2000),
        }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("InvalidCredentialsError");
  });
});

describe("EmailPasswordService - dangling session protection", () => {
  // Shared in-memory stores for these tests.
  const localUsers = new Map<string, User>();
  const localIdentifierRecords = new Map<string, Identifier>();
  const localPasswordHashes = new Map<string, string>();
  const localSessions = new Map<string, Session>();

  const localIdentifierStore = memoryIdentifierStore(localIdentifierRecords);

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
  };

  const localEmailPasswordStore = {
    createUser: ({ name, attributes }: CreateUserInput) =>
      Effect.sync(() => {
        const id = `user-${localUsers.size + 1}`;
        const user: User = {
          id,
          ...(name !== undefined && { name }),
          createdAt: new Date(),
          updatedAt: new Date(),
          attributes: attributes ?? {},
        };
        localUsers.set(id, user);
        return { user, created: true };
      }),
    getPasswordHash: (userId: string) => Effect.sync(() => localPasswordHashes.get(userId) ?? null),
    clearPasswordHash: (userId: string) =>
      Effect.sync(() => void localPasswordHashes.delete(userId)),
    setPasswordHash: (userId: string, hash: string) =>
      Effect.sync(() => {
        localPasswordHashes.set(userId, hash);
      }),
  };

  const makeLocalContext = async () => {
    const sessionManager = await Effect.runPromise(
      Effect.provide(
        make({
          sessionExpiresIn: { activePeriod: 3_600_000, idlePeriod: 1_800_000 },
        }),
        Context.merge(
          Context.merge(
            Context.make(SessionStore, localSessionStore),
            Context.make(UserStore, localUserStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ).pipe(Effect.provide(Hooks.Default)),
    );
    return Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.merge(
          Context.make(EmailPasswordStore, localEmailPasswordStore),
          Context.make(PasswordHasher, Password.pbkdf2Hasher({ iterations: 1000 })),
        ),
        Context.merge(
          Context.merge(
            Context.make(UserStore, localUserStore),
            Context.make(IdentifierStore, localIdentifierStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ),
    );
  };

  beforeEach(() => {
    localUsers.clear();
    localIdentifierRecords.clear();
    localPasswordHashes.clear();
    localSessions.clear();
  });

  it("signIn succeeds and returns the session even when afterSignIn hook fails (no dangling session)", async () => {
    const ctx = await makeLocalContext();

    // First, register a user.
    const signUpResult = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* EmailPassword.make();
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
        const svc = yield* EmailPassword.make();
        return yield* svc.signIn({ email: "alice@example.com", password: "hunter2!" });
      }).pipe(
        Effect.provide(ctx),
        Effect.provide(composePlugins([failingAfterSignIn]).pipe(Layer.provide(Hooks.Default))),
      ),
    );

    // signIn must succeed (no error propagated) even though the hook failed.
    expect(signInResult.session).toBeDefined();
    expect(signInResult.identifier).toEqual({ type: "email", value: "alice@example.com" });

    // The session is live in the store — no dangling session.
    expect(signInResult.session && localSessions.has(hashToken(signInResult.session.id))).toBe(
      true,
    );
  });

  it("signUp succeeds and returns the session even when afterSignUp hook fails (no dangling session)", async () => {
    const ctx = await makeLocalContext();

    const failingAfterSignUp = makePlugin({
      afterSignUp: () => Effect.fail(new Errors.AuthError({ message: "hook boom" })),
    });

    const signUpResult = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* EmailPassword.make();
        return yield* svc.signUp({ email: "bob@example.com", password: "hunter2!" });
      }).pipe(
        Effect.provide(ctx),
        Effect.provide(composePlugins([failingAfterSignUp]).pipe(Layer.provide(Hooks.Default))),
      ),
    );

    // signUp must succeed (no error propagated) even though the hook failed.
    expect(signUpResult.session).toBeDefined();
    expect(signUpResult.identifier).toEqual({ type: "email", value: "bob@example.com" });

    // The session is live in the store — no dangling session.
    expect(signUpResult.session && localSessions.has(hashToken(signUpResult.session.id))).toBe(
      true,
    );
  });
});

describe("EmailPasswordService — anti-enumeration sign-up mode", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
  });

  it("default mode: duplicate email still returns EmailInUseError (unchanged)", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make();
      yield* service.signUp({ email: "dup@example.com", password: "strong-password-123" });
      return yield* Effect.result(
        service.signUp({ email: "DUP@Example.com", password: "another-strong-pw" }),
      );
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailInUseError");
  });

  it("antiEnumeration mode: fresh and duplicate sign-ups are indistinguishable", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make({ antiEnumeration: true });
      const fresh = yield* service.signUp({
        email: "shape@example.com",
        password: "strong-password-123",
        name: "Fresh User",
      });
      const duplicate = yield* service.signUp({
        email: "Shape@Example.com",
        password: "different-strong-pw",
        name: "Attacker Supplied Name",
      });
      return { fresh, duplicate };
    });

    const { fresh, duplicate } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // Neither branch creates a session — no Set-Cookie on either at the
    // HTTP layer, so "a session came back" can't itself be the oracle.
    expect(fresh.session).toBeUndefined();
    expect(duplicate.session).toBeUndefined();

    // Same body shape: same set of top-level fields on both branches.
    expect(Arr.sort(Object.keys(duplicate), Order.String)).toEqual(
      Arr.sort(Object.keys(fresh), Order.String),
    );
    expect(fresh.method).toBe("email-password");
    expect(duplicate.method).toBe("email-password");
    expect(duplicate.identifier).toEqual({ type: "email", value: "shape@example.com" });

    // The duplicate branch never touches the real account: different user
    // id, and its fields reflect only what THIS request submitted.
    expect(duplicate.user.id).not.toBe(fresh.user.id);
    expect(duplicate.user.name).toBe("Attacker Supplied Name");

    // The real, pre-existing account is untouched (no second identifier or
    // password write landed against it).
    const identifiersForEmail = Array.from(identifierRecords.values()).filter(
      (identifier) => identifier.type === "email" && identifier.value === "shape@example.com",
    );
    expect(identifiersForEmail).toHaveLength(1);
    expect(identifiersForEmail[0]?.userId).toBe(fresh.user.id);
  });

  it("antiEnumeration mode: the duplicate branch still hashes the submitted password", async () => {
    let hashCalls = 0;
    const realHasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const spyHasher: typeof PasswordHasher.Service = {
      algorithm: realHasher.algorithm,
      hash: (password) => {
        hashCalls++;
        return realHasher.hash(password);
      },
      verify: (password, hash) => realHasher.verify(password, hash),
    };

    const sessionManager = await Effect.runPromise(
      Effect.provide(
        make(sessionConfig),
        Context.merge(
          Context.merge(
            Context.make(SessionStore, sessionStore),
            Context.make(UserStore, userStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ).pipe(Effect.provide(Hooks.Default)),
    );

    const ctx = Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.merge(
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.make(PasswordHasher, spyHasher),
        ),
        Context.merge(
          Context.merge(
            Context.make(UserStore, userStore),
            Context.make(IdentifierStore, identifierStore),
          ),
          Context.make(Crypto.Crypto, PlatformCrypto.instance),
        ),
      ),
    );

    const program = Effect.gen(function* () {
      const service = yield* EmailPassword.make({ antiEnumeration: true });
      yield* service.signUp({ email: "hash@example.com", password: "strong-password-123" });
      return yield* service.signUp({ email: "Hash@Example.com", password: "another-strong-pw" });
    });

    await Effect.runPromise(Effect.provide(program, ctx).pipe(Effect.provide(Hooks.Default)));

    // One hash for the fresh branch, one for the duplicate branch.
    expect(hashCalls).toBe(2);
  });

  it("antiEnumeration mode: the stand-in's id comes from the store's newUserId", async () => {
    const minted: string[] = [];
    const store: typeof EmailPasswordStore.Service = {
      ...emailPasswordStore,
      newUserId: () =>
        Effect.sync(() => {
          const id = `user-${users.size + 1 + minted.length}`;
          minted.push(id);
          return id;
        }),
    };
    const signUpTwice = (testStore: typeof EmailPasswordStore.Service) =>
      Effect.gen(function* () {
        const testContext = yield* Effect.tryPromise(() => makeTestContext(testStore)).pipe(
          Effect.orDie,
        );
        const service = yield* EmailPassword.make({ antiEnumeration: true }).pipe(
          Effect.provide(testContext),
        );
        const signUp = (password: string) =>
          service.signUp({ email: "mint@example.com", password }).pipe(Effect.provide(testContext));
        const fresh = yield* signUp("strong-password-123");
        const duplicate = yield* signUp("another-strong-pw");
        return { fresh, duplicate };
      }).pipe(Effect.provide(Hooks.Default));

    const minting = await Effect.runPromise(signUpTwice(store));
    expect(minting.fresh.user.id).toBe("user-1");
    // Minted by the store, so it has the shape of the store's own ids, and
    // it names no user.
    expect(minted).toEqual([minting.duplicate.user.id]);
    expect(minting.duplicate.user.id).toMatch(/^user-\d+$/);
    expect(users.has(minting.duplicate.user.id)).toBe(false);
    // One timestamp for both, as a store's `createUser` sets them.
    expect(minting.duplicate.user.updatedAt).toBe(minting.duplicate.user.createdAt);

    // Without the seam the stand-in's id is a random UUID.
    users.clear();
    identifierRecords.clear();
    const fallback = await Effect.runPromise(signUpTwice(emailPasswordStore));
    expect(fallback.duplicate.user.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  // The address is found taken at the insert rather than at the pre-check.
  // Each store seeds the owner's row from inside `createUser`, after the
  // sign-up's pre-check found the address free.
  const owner: User = {
    id: "owner",
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  };
  const seedOwner = (email: string) => {
    users.set(owner.id, owner);
    seedEmailIdentifier(owner.id, email, false);
    passwordHashes.set(owner.id, "owner-hash");
  };
  const takenAtInsert: ReadonlyArray<{
    readonly name: string;
    readonly store: (email: string) => typeof EmailPasswordStore.Service;
  }> = [
    {
      name: "a writer that returns the existing owner with created: false",
      store: (email) => ({
        ...emailPasswordStore,
        createUser: () =>
          Effect.sync(() => {
            seedOwner(email);
            return { user: owner, created: false };
          }),
      }),
    },
    {
      name: "a plain insert that loses the identifier claim to a concurrent sign-up",
      store: (email) => ({
        ...emailPasswordStore,
        createUser: (input) =>
          Effect.gen(function* () {
            seedOwner(email);
            return yield* emailPasswordStore.createUser(input);
          }),
      }),
    },
  ];

  it.each(takenAtInsert)(
    "antiEnumeration mode: $name answers as the pre-check duplicate does",
    async ({ store }) => {
      let hashCalls = 0;
      const realHasher = Password.pbkdf2Hasher({ iterations: 1000 });
      const spyHasher: typeof PasswordHasher.Service = {
        algorithm: realHasher.algorithm,
        hash: (password) => {
          hashCalls++;
          return realHasher.hash(password);
        },
        verify: (password, hash) => realHasher.verify(password, hash),
      };
      const signUp = (testStore: typeof EmailPasswordStore.Service, email: string) =>
        Effect.gen(function* () {
          const testContext = yield* Effect.tryPromise(() =>
            makeTestContext(testStore, spyHasher),
          ).pipe(Effect.orDie);
          const service = yield* EmailPassword.make({ antiEnumeration: true }).pipe(
            Effect.provide(testContext),
          );
          return yield* service
            .signUp({ email, password: "attacker-password-123", name: "Attacker" })
            .pipe(Effect.provide(testContext));
        }).pipe(Effect.provide(Hooks.Default));

      // The reference answer: the pre-check finds the address taken.
      seedEmailIdentifier("someone", "precheck@example.com", false);
      const precheck = await Effect.runPromise(signUp(emailPasswordStore, "precheck@example.com"));
      const precheckHashes = hashCalls;

      const result = await Effect.runPromise(
        signUp(store("victim@example.com"), "victim@example.com"),
      );

      // Same shape as the pre-check duplicate, with no session.
      expect(result.session).toBeUndefined();
      expect(Arr.sort(Object.keys(result), Order.String)).toEqual(
        Arr.sort(Object.keys(precheck), Order.String),
      );
      expect(Arr.sort(Object.keys(result.user), Order.String)).toEqual(
        Arr.sort(Object.keys(precheck.user), Order.String),
      );
      expect(result.identifier).toEqual({ type: "email", value: "victim@example.com" });
      expect(result.method).toBe(precheck.method);
      expect(result.user.id).not.toBe(owner.id);
      // The submitted password is hashed, as on the pre-check branch.
      expect(precheckHashes).toBe(1);
      expect(hashCalls).toBe(2);
      // Nothing landed on the owner.
      expect(passwordHashes.get(owner.id)).toBe("owner-hash");
      expect(sessions.size).toBe(0);
      expect(
        Array.from(identifierRecords.values())
          .filter((identifier) => identifier.value === "victim@example.com")
          .map(({ userId, verified }) => ({ userId, verified })),
      ).toEqual([{ userId: owner.id, verified: false }]);
    },
  );
});
