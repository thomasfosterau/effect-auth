import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, Crypto, Effect } from "effect";
import { Hooks } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as AuthLifecycle from "./AuthLifecycle.ts";
import {
  type EmailVerification,
  EmailVerificationStore,
  EmailVerificationService,
} from "./email/EmailVerification.ts";
import * as EmailVerificationModule from "./email/EmailVerification.ts";
import {
  type Identifier,
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
} from "./Identifier.ts";
import { PasswordHasher } from "./password/Password.ts";
import * as Password from "./password/Password.ts";
import { make, SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { UserServiceStore, UserService } from "./User.ts";
import * as UserModule from "./User.ts";
import type { Session, SessionConfig, User } from "./Types.ts";
import {
  EmailPasswordService,
  EmailPasswordStore,
  type CreateUserInput,
  type EmailPasswordConfig,
} from "./email/EmailPassword.ts";
import * as EmailPassword from "./email/EmailPassword.ts";

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
const sessions = new Map<string, Session>();
const verifications = new Map<string, EmailVerification>();
const sentEmails: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

/** Seed an email identifier the way the store would persist it. */
const addEmailIdentifier = (userId: string, email: string, verified: boolean) => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    ...(verified ? { verifiedAt: new Date() } : {}),
  });
  identifierRecords.set(identifier.id, identifier);
};

const findEmailIdentifier = (email: string): Identifier | null =>
  Array.from(identifierRecords.values()).find(
    (identifier) => identifier.type === "email" && identifier.value === email,
  ) ?? null;

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
  createUser: ({ name, attributes }: CreateUserInput) =>
    Effect.sync(() => {
      const id = `user-${users.size + 1}`;
      const user: User = {
        id,
        ...(name !== undefined && { name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: attributes ?? {},
      };
      users.set(id, user);
      return { user, created: true };
    }),

  getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),

  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      passwordHashes.set(userId, hash);
    }),
};

const emailVerificationStore = {
  create: (verification: EmailVerification) =>
    Effect.sync(() => {
      verifications.set(verification.token, verification);
      return verification;
    }),

  get: (token: string) => Effect.sync(() => verifications.get(token) ?? null),

  delete: (token: string) =>
    Effect.sync(() => {
      verifications.delete(token);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [token, verification] of verifications.entries()) {
        if (verification.userId === userId) {
          verifications.delete(token);
        }
      }
    }),
};

const userServiceStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),

  update: (user: User) =>
    Effect.sync(() => {
      users.set(user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      users.delete(userId);
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

const makeTestContext = async (emailPasswordConfig: EmailPasswordConfig = {}) => {
  const hasher = Password.pbkdf2Hasher({ iterations: 1000 });

  const cryptoContext = Context.make(Crypto.Crypto, PlatformCrypto.instance);

  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        cryptoContext,
      ),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  const emailVerificationService = await Effect.runPromise(
    Effect.provide(
      EmailVerificationModule.make({
        sendEmail: (email, token) =>
          Effect.sync(() => {
            sentEmails.push({ email, token });
          }),
      }),
      Context.merge(Context.make(EmailVerificationStore, emailVerificationStore), cryptoContext),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  const emailPasswordService = await Effect.runPromise(
    Effect.provide(
      EmailPassword.make(emailPasswordConfig),
      Context.merge(
        Context.merge(
          Context.make(EmailPasswordStore, emailPasswordStore),
          Context.make(IdentifierStore, identifierStore),
        ),
        Context.merge(
          Context.make(UserStore, userStore),
          Context.merge(
            Context.make(PasswordHasher, hasher),
            Context.make(SessionService, sessionManager),
          ),
        ),
      ),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  const userService = await Effect.runPromise(
    Effect.provide(UserModule.make(), Context.make(UserServiceStore, userServiceStore)),
  );

  return Context.merge(
    cryptoContext,
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(
        Context.make(SessionStore, sessionStore),
        Context.merge(
          Context.merge(
            Context.make(UserStore, userStore),
            Context.make(IdentifierStore, identifierStore),
          ),
          Context.merge(
            Context.make(EmailPasswordService, emailPasswordService),
            Context.merge(
              Context.make(EmailPasswordStore, emailPasswordStore),
              Context.merge(
                Context.make(EmailVerificationStore, emailVerificationStore),
                Context.merge(
                  Context.make(EmailVerificationService, emailVerificationService),
                  Context.merge(
                    Context.make(UserServiceStore, userServiceStore),
                    Context.merge(
                      Context.make(UserService, userService),
                      Context.make(PasswordHasher, hasher),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    ),
  );
};

describe("AuthLifecycleService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
    verifications.clear();
    sentEmails.splice(0, sentEmails.length);
  });

  it("should sign up and require verification when configured", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* AuthLifecycle.make({
        requireEmailVerification: true,
      });

      return yield* service.signUp({
        email: "new@example.com",
        password: "strong-password-123",
        name: "New User",
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.needsEmailVerification).toBe(true);
    expect(result.session).toBeUndefined();
    expect(sentEmails.length).toBe(1);
    expect(sentEmails[0]?.email).toBe("new@example.com");
    // Sign-up claims an (unverified) email identifier for the new user.
    const identifier = findEmailIdentifier("new@example.com");
    expect(identifier?.userId).toBe(result.user.id);
    expect(identifier?.verified).toBe(false);
  });

  it("should return verification-needed on sign-in and resend when enabled", async () => {
    const testContext = await makeTestContext({ requireEmailVerification: true });

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("password-123"));

    const user: User = {
      id: "user-sign-in-unverified",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    addEmailIdentifier(user.id, "signin@example.com", false);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* AuthLifecycle.make({
        requireEmailVerification: true,
        sendOnSignIn: true,
      });

      return yield* service.signIn({
        email: "signin@example.com",
        password: "password-123",
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.needsEmailVerification).toBe(true);
    expect(result.session).toBeUndefined();
    expect(result.user.id).toBe(user.id);
    expect(sentEmails.length).toBe(1);
    expect(sentEmails[0]?.email).toBe("signin@example.com");
  });

  it("should verify token and auto sign in", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-verify",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    addEmailIdentifier(user.id, "verify@example.com", false);

    const token = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const verification = yield* EmailVerificationService;
          const created = yield* verification.createVerification(user.id, "verify@example.com");
          return created.token;
        }),
        testContext,
      ).pipe(Effect.provide(Hooks.Default)),
    );

    const program = Effect.gen(function* () {
      const service = yield* AuthLifecycle.make({
        autoSignInAfterVerification: true,
      });
      return yield* service.verifyEmail({ token });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session).toBeDefined();
    expect(result.needsEmailVerification).toBe(false);
    // The email identifier was promoted to verified.
    expect(findEmailIdentifier("verify@example.com")?.verified).toBe(true);
  });

  it("should sign in verified users normally", async () => {
    const testContext = await makeTestContext();

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("verified-password-123"));

    const user: User = {
      id: "user-verified",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    users.set(user.id, user);
    addEmailIdentifier(user.id, "verified@example.com", true);
    passwordHashes.set(user.id, hashResult.hash);

    const program = Effect.gen(function* () {
      const service = yield* AuthLifecycle.make({
        requireEmailVerification: true,
      });

      return yield* service.signIn({
        email: "verified@example.com",
        password: "verified-password-123",
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.needsEmailVerification).toBe(false);
    expect(result.session).toBeDefined();
    expect(result.user.id).toBe(user.id);
  });
});
