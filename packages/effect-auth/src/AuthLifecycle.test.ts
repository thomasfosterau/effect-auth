import { beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, Crypto, Effect, Layer } from "effect";
import { Hooks } from "./Hooks.ts";
import { AuthError, EmailVerificationError } from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import * as AuthLifecycle from "./AuthLifecycle.ts";
import {
  type EmailVerification,
  type EmailVerificationConfig,
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

const makeTestContext = async (
  emailPasswordConfig: EmailPasswordConfig = {},
  options: {
    /** Replaces the verification `sendEmail`, which by default records into `sentEmails`. */
    readonly sendEmail?: EmailVerificationConfig["sendEmail"] | undefined;
    /** The `Hooks` the verification service runs. Default `Hooks.Default`. */
    readonly hooks?: Layer.Layer<Hooks> | undefined;
  } = {},
) => {
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
        sendEmail:
          options.sendEmail ??
          ((email, token) =>
            Effect.sync(() => {
              sentEmails.push({ email, token });
            })),
      }),
      Context.merge(Context.make(EmailVerificationStore, emailVerificationStore), cryptoContext),
    ).pipe(Effect.provide(options.hooks ?? Hooks.Default)),
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

  it("a sign-up for an address held unverified answers with the submitted address", async () => {
    const testContext = await makeTestContext();

    // An earlier sign-up for the address whose verification never completed.
    const pending: User = {
      id: "user-pending",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(pending.id, pending);
    addEmailIdentifier(pending.id, "pending@example.com", false);

    const program = Effect.gen(function* () {
      const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
      return yield* service.signUp({
        email: "  Pending@Example.com ",
        password: "strong-password-123",
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // The recovered branch answers with the held user and the address it was
    // made with (normalized), which the HTTP sign-up response reports as the
    // user's `email`.
    expect(result.user.id).toBe(pending.id);
    expect(result.identifier).toEqual({ type: "email", value: "pending@example.com" });
    expect(result.needsEmailVerification).toBe(true);
    expect(result.session).toBeUndefined();
    expect(sentEmails.map((sent) => sent.email)).toEqual(["pending@example.com"]);
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

describe("AuthLifecycleService.signUp for a held address under antiEnumeration (#422)", () => {
  const HELD = "held@example.com";
  const FRESH = "fresh@example.com";
  const PASSWORD = "strong-password-123";

  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
    verifications.clear();
    sentEmails.splice(0, sentEmails.length);
  });

  /** The address's holder: a user who signed up with HELD earlier. */
  const seedHolder = (verified: boolean): User => {
    const holder: User = {
      id: "user-holder",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    users.set(holder.id, holder);
    addEmailIdentifier(holder.id, HELD, verified);
    return holder;
  };

  /** A fresh sign-up for FRESH, then one for HELD, through one service. */
  const signUpFreshThenHeld = (
    config: AuthLifecycle.AuthLifecycleConfig,
    context: Awaited<ReturnType<typeof makeTestContext>>,
  ) =>
    Effect.gen(function* () {
      const service = yield* AuthLifecycle.make(config);
      const fresh = yield* service.signUp({ email: FRESH, password: PASSWORD, name: "Probe" });
      const held = yield* service.signUp({ email: HELD, password: PASSWORD, name: "Probe" });
      return { fresh, held };
    }).pipe(Effect.provide(context), Effect.provide(Hooks.Default));

  /** A `Hooks` layer recording the user id each verification hook sees. */
  const recordingVerificationHooks = (calls: Array<readonly [string, string]>) =>
    Layer.effect(
      Hooks,
      Effect.gen(function* () {
        const base = yield* Hooks;
        return {
          ...base,
          beforeCreateVerification: (args) =>
            Effect.sync(() => void calls.push(["before", args.userId])).pipe(Effect.as(args)),
          afterCreateVerification: (args) =>
            Effect.sync(() => void calls.push(["after", args.userId])).pipe(Effect.as(args)),
        } satisfies typeof Hooks.Service;
      }),
    ).pipe(Layer.provide(Hooks.Default));

  it.each([
    { holder: "verified", verified: true },
    { holder: "unverified", verified: false },
  ])(
    "the $holder holder gets the existing-account notice, and no verification record or link",
    async ({ verified }) => {
      const holder = seedHolder(verified);
      const hookCalls: Array<readonly [string, string]> = [];
      const context = await makeTestContext(
        { antiEnumeration: true },
        { hooks: recordingVerificationHooks(hookCalls) },
      );
      const notices: string[] = [];

      const { fresh, held } = await Effect.runPromise(
        signUpFreshThenHeld(
          {
            requireEmailVerification: true,
            sendExistingAccountNotice: (email) => Effect.sync(() => void notices.push(email)),
          },
          context,
        ),
      );

      // The held address is answered by a stand-in no row backs, in the shape
      // a fresh sign-up gets.
      expect(held.user.id).not.toBe(holder.id);
      expect(users.has(held.user.id)).toBe(false);
      expect(Object.keys(held)).toEqual(Object.keys(fresh));
      expect(held.identifier).toEqual({ type: "email", value: HELD });
      expect(held.needsEmailVerification).toBe(true);
      expect(fresh.needsEmailVerification).toBe(true);
      expect(held.session).toBeUndefined();
      expect(fresh.session).toBeUndefined();

      // One verification record, for the fresh user; none for the stand-in.
      const records = [...verifications.values()];
      expect(records.map((record) => [record.userId, record.email])).toEqual([
        [fresh.user.id, FRESH],
      ]);
      expect(records.every((record) => users.has(record.userId))).toBe(true);
      // The verification hooks never see the stand-in's id.
      expect(hookCalls).toEqual([
        ["before", fresh.user.id],
        ["after", fresh.user.id],
      ]);

      // The holder gets the notice and no link; the fresh address gets its link.
      expect(notices).toEqual([HELD]);
      expect(sentEmails.map((sent) => sent.email)).toEqual([FRESH]);

      // That link verifies the fresh user.
      const verifiedResult = await Effect.runPromise(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
          return yield* service.verifyEmail({ token: sentEmails[0]!.token });
        }).pipe(Effect.provide(context), Effect.provide(Hooks.Default)),
      );
      expect(verifiedResult.user.id).toBe(fresh.user.id);
    },
  );

  it("without sendExistingAccountNotice, the holder is sent nothing", async () => {
    seedHolder(true);
    const context = await makeTestContext({ antiEnumeration: true });

    const { held } = await Effect.runPromise(
      signUpFreshThenHeld({ requireEmailVerification: true }, context),
    );

    expect(held.needsEmailVerification).toBe(true);
    expect(sentEmails.map((sent) => sent.email)).toEqual([FRESH]);
    expect([...verifications.values()].map((record) => record.email)).toEqual([FRESH]);
  });

  it("with verification off, neither sign-up sends anything", async () => {
    seedHolder(true);
    const context = await makeTestContext({ antiEnumeration: true });
    const notices: string[] = [];

    await Effect.runPromise(
      signUpFreshThenHeld(
        { sendExistingAccountNotice: (email) => Effect.sync(() => void notices.push(email)) },
        context,
      ),
    );

    expect(notices).toEqual([]);
    expect(sentEmails).toEqual([]);
    expect(verifications.size).toBe(0);
  });

  it("a failed notice fails the sign-up as a failed verification send does", async () => {
    seedHolder(true);
    const context = await makeTestContext(
      { antiEnumeration: true },
      {
        sendEmail: () =>
          Effect.fail(new EmailVerificationError({ message: "provider down (verification)" })),
      },
    );

    const errors = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* AuthLifecycle.make({
          requireEmailVerification: true,
          sendExistingAccountNotice: () =>
            Effect.fail(new AuthError({ message: "provider down (notice)" })),
        });
        const fresh = yield* Effect.flip(service.signUp({ email: FRESH, password: PASSWORD }));
        const held = yield* Effect.flip(service.signUp({ email: HELD, password: PASSWORD }));
        return { fresh, held };
      }).pipe(Effect.provide(context), Effect.provide(Hooks.Default)),
    );

    const describeError = (error: { readonly _tag: string; readonly message: string }) => ({
      tag: error._tag,
      message: error.message.replace(FRESH, "<address>").replace(HELD, "<address>"),
    });
    expect(describeError(errors.held)).toEqual(describeError(errors.fresh));
    expect(errors.held._tag).toBe("EmailVerificationError");
    expect(errors.held.message).toBe(`Failed to send verification email to ${HELD}`);
  });
});
