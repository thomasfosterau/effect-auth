import { assert, beforeEach, describe, expect, it } from "vite-plus/test";
import { Context, DateTime, Effect, Layer, MutableHashMap, Result, Struct } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { SecureRandom } from "effect/crypto";
import { type DeliveryFailure, Hooks, makePlugin } from "./Hooks.ts";
import { AuthError, EmailVerificationError, InvalidCredentialsError } from "./Errors.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { RateLimitStore } from "./RateLimit.ts";
import { memoryRateLimitStore } from "./testing/MemoryStores.ts";
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
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";
import { ApiKeyStore } from "./ApiKey.ts";
import { MultiFactorStore } from "./multifactor/MultiFactor.ts";
import { memoryApiKeyStore, memoryMultiFactorStore } from "./testing/MemoryStores.ts";

/** The no-op hooks, with the detached sends run in place so a test reads them on return. */
const TestHooks = Layer.merge(Hooks.Default, inlineDeliveryScheduler);

const users = MutableHashMap.empty<string, User>();
const identifierRecords = MutableHashMap.empty<string, Identifier>();
const passwordHashes = MutableHashMap.empty<string, string>();
const sessions = MutableHashMap.empty<string, Session>();
const verifications = MutableHashMap.empty<string, EmailVerification>();
const sentEmails: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

/** Seed an email identifier the way the store would persist it. */
const addEmailIdentifier = (userId: string, email: string, verified: boolean) => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    ...(verified ? { verifiedAt: DateTime.toDateUtc(DateTime.nowUnsafe()) } : {}),
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifierRecords, identifier.id, identifier);
};

const findEmailIdentifier = (email: string): Identifier | null =>
  Array.from(MutableHashMap.values(identifierRecords)).find(
    (identifier) => identifier.type === "email" && identifier.value === email,
  ) ?? null;

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

const emailPasswordStore = {
  createUser: ({ name, attributes }: CreateUserInput) =>
    Effect.sync(() => {
      const id = `user-${MutableHashMap.size(users) + 1}`;
      const user: User = {
        id,
        ...(name !== undefined && { name }),
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: attributes ?? {},
      };
      MutableHashMap.set(users, id, user);
      return { user, created: true };
    }),

  getPasswordHash: (userId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(passwordHashes, userId))),

  clearPasswordHash: (userId: string) =>
    Effect.sync(() => void MutableHashMap.remove(passwordHashes, userId)),
  setPasswordHash: (userId: string, hash: string) =>
    Effect.sync(() => {
      MutableHashMap.set(passwordHashes, userId, hash);
    }),
};

const emailVerificationStore = {
  create: (verification: EmailVerification) =>
    Effect.sync(() => {
      MutableHashMap.set(verifications, verification.token, verification);
      return verification;
    }),

  get: (token: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(verifications, token))),

  delete: (token: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(verifications, token);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(verifications, (verification, token) => {
        if (verification.userId === userId) {
          MutableHashMap.remove(verifications, token);
        }
      });
    }),

  getLatestByUserId: (userId: string) =>
    Effect.sync(() => {
      let latest: EmailVerification | null = null;
      MutableHashMap.forEach(verifications, (v) => {
        if (v.userId === userId && (latest === null || v.createdAt > latest.createdAt)) {
          latest = v;
        }
      });
      return latest;
    }),
};

const userServiceStore = {
  get: (userId: string) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),

  update: (user: User) =>
    Effect.sync(() => {
      MutableHashMap.set(users, user.id, user);
      return user;
    }),

  delete: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(users, userId);
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
    /** The `Hooks` the verification and email-password services run. Default `Hooks.Default`. */
    readonly hooks?: Layer.Layer<Hooks> | undefined;
    /** The `UserService` config (built after, and not seen by, `EmailPasswordService`). */
    readonly userService?: UserModule.UserServiceConfig | undefined;
    /** The verification resends' `resendCooldown`. Default: the service's. */
    readonly resendCooldown?: number | undefined;
  } = {},
) => {
  const hasher = Password.pbkdf2Hasher({ iterations: 1000 });

  const cryptoContext = Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance);

  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        cryptoContext,
      ),
    ).pipe(Effect.provide(TestHooks)),
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
        ...(options.resendCooldown !== undefined && { resendCooldown: options.resendCooldown }),
      }),
      Context.add(
        Context.merge(Context.make(EmailVerificationStore, emailVerificationStore), cryptoContext),
        RateLimitStore,
        memoryRateLimitStore(),
      ),
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
    ).pipe(Effect.provide(options.hooks ?? Hooks.Default)),
  );

  const userService = await Effect.runPromise(
    Effect.provide(
      UserModule.make(options.userService),
      Context.make(UserServiceStore, userServiceStore),
    ),
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
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(verifications);
    sentEmails.splice(0, sentEmails.length);
  });

  it("should sign up and require verification when configured", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            requireEmailVerification: true,
          });

          return yield* service.signUp({
            email: "new@example.com",
            password: "strong-password-123",
            name: "New User",
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
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

  it("a sign-up for an address held unverified answers with none of the holder's data (#421)", async () => {
    const testContext = await makeTestContext();

    // An earlier sign-up for the address whose verification never completed,
    // with a profile of its own.
    const pending: User = {
      id: "user-pending",
      name: "Pending Holder",
      image: "https://example.com/pending.png",
      createdAt: DateTime.toDateUtc(DateTime.makeUnsafe("2020-01-01T00:00:00Z")),
      updatedAt: DateTime.toDateUtc(DateTime.makeUnsafe("2021-01-01T00:00:00Z")),
      attributes: { plan: "enterprise", secret: "holder-only" },
    };
    MutableHashMap.set(users, pending.id, pending);
    addEmailIdentifier(pending.id, "pending@example.com", false);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
          return yield* service.signUp({
            email: "  Pending@Example.com ",
            password: "strong-password-123",
            name: "Probe",
            attributes: { plan: "free" },
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    // The answer is a stand-in built from the caller's own input: a fresh id,
    // the submitted name and attributes, no image, and one new timestamp.
    expect(result.user.id).not.toBe(pending.id);
    expect(result.user.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(result.user.name).toBe("Probe");
    expect(result.user.image).toBeUndefined();
    expect(result.user.attributes).toEqual({ plan: "free" });
    expect(result.user.createdAt).toEqual(result.user.updatedAt);
    expect(result.user.createdAt.getTime()).toBeGreaterThan(pending.updatedAt.getTime());
    expect(result.identifier).toEqual({ type: "email", value: "pending@example.com" });
    expect(result.needsEmailVerification).toBe(true);
    expect(result.session).toBeUndefined();
    // The holder's record is untouched, and the verification is re-issued to
    // the holder, not to the stand-in.
    expect(Option.getOrUndefined(MutableHashMap.get(users, pending.id))).toEqual(pending);
    expect(sentEmails.map((sent) => sent.email)).toEqual(["pending@example.com"]);
    expect(Arr.fromIterable(MutableHashMap.values(verifications)).map((v) => v.userId)).toEqual([
      pending.id,
    ]);
  });

  it("a sign-up for an address held verified fails with EmailInUseError", async () => {
    const testContext = await makeTestContext();

    const holder: User = {
      id: "user-holder",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, holder.id, holder);
    addEmailIdentifier(holder.id, "held@example.com", true);

    const error = await Effect.runPromise(
      Effect.flip(
        Effect.provide(
          Effect.gen(function* () {
            const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
            return yield* service.signUp({
              email: "held@example.com",
              password: "strong-password-123",
            });
          }),
          testContext,
        ),
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(error._tag).toBe("EmailInUseError");
    expect(sentEmails).toEqual([]);
  });

  it("should return verification-needed on sign-in and resend when enabled", async () => {
    const testContext = await makeTestContext({ requireEmailVerification: true });

    const hasher = Password.pbkdf2Hasher({ iterations: 1000 });
    const hashResult = await Effect.runPromise(hasher.hash("password-123"));

    const user: User = {
      id: "user-sign-in-unverified",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, "signin@example.com", false);
    MutableHashMap.set(passwordHashes, user.id, hashResult.hash);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            requireEmailVerification: true,
            sendOnSignIn: true,
          });

          return yield* service.signIn({
            email: "signin@example.com",
            password: "password-123",
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result.needsEmailVerification).toBe(true);
    expect(result.session).toBeUndefined();
    expect(result.user.id).toBe(user.id);
    expect(sentEmails.length).toBe(1);
    expect(sentEmails[0]?.email).toBe("signin@example.com");
  });

  // The default 60 s resend cooldown (#682): a second sign-in and a duplicate
  // sign-up inside it answer as before and send nothing more.
  it("holds the sign-in and sign-up resends back inside the cooldown, answering alike (#682)", async () => {
    const testContext = await makeTestContext({ requireEmailVerification: true });
    const hashResult = await Effect.runPromise(
      Password.pbkdf2Hasher({ iterations: 1000 }).hash("password-123"),
    );
    MutableHashMap.set(users, "user-cooldown", {
      id: "user-cooldown",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-cooldown", "cooldown@example.com", false);
    MutableHashMap.set(passwordHashes, "user-cooldown", hashResult.hash);

    const results = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            requireEmailVerification: true,
            sendOnSignIn: true,
          });
          const signIn = service.signIn({
            email: "cooldown@example.com",
            password: "password-123",
          });
          return [
            yield* signIn,
            yield* signIn,
            yield* service.signUp({ email: "cooldown@example.com", password: "password-456" }),
          ];
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(results.map((result) => result.needsEmailVerification)).toEqual([true, true, true]);
    expect(sentEmails.map((sent) => sent.email)).toEqual(["cooldown@example.com"]);
    expect(MutableHashMap.size(verifications)).toBe(1);
  });

  // The per-recipient cap (#684): past five resends in the hour, a sign-in and
  // a duplicate sign-up answer as before and send nothing more.
  it("holds the sign-in and sign-up resends back past the send cap, answering alike (#684)", async () => {
    const testContext = await makeTestContext(
      { requireEmailVerification: true },
      { resendCooldown: 0 },
    );
    const hashResult = await Effect.runPromise(
      Password.pbkdf2Hasher({ iterations: 1000 }).hash("password-123"),
    );
    MutableHashMap.set(users, "user-capped", {
      id: "user-capped",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-capped", "capped@example.com", false);
    MutableHashMap.set(passwordHashes, "user-capped", hashResult.hash);

    const results = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            requireEmailVerification: true,
            sendOnSignIn: true,
          });
          const signIn = service.signIn({ email: "capped@example.com", password: "password-123" });
          const signUp = service.signUp({ email: "capped@example.com", password: "password-456" });
          return yield* Effect.all([signIn, signIn, signIn, signIn, signIn, signIn, signUp], {
            concurrency: 1,
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(results.map((result) => result.needsEmailVerification)).toEqual(
      Arr.makeBy(7, () => true),
    );
    expect(sentEmails.map((sent) => sent.email)).toEqual(Arr.makeBy(5, () => "capped@example.com"));
  });

  it("should verify token and auto sign in", async () => {
    const testContext = await makeTestContext();

    const user: User = {
      id: "user-verify",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, "verify@example.com", false);

    const token = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const verification = yield* EmailVerificationService;
          const created = yield* verification.createVerification(user.id, "verify@example.com");
          return created.token;
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            autoSignInAfterVerification: true,
          });
          return yield* service.verifyEmail({ token });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
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
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };

    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, "verified@example.com", true);
    MutableHashMap.set(passwordHashes, user.id, hashResult.hash);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({
            requireEmailVerification: true,
          });

          return yield* service.signIn({
            email: "verified@example.com",
            password: "verified-password-123",
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
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
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(verifications);
    sentEmails.splice(0, sentEmails.length);
  });

  /** The address's holder: a user who signed up with HELD earlier. */
  const seedHolder = (verified: boolean): User => {
    const holder: User = {
      id: "user-holder",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, holder.id, holder);
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
    }).pipe(Effect.provide(context), Effect.provide(TestHooks));

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
      expect(MutableHashMap.has(users, held.user.id)).toBe(false);
      expect(Struct.keys(held)).toEqual(Struct.keys(fresh));
      expect(held.identifier).toEqual({ type: "email", value: HELD });
      expect(held.needsEmailVerification).toBe(true);
      expect(fresh.needsEmailVerification).toBe(true);
      expect(held.session).toBeUndefined();
      expect(fresh.session).toBeUndefined();

      // One verification record, for the fresh user; none for the stand-in.
      const records = Arr.fromIterable(MutableHashMap.values(verifications));
      expect(records.map((record) => [record.userId, record.email])).toEqual([
        [fresh.user.id, FRESH],
      ]);
      expect(records.every((record) => MutableHashMap.has(users, record.userId))).toBe(true);
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
          const [sent] = sentEmails;
          assert(sent !== undefined);
          return yield* service.verifyEmail({ token: sent.token });
        }).pipe(Effect.provide(context), Effect.provide(TestHooks)),
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
    expect(
      Arr.fromIterable(MutableHashMap.values(verifications)).map((record) => record.email),
    ).toEqual([FRESH]);
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
    expect(MutableHashMap.size(verifications)).toBe(0);
  });

  it("a failed send fails neither answer; both failures reach afterDeliveryFailure (#196)", async () => {
    seedHolder(true);
    const failures: DeliveryFailure[] = [];
    const recording = makePlugin({
      afterDeliveryFailure: Hooks.tap((failure: DeliveryFailure) =>
        Effect.sync(() => void failures.push(failure)),
      ),
    }).pipe(Layer.provide(Hooks.Default));
    const context = await makeTestContext(
      { antiEnumeration: true },
      {
        sendEmail: () =>
          Effect.fail(new EmailVerificationError({ message: "provider down (verification)" })),
        hooks: recording,
      },
    );

    const results = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* AuthLifecycle.make({
          requireEmailVerification: true,
          sendExistingAccountNotice: () =>
            Effect.fail(new AuthError({ message: "provider down (notice)" })),
        });
        const fresh = yield* service.signUp({ email: FRESH, password: PASSWORD });
        const held = yield* service.signUp({ email: HELD, password: PASSWORD });
        return { fresh, held };
      }).pipe(
        Effect.provide(context),
        Effect.provide(Layer.merge(recording, inlineDeliveryScheduler)),
      ),
    );

    expect(results.fresh.needsEmailVerification).toBe(true);
    expect(results.held.needsEmailVerification).toBe(true);
    expect(failures.map((failure) => failure.purpose).toSorted()).toEqual([
      "email-verification",
      "existing-account",
    ]);
  });
});

describe("AuthLifecycleService.verifyEmail on an address's first proof (#425)", () => {
  const VICTIM = "victim@example.com";
  const ATTACKER_PASSWORD = "attacker-password-123";
  const VICTIM_PASSWORD = "victim-password-123";

  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(verifications);
    sentEmails.splice(0, sentEmails.length);
  });

  it("a squatter's password and sessions do not survive the victim's verification", async () => {
    const context = await makeTestContext({ requireEmailVerification: true });
    const sessionsOf = (userId: string) =>
      Arr.fromIterable(MutableHashMap.values(sessions)).filter(
        (session) => session.userId === userId,
      ).length;

    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
        const manager = yield* SessionService;
        const emailPassword = yield* EmailPasswordService;

        // 1. The attacker signs up with the victim's address and a password
        //    they know; the address stays unverified. They also hold a session.
        const squat = yield* service.signUp({ email: VICTIM, password: ATTACKER_PASSWORD });
        yield* manager.createSession(squat.user.id);
        const squatterSessions = sessionsOf(squat.user.id);

        // 2. The victim signs up with their own address and password; the
        //    recovered branch answers as if it went through and re-sends a link.
        const recovered = yield* service.signUp({ email: VICTIM, password: VICTIM_PASSWORD });
        const link = sentEmails.at(-1);
        assert(link !== undefined, "the recovered sign-up re-sends a link");

        // 3. The victim follows the link and is signed into the account.
        const verified = yield* service.verifyEmail({ token: link.token });

        // 4. The attacker's password no longer signs in.
        const attackerSignIn = yield* Effect.flip(
          service.signIn({ email: VICTIM, password: ATTACKER_PASSWORD }),
        );
        const sessionsAfterVerify = sessionsOf(squat.user.id);

        // The verifier sets their own password from the session it issued.
        yield* emailPassword.setPassword(squat.user.id, VICTIM_PASSWORD);
        const victimSignIn = yield* service.signIn({ email: VICTIM, password: VICTIM_PASSWORD });

        return {
          squat,
          squatterSessions,
          recovered,
          link,
          verified,
          attackerSignIn,
          sessionsAfterVerify,
          victimSignIn,
        };
      }).pipe(Effect.provide(context), Effect.provide(TestHooks)),
    );

    expect(outcome.squatterSessions).toBe(1);
    expect(outcome.recovered.needsEmailVerification).toBe(true);
    expect(outcome.link.email).toBe(VICTIM);
    expect(outcome.verified.user.id).toBe(outcome.squat.user.id);
    expect(outcome.verified.session).toBeDefined();
    expect(outcome.attackerSignIn).toBeInstanceOf(InvalidCredentialsError);
    // Only the session the verification issued is left.
    expect(outcome.sessionsAfterVerify).toBe(1);
    expect(outcome.victimSignIn.user.id).toBe(outcome.squat.user.id);
  });

  it("without auto sign-in, the first proof still clears the password and revokes every session", async () => {
    const context = await makeTestContext();
    const user: User = {
      id: "user-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, VICTIM, false);
    MutableHashMap.set(passwordHashes, user.id, "squatter-hash");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const manager = yield* SessionService;
        yield* manager.createSession(user.id);
        const verification = yield* EmailVerificationService;
        const { token } = yield* verification.createVerification(user.id, VICTIM);
        const service = yield* AuthLifecycle.make({ autoSignInAfterVerification: false });
        return yield* service.verifyEmail({ token });
      }).pipe(Effect.provide(context), Effect.provide(TestHooks)),
    );

    expect(result.session).toBeUndefined();
    expect(MutableHashMap.has(passwordHashes, user.id)).toBe(false);
    expect(MutableHashMap.size(sessions)).toBe(0);
    expect(findEmailIdentifier(VICTIM)?.verified).toBe(true);
  });

  it("the first proof also removes the squatter's API keys and multi-factor enrolment (#694)", async () => {
    const context = await makeTestContext();
    const user: User = {
      id: "user-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, VICTIM, false);
    const apiKeys = memoryApiKeyStore();
    const multiFactor = memoryMultiFactorStore();

    const left = await Effect.runPromise(
      Effect.gen(function* () {
        yield* apiKeys.create({
          id: "squatter-key",
          start: "abcdef",
          keyHash: "squatter-key-hash",
          userId: user.id,
          enabled: true,
          metadata: {},
          createdAt: 0,
          updatedAt: 0,
        });
        yield* multiFactor.upsert({
          userId: user.id,
          secret: "JBSWY3DPEHPK3PXP",
          backupCodes: ["backup-code-hash"],
          verified: true,
          createdAt: 0,
        });
        const verification = yield* EmailVerificationService;
        const { token } = yield* verification.createVerification(user.id, VICTIM);
        const service = yield* AuthLifecycle.make({});
        yield* service.verifyEmail({ token });
        return {
          apiKeys: yield* apiKeys.listByUserId(user.id),
          multiFactor: yield* multiFactor.get(user.id),
        };
      }).pipe(
        Effect.provideService(ApiKeyStore, apiKeys),
        Effect.provideService(MultiFactorStore, multiFactor),
        Effect.provide(context),
        Effect.provide(TestHooks),
      ),
    );

    expect(left).toEqual({ apiKeys: [], multiFactor: null });
    expect(findEmailIdentifier(VICTIM)?.verified).toBe(true);
  });

  it("verifying an address already verified leaves the password and sessions alone", async () => {
    const context = await makeTestContext();
    const user: User = {
      id: "user-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, user.id, user);
    addEmailIdentifier(user.id, VICTIM, true);
    MutableHashMap.set(passwordHashes, user.id, "owner-hash");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const manager = yield* SessionService;
        yield* manager.createSession(user.id);
        const verification = yield* EmailVerificationService;
        const { token } = yield* verification.createVerification(user.id, VICTIM);
        const service = yield* AuthLifecycle.make();
        const result = yield* service.verifyEmail({ token });
        return result;
      }).pipe(Effect.provide(context), Effect.provide(TestHooks)),
    );

    expect(Option.getOrUndefined(MutableHashMap.get(passwordHashes, user.id))).toBe("owner-hash");
    // The session held before and the one the verification issued.
    expect(MutableHashMap.size(sessions)).toBe(2);
    expect(result.session).toBeDefined();
  });
});

describe("AuthLifecycleService.signUp recovers the address the beforeSignUp hooks chose (#426)", () => {
  const PASSWORD = "strong-password-123";

  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(verifications);
    sentEmails.splice(0, sentEmails.length);
  });

  /** A `Hooks` layer whose `beforeSignUp` strips a `+tag` from the address. */
  const stripTagHooks = Layer.effect(
    Hooks,
    Effect.gen(function* () {
      const base = yield* Hooks;
      return {
        ...base,
        beforeSignUp: (input) =>
          Effect.succeed({ ...input, email: input.email.replace(/\+[^@]*@/, "@") }),
      } satisfies typeof Hooks.Service;
    }),
  ).pipe(Layer.provide(Hooks.Default));

  const seed = (id: string, email: string, verified: boolean) => {
    MutableHashMap.set(users, id, {
      id,
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier(id, email, verified);
  };

  const signUp = async (email: string) => {
    const context = await makeTestContext({}, { hooks: stripTagHooks });
    return Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
        return yield* Effect.result(service.signUp({ email, password: PASSWORD }));
      }).pipe(Effect.provide(context), Effect.provide(TestHooks)),
    );
  };

  it("re-issues the verification of the rewritten address's unverified holder", async () => {
    seed("user-rewritten", "alice@example.com", false);

    const result = await signUp("alice+promo@example.com");

    assert(Result.isSuccess(result));
    expect(result.success.identifier).toEqual({ type: "email", value: "alice@example.com" });
    expect(sentEmails.map((sent) => sent.email)).toEqual(["alice@example.com"]);
    expect(Arr.fromIterable(MutableHashMap.values(verifications)).map((v) => v.userId)).toEqual([
      "user-rewritten",
    ]);
  });

  it("fails with EmailInUseError when the rewritten address is held verified, whoever holds the raw one", async () => {
    seed("user-raw", "alice+promo@example.com", false);
    seed("user-rewritten", "alice@example.com", true);

    const result = await signUp("alice+promo@example.com");

    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailInUseError");
    expect(sentEmails).toEqual([]);
    expect(MutableHashMap.size(verifications)).toBe(0);
  });
});

describe("AuthLifecycleService.signUp never stores authority-bearing attributes (#580)", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(passwordHashes);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(verifications);
    sentEmails.splice(0, sentEmails.length);
  });

  const forged = {
    role: "admin",
    tier: "gold",
    banned: false,
    banReason: "none",
    banExpires: 0,
    scimUserName: "ceo",
    scimDeactivated: false,
    scimExternalId: "idp-1",
    isAnonymous: true,
    plan: "pro",
  };

  const signUp = (testContext: Awaited<ReturnType<typeof makeTestContext>>, email: string) =>
    Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* AuthLifecycle.make({ requireEmailVerification: true });
          return yield* service.signUp({
            email,
            password: "strong-password-123",
            attributes: forged,
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

  it("strips the UserService's server-only attributes, which EmailPasswordService never saw, and the ban, SCIM and anonymous keys", async () => {
    const testContext = await makeTestContext(
      {},
      { userService: { serverOnlyAttributes: ["role", "tier"] } },
    );

    const result = await signUp(testContext, "fresh@example.com");

    expect(result.user.attributes).toEqual({ plan: "pro" });
    expect(Option.getOrUndefined(MutableHashMap.get(users, result.user.id))?.attributes).toEqual({
      plan: "pro",
    });
  });

  it("answers an address held unverified with a stand-in stripped the same way", async () => {
    const testContext = await makeTestContext(
      {},
      { userService: { serverOnlyAttributes: ["role", "tier"] } },
    );
    const holder: User = {
      id: "user-holder",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    MutableHashMap.set(users, holder.id, holder);
    addEmailIdentifier(holder.id, "held@example.com", false);

    const result = await signUp(testContext, "held@example.com");

    expect(result.user.id).not.toBe(holder.id);
    expect(result.user.attributes).toEqual({ plan: "pro" });
  });
});
