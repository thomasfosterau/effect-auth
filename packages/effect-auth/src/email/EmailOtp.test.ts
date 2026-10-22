import { assert, describe, it, expect, beforeEach, afterEach, vi } from "vite-plus/test";
import { EmailPasswordStore } from "./EmailPassword.ts";
import { memoryEmailPasswordStore } from "../testing/MemoryStores.ts";
import { Context, Crypto, Effect, Predicate, Result, Tracer } from "effect";
import { Hooks } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import {
  type EmailOtpCreateUserInput,
  type EmailOtpPurpose,
  type EmailOtpRecord,
  EmailOtpStore,
  EmailOtpUserStore,
} from "./EmailOtp.ts";
import * as EmailOtp from "./EmailOtp.ts";
import {
  type Identifier,
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
} from "../Identifier.ts";
import { hashToken } from "../TokenHash.ts";
import { make, SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import type { Session, User, SessionConfig } from "../Types.ts";
import * as Errors from "../Errors.ts";
import {
  observable,
  type RecordState,
  runVerifySequence,
  verifySequences,
  wrongCode,
  zeroCrypto,
} from "../testing/Passwordless.ts";

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const otpRecords = new Map<string, EmailOtpRecord>();
const sessions = new Map<string, Session>();
const sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }> = [];
/** The name of each `EmailOtpStore` call, in order. */
const storeOps: string[] = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

const recordKey = (email: string, purpose: EmailOtpPurpose) => `${email}:${purpose}`;

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

const addUser = (user: User) => {
  users.set(user.id, user);
};

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

const emailOtpUserStore = {
  createUser: (input: EmailOtpCreateUserInput) =>
    Effect.sync(() => {
      createdWith.push(input.identifier);
      const user: User = {
        id: `user-${users.size + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      };
      addUser(user);
      return { user, created: true };
    }),
};

/** The `identifier` each `createUser` call was given. */
const createdWith: Array<EmailOtpCreateUserInput["identifier"]> = [];

const emailOtpStore = {
  upsert: (record: EmailOtpRecord) =>
    Effect.sync(() => {
      storeOps.push("upsert");
      otpRecords.set(recordKey(record.email, record.purpose), record);
      return record;
    }),

  get: (email: string, purpose: EmailOtpPurpose) =>
    Effect.sync(() => {
      storeOps.push("get");
      return otpRecords.get(recordKey(email, purpose)) ?? null;
    }),

  delete: (email: string, purpose: EmailOtpPurpose) =>
    Effect.sync(() => {
      storeOps.push("delete");
      otpRecords.delete(recordKey(email, purpose));
    }),

  incrementAttempts: (email: string, purpose: EmailOtpPurpose) =>
    Effect.gen(function* () {
      storeOps.push("incrementAttempts");
      const record = otpRecords.get(recordKey(email, purpose));
      if (!record) {
        return yield* new Errors.AuthError({
          message: "OTP record not found",
        });
      }
      const updated = { ...record, attempts: record.attempts + 1 };
      otpRecords.set(recordKey(email, purpose), updated);
      return updated.attempts;
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

/** Password hashes, so a test can see a first proof clear one (#440). */
const passwordHashes = new Map<string, string>();
const emailPasswordStore = memoryEmailPasswordStore({ users: new Map(), passwordHashes });

const makeTestContext = async () => {
  // SessionService's `make` now resolves SessionStore | UserStore | Hooks at
  // construction time, so Hooks must be provided alongside the raw stores.
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
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.make(EmailPasswordStore, emailPasswordStore),
    ),
    Context.merge(
      Context.merge(
        Context.make(EmailOtpStore, emailOtpStore),
        Context.make(EmailOtpUserStore, emailOtpUserStore),
      ),
      Context.merge(
        Context.merge(
          Context.make(IdentifierStore, identifierStore),
          Context.make(UserStore, userStore),
        ),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ),
  );
};

const recordingSend = (email: string, otp: string, purpose: EmailOtpPurpose) =>
  Effect.sync(() => {
    sentOtps.push({ email, otp, purpose });
  });

describe("EmailOtpService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    otpRecords.clear();
    sessions.clear();
    passwordHashes.clear();
    sentOtps.splice(0, sentOtps.length);
    storeOps.length = 0;
    createdWith.length = 0;
  });

  it("should send a numeric OTP and store only its hash", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("new@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(1);
    const sent = sentOtps[0]!;
    expect(sent.email).toBe("new@example.com");
    expect(sent.purpose).toBe("sign-in");
    expect(sent.otp).toMatch(/^\d{6}$/);

    const record = otpRecords.get("new@example.com:sign-in");
    expect(record).toBeDefined();
    expect(record?.otpHash).toBe(hashToken(sent.otp));
    expect(record?.otpHash).not.toBe(sent.otp);
    expect(record?.attempts).toBe(0);
  });

  it("should respect a custom OTP length and replace outstanding codes", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        otpLength: 8,
        sendVerificationOtp: recordingSend,
      });
      yield* service.send("repeat@example.com", "sign-in");
      yield* service.send("repeat@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(2);
    expect(sentOtps[0]?.otp).toMatch(/^\d{8}$/);
    // One active OTP per email + purpose: only the latest hash remains.
    expect(otpRecords.size).toBe(1);
    expect(otpRecords.get("repeat@example.com:sign-in")?.otpHash).toBe(hashToken(sentOtps[1]!.otp));
  });

  it("should sign in a new user with a valid OTP, creating a verified email identifier and session", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("  Fresh@Example.COM ", "sign-in");
      return yield* service.signIn("fresh@example.com", sentOtps[0]!.otp, {
        sessionAttributes: { device: "test" },
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // The OTP proves email ownership, so the new user's email identifier is
    // created verified.
    const identifier = findEmailIdentifier("fresh@example.com");
    expect(identifier?.userId).toBe(result.user.id);
    expect(identifier?.verified).toBe(true);
    // The store was handed the address to create the user with (#380).
    expect(createdWith).toEqual([
      { type: "email", value: "fresh@example.com", verified: true, verifiedAt: expect.any(Date) },
    ]);
    expect(result.session.userId).toBe(result.user.id);
    expect(result.session.attributes).toEqual({ device: "test" });
    expect(sessions.size).toBe(1);
    // One-time use: record consumed.
    expect(otpRecords.size).toBe(0);
  });

  it("should sign in an existing user without creating a new one", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-known",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    });
    addEmailIdentifier("user-known", "known@example.com", true);

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("known@example.com", "sign-in");
      return yield* service.signIn("known@example.com", sentOtps[0]!.otp);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe("user-known");
    expect(users.size).toBe(1);
    expect(result.session.userId).toBe("user-known");
  });

  it("clears a squatter's password and sessions on the address's first proof (#440)", async () => {
    const testContext = await makeTestContext();

    // A squatter signed up with the address and a password they know, and
    // holds a session; the address was never verified.
    addUser({ id: "user-squat", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-squat", "victim@example.com", false);
    passwordHashes.set("user-squat", "squatter-hash");
    const now = new Date();
    sessions.set("squatter-session", {
      id: "squatter-session",
      userId: "user-squat",
      expiresAt: new Date(now.getTime() + 3_600_000),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("victim@example.com", "sign-in");
      return yield* service.signIn("victim@example.com", sentOtps[0]!.otp);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // The holder of the address is signed in; the squatter's password and
    // session are gone, so only the session just issued remains.
    expect(result.user.id).toBe("user-squat");
    expect(passwordHashes.has("user-squat")).toBe(false);
    expect(sessions.has("squatter-session")).toBe(false);
    expect([...sessions.values()].map((session) => session.userId)).toEqual(["user-squat"]);
    expect(findEmailIdentifier("victim@example.com")?.verified).toBe(true);
  });

  it("keeps the password and sessions of an account whose address is already verified (#440)", async () => {
    const testContext = await makeTestContext();

    addUser({ id: "user-owner", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-owner", "victim@example.com", true);
    passwordHashes.set("user-owner", "owner-hash");

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("victim@example.com", "sign-in");
      return yield* service.signIn("victim@example.com", sentOtps[0]!.otp);
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(passwordHashes.get("user-owner")).toBe("owner-hash");
  });

  it("should reject a replayed OTP (one-time use)", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("once@example.com", "sign-in");
      const otp = sentOtps[0]!.otp;
      yield* service.signIn("once@example.com", otp);
      return yield* Effect.result(service.signIn("once@example.com", otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailOtpError");
    expect(sessions.size).toBe(1);
  });

  it("should reject expired OTPs and delete the record", async () => {
    const testContext = await makeTestContext();

    otpRecords.set("late@example.com:sign-in", {
      email: "late@example.com",
      otpHash: hashToken("123456"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now() - 10 * 60 * 1000,
      expiresAt: Date.now() - 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      return yield* Effect.result(service.signIn("late@example.com", "123456"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailOtpError");
    expect(otpRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should increment attempts on a wrong OTP and delete the record when the limit is hit", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        maxAttempts: 3,
        sendVerificationOtp: recordingSend,
      });
      yield* service.send("guess@example.com", "sign-in");

      const first = yield* Effect.result(service.signIn("guess@example.com", "000000"));
      const second = yield* Effect.result(service.signIn("guess@example.com", "000001"));
      const third = yield* Effect.result(service.signIn("guess@example.com", "000002"));
      // Record has been deleted; even the real OTP no longer works.
      const real = yield* Effect.result(service.signIn("guess@example.com", sentOtps[0]!.otp));

      return { first, second, third, real };
    });

    const { first, second, third, real } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(first._tag).toBe("Failure");
    expect(second._tag).toBe("Failure");
    expect(third._tag).toBe("Failure");
    expect(real._tag).toBe("Failure");
    assert(Result.isFailure(real));
    expect(real.failure._tag).toBe("EmailOtpError");
    expect(otpRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
    expect(users.size).toBe(0);
  });

  it("should allow the correct OTP after fewer than maxAttempts failures", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("fumble@example.com", "sign-in");
      yield* Effect.result(service.signIn("fumble@example.com", "000000"));
      return yield* service.signIn("fumble@example.com", sentOtps[0]!.otp);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(findEmailIdentifier("fumble@example.com")?.userId).toBe(result.user.id);
    expect(sessions.size).toBe(1);
  });

  it("should not send sign-in OTPs to unknown emails when sign-up is disabled, storing a marker", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        disableSignUp: true,
        sendVerificationOtp: recordingSend,
      });
      yield* service.send("stranger@example.com", "sign-in");
    });

    // Anti-enumeration: succeeds without sending, and stores an undelivered
    // marker record as it would a code (#417).
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(0);
    expect(otpRecords.get("stranger@example.com:sign-in")?.attempts).toBe(0);
  });

  it("should not create users at sign-in when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    otpRecords.set("orphan@example.com:sign-in", {
      email: "orphan@example.com",
      otpHash: hashToken("123456"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        disableSignUp: true,
        sendVerificationOtp: recordingSend,
      });
      return yield* Effect.result(service.signIn("orphan@example.com", "123456"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailOtpError");
    expect(users.size).toBe(0);
    expect(identifierRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should only send forget-password OTPs to existing users, succeeding either way", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-member",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    });
    addEmailIdentifier("user-member", "member@example.com", true);

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("missing@example.com", "forget-password");
      yield* service.send("member@example.com", "forget-password");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // Anti-enumeration: both calls succeed, only the existing user gets a code,
    // and the missing email holds an undelivered marker record (#417).
    expect(sentOtps.length).toBe(1);
    expect(sentOtps[0]?.email).toBe("member@example.com");
    expect(sentOtps[0]?.purpose).toBe("forget-password");
    expect(otpRecords.size).toBe(2);
    expect(otpRecords.has("missing@example.com:forget-password")).toBe(true);
  });

  it("should verify email-verification OTPs via check without creating a session", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("verify@example.com", "email-verification");
      return yield* service.check("verify@example.com", sentOtps[0]!.otp, "email-verification");
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result).toEqual({ email: "verify@example.com", verified: true });
    expect(sessions.size).toBe(0);
    // One-time use: record consumed.
    expect(otpRecords.size).toBe(0);
  });

  it("should scope OTPs to their purpose", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("scoped@example.com", "email-verification");
      // A code issued for email-verification must not sign the user in.
      return yield* Effect.result(service.signIn("scoped@example.com", sentOtps[0]!.otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("EmailOtpError");
    expect(sessions.size).toBe(0);
  });

  it("should fail with ResendTooSoonError when a resend is within the cooldown window", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        sendVerificationOtp: recordingSend,
        resendCooldown: 60_000,
      });
      yield* service.send("user@example.com", "sign-in");
      return yield* Effect.result(service.send("user@example.com", "sign-in"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("ResendTooSoonError");
    expect((result.failure as { retryAfter: number }).retryAfter).toBeGreaterThan(0);
    expect((result.failure as { retryAfter: number }).retryAfter).toBeLessThanOrEqual(60_000);
    // The original OTP is preserved — no replacement was issued.
    expect(sentOtps.length).toBe(1);
    expect(otpRecords.size).toBe(1);
  });

  it("should allow a resend after the cooldown window has elapsed", async () => {
    const testContext = await makeTestContext();

    // Seed an OTP record whose createdAt is older than the 60 s cooldown.
    otpRecords.set("user@example.com:sign-in", {
      email: "user@example.com",
      otpHash: hashToken("123456"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now() - 70_000,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        sendVerificationOtp: recordingSend,
        resendCooldown: 60_000,
      });
      yield* service.send("user@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // A fresh OTP was issued after the cooldown elapsed.
    expect(sentOtps.length).toBe(1);
    expect(otpRecords.size).toBe(1);
    // The new record has a fresh hash, not the seeded one.
    expect(otpRecords.get("user@example.com:sign-in")?.otpHash).toBe(hashToken(sentOtps[0]!.otp));
  });

  it("should scope the cooldown to each purpose independently", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        sendVerificationOtp: recordingSend,
        resendCooldown: 60_000,
      });
      // First send for sign-in; immediate re-send for a different purpose is allowed.
      yield* service.send("user@example.com", "sign-in");
      yield* service.send("user@example.com", "email-verification");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(2);
    expect(otpRecords.size).toBe(2);
  });

  it("should not apply the cooldown when resendCooldown is not configured", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({ sendVerificationOtp: recordingSend });
      yield* service.send("repeat@example.com", "sign-in");
      yield* service.send("repeat@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(2);
    expect(otpRecords.size).toBe(1);
  });

  // #415: where `send` hides whether the email has an account, an unknown email
  // must hit the cooldown exactly as a known one does, or the second request's
  // answer reveals the account.
  it.each([
    { purpose: "sign-in", disableSignUp: true },
    { purpose: "forget-password", disableSignUp: false },
  ] as const)(
    "answers a known and an unknown email alike within the cooldown ($purpose, disableSignUp: $disableSignUp)",
    async ({ purpose, disableSignUp }) => {
      const testContext = await makeTestContext();
      addUser({ id: "user-member", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
      addEmailIdentifier("user-member", "member@example.com", true);

      const program = Effect.gen(function* () {
        const service = yield* EmailOtp.make({
          disableSignUp,
          resendCooldown: 60_000,
          sendVerificationOtp: recordingSend,
        });
        const twice = (email: string) =>
          Effect.all(
            [
              Effect.result(service.send(email, purpose)),
              Effect.result(service.send(email, purpose)),
            ],
            { concurrency: 1 },
          );
        return {
          known: yield* twice("member@example.com"),
          unknown: yield* twice("missing@example.com"),
        };
      });

      const { known, unknown } = await Effect.runPromise(
        Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
      );

      expect(unknown.map(observable)).toEqual(known.map(observable));
      expect(known.map(observable)).toEqual([
        { _tag: "Success" },
        {
          _tag: "Failure",
          error: "ResendTooSoonError",
          message: "Please wait before requesting another OTP",
        },
      ]);
      for (const result of [known[1], unknown[1]]) {
        expect(result._tag).toBe("Failure");
        assert(Result.isFailure(result));
        assert(Predicate.isTagged(result.failure, "ResendTooSoonError"));
        expect(result.failure.retryAfter).toBeGreaterThan(0);
        expect(result.failure.retryAfter).toBeLessThanOrEqual(60_000);
      }
      // Only the account holder is sent a code; the unknown email holds an
      // undelivered record as its cooldown marker.
      expect(sentOtps.map((sent) => sent.email)).toEqual(["member@example.com"]);
      expect(otpRecords.has(`missing@example.com:${purpose}`)).toBe(true);
    },
  );

  // #415: an unknown email's cooldown marker must never be redeemable. With
  // `zeroCrypto` the only code `send` can draw is all zeros, so a marker that
  // held an `otpLength`-digit code would match that guess.
  it.each([
    { purpose: "sign-in", disableSignUp: true },
    { purpose: "forget-password", disableSignUp: false },
  ] as const)(
    "stores a cooldown marker for an unknown email that no code redeems ($purpose)",
    async ({ purpose, disableSignUp }) => {
      const testContext = await makeTestContext();
      addUser({ id: "user-member", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
      addEmailIdentifier("user-member", "member@example.com", true);
      const otpLength = 6;
      const guess = "0".repeat(otpLength);

      const program = Effect.gen(function* () {
        const service = yield* EmailOtp.make({
          otpLength,
          disableSignUp,
          resendCooldown: 60_000,
          sendVerificationOtp: recordingSend,
        }).pipe(Effect.provideService(Crypto.Crypto, zeroCrypto));
        yield* service.send("member@example.com", purpose);
        yield* service.send("missing@example.com", purpose);
        const marker = otpRecords.get(recordKey("missing@example.com", purpose));
        const error = yield* Effect.flip(
          purpose === "sign-in"
            ? Effect.asVoid(service.signIn("missing@example.com", guess))
            : Effect.asVoid(service.check("missing@example.com", guess, purpose)),
        );
        return { marker, error };
      });

      const { marker, error } = await Effect.runPromise(
        Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
      );

      // The stub draws only the all-zero code, as the account holder's shows.
      expect(sentOtps).toEqual([{ email: "member@example.com", otp: guess, purpose }]);
      expect(marker).toBeDefined();
      expect(marker?.otpHash).not.toBe(hashToken(guess));
      expect(error).toMatchObject({ _tag: "EmailOtpError", message: "Invalid or expired OTP" });
      expect(users.size).toBe(1);
      expect(createdWith).toEqual([]);
    },
  );
});

// #417: where `send` hides whether the email has an account, verification must
// answer an email that holds an outstanding code exactly as it answers one
// that holds a marker record or nothing at all: through wrong codes, the
// attempt limit and expiry.
describe("EmailOtpService verification where send hides the account (#417)", () => {
  const maxAttempts = 3;
  const expiresIn = 5 * 60 * 1000;
  const hidden = [
    { purpose: "sign-in", disableSignUp: true },
    { purpose: "forget-password", disableSignUp: false },
  ] as const;
  const invalid = { _tag: "Failure", error: "EmailOtpError", message: "Invalid or expired OTP" };

  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    otpRecords.clear();
    sessions.clear();
    sentOtps.splice(0, sentOtps.length);
    storeOps.length = 0;
    createdWith.length = 0;
    addUser({ id: "user-member", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-member", "member@example.com", true);
    vi.useFakeTimers({ toFake: ["Date"] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const recordOf = (email: string, purpose: EmailOtpPurpose) => (): RecordState | null => {
    const record = otpRecords.get(recordKey(email, purpose));
    return record === undefined
      ? null
      : { attempts: record.attempts, lifetime: record.expiresAt - record.createdAt };
  };

  /** Run `sequence` for `email`, requesting a code first when `send` is set. */
  const run = (
    config: { readonly purpose: EmailOtpPurpose; readonly disableSignUp: boolean },
    sequence: (typeof verifySequences)[number],
    email: string,
    send: boolean,
  ) =>
    Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        maxAttempts,
        expiresIn,
        disableSignUp: config.disableSignUp,
        sendVerificationOtp: recordingSend,
      });
      return yield* runVerifySequence(sequence, {
        maxAttempts,
        expiresIn,
        send: send ? service.send(email, config.purpose) : undefined,
        verify:
          config.purpose === "sign-in"
            ? service.signIn(email, wrongCode)
            : service.check(email, wrongCode, config.purpose),
        record: recordOf(email, config.purpose),
      });
    });

  const runPromise = <A, E>(
    program: Effect.Effect<
      A,
      E,
      | EmailOtpStore
      | EmailOtpUserStore
      | IdentifierStore
      | UserStore
      | SessionService
      | EmailPasswordStore
      | Crypto.Crypto
    >,
  ) =>
    makeTestContext().then((context) =>
      Effect.runPromise(Effect.provide(program, context).pipe(Effect.provide(Hooks.Default))),
    );

  it.each(hidden.flatMap((config) => verifySequences.map((sequence) => ({ ...config, sequence }))))(
    "answers $sequence alike for every email ($purpose, disableSignUp: $disableSignUp)",
    async ({ purpose, disableSignUp, sequence }) => {
      const config = { purpose, disableSignUp };
      const { known, unknown, unrequested } = await runPromise(
        Effect.gen(function* () {
          return {
            known: yield* run(config, sequence, "member@example.com", true),
            unknown: yield* run(config, sequence, "missing@example.com", true),
            unrequested: yield* run(config, sequence, "absent@example.com", false),
          };
        }),
      );

      // The unknown email's marker record is counted and expired exactly as
      // the account holder's code record, and every answer matches.
      expect(unknown).toEqual(known);
      const lifetime = expiresIn;
      expect(known.map((step) => step.record)).toEqual(
        sequence === "wrong codes"
          ? [
              { attempts: 0, lifetime },
              { attempts: 1, lifetime },
              { attempts: 2, lifetime },
              null,
              null,
            ]
          : [{ attempts: 0, lifetime }, null, null],
      );
      // An email holding no record at all answers the same.
      expect(unrequested.map((step) => step.answer)).toEqual(known.map((step) => step.answer));
      expect(known.slice(1).map((step) => step.answer)).toEqual(known.slice(1).map(() => invalid));
      expect(sentOtps.map((sent) => sent.email)).toEqual(["member@example.com"]);
    },
  );

  it.each([
    { purpose: "sign-in", disableSignUp: false },
    { purpose: "email-verification", disableSignUp: true },
  ] as const)(
    "keeps the expiry and attempt-limit answers where the account isn't hidden ($purpose, disableSignUp: $disableSignUp)",
    async ({ purpose, disableSignUp }) => {
      const config = { purpose, disableSignUp };
      const { wrong, expired } = await runPromise(
        Effect.gen(function* () {
          return {
            wrong: yield* run(config, "wrong codes", "member@example.com", true),
            expired: yield* run(config, "expired code", "member@example.com", true),
          };
        }),
      );

      const answer = (message: string) => ({ _tag: "Failure", error: "EmailOtpError", message });
      expect(wrong.slice(1).map((step) => step.answer)).toEqual([
        invalid,
        invalid,
        answer("Too many attempts"),
        invalid,
      ]);
      expect(expired.slice(1).map((step) => step.answer)).toEqual([
        answer("OTP has expired"),
        invalid,
      ]);
    },
  );

  it.each(hidden)(
    "does the same store work to send to a known and an unknown email without a cooldown ($purpose)",
    async ({ purpose, disableSignUp }) => {
      const { knownOps, unknownOps } = await runPromise(
        Effect.gen(function* () {
          const service = yield* EmailOtp.make({
            disableSignUp,
            sendVerificationOtp: recordingSend,
          });
          yield* service.send("member@example.com", purpose);
          const knownOps = storeOps.splice(0);
          yield* service.send("missing@example.com", purpose);
          return { knownOps, unknownOps: storeOps.splice(0) };
        }),
      );

      expect(unknownOps).toEqual(knownOps);
      expect(knownOps).toEqual(["upsert"]);
      expect(recordOf("missing@example.com", purpose)()).toEqual(
        recordOf("member@example.com", purpose)(),
      );
    },
  );

  it.each(hidden)(
    "answers the generic message for a known email whose record has used every attempt ($purpose, disableSignUp: $disableSignUp)",
    async ({ purpose, disableSignUp }) => {
      // Seed the defensive branch: a record that reached `maxAttempts` without
      // being deleted. Even the correct code must answer the generic message.
      const { answer, record } = await runPromise(
        Effect.gen(function* () {
          const service = yield* EmailOtp.make({
            maxAttempts,
            expiresIn,
            disableSignUp,
            sendVerificationOtp: recordingSend,
          });
          yield* service.send("member@example.com", purpose);
          const stored = otpRecords.get(recordKey("member@example.com", purpose))!;
          otpRecords.set(recordKey("member@example.com", purpose), {
            ...stored,
            attempts: maxAttempts,
          });
          const otp = sentOtps[0]!.otp;
          const result =
            purpose === "sign-in"
              ? yield* Effect.result(service.signIn("member@example.com", otp))
              : yield* Effect.result(service.check("member@example.com", otp, purpose));
          return {
            answer: observable(result),
            record: recordOf("member@example.com", purpose)(),
          };
        }),
      );

      expect(answer).toEqual(invalid);
      expect(record).toBeNull();
    },
  );

  it("records the real reason on the signIn span while answering the generic message", async () => {
    // The span keeps the reason operators need; the caller sees only the
    // generic message. Capture the spans the service creates.
    const spans: Tracer.NativeSpan[] = [];
    const tracer = Tracer.make({
      span(options) {
        const span = new Tracer.NativeSpan(options);
        spans.push(span);
        return span;
      },
    });

    const answers = await runPromise(
      Effect.gen(function* () {
        const service = yield* EmailOtp.make({
          maxAttempts,
          expiresIn,
          disableSignUp: true,
          sendVerificationOtp: recordingSend,
        });
        yield* service.send("member@example.com", "sign-in");
        // Wrong codes past the limit, then one more against the deleted record.
        return yield* Effect.replicateEffect(
          Effect.result(service.signIn("member@example.com", wrongCode)).pipe(
            Effect.map(observable),
          ),
          maxAttempts + 1,
          { concurrency: 1 },
        );
      }).pipe(Effect.provideService(Tracer.Tracer, tracer)),
    );

    expect(answers).toEqual(Array.from({ length: maxAttempts + 1 }, () => invalid));
    const reasons = spans
      .filter((span) => span.name === "EmailOtpService.signIn")
      .map((span) => span.attributes.get("auth.otp.failure"));
    expect(reasons).toEqual(["mismatch", "mismatch", "attempts", "missing"]);
  });
});
