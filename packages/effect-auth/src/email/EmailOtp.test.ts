import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Crypto, Effect } from "effect";
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

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const otpRecords = new Map<string, EmailOtpRecord>();
const sessions = new Map<string, Session>();
const sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }> = [];

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
      const user: User = {
        id: `user-${users.size + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      };
      addUser(user);
      return user;
    }),
};

const emailOtpStore = {
  upsert: (record: EmailOtpRecord) =>
    Effect.sync(() => {
      otpRecords.set(recordKey(record.email, record.purpose), record);
      return record;
    }),

  get: (email: string, purpose: EmailOtpPurpose) =>
    Effect.sync(() => otpRecords.get(recordKey(email, purpose)) ?? null),

  delete: (email: string, purpose: EmailOtpPurpose) =>
    Effect.sync(() => {
      otpRecords.delete(recordKey(email, purpose));
    }),

  incrementAttempts: (email: string, purpose: EmailOtpPurpose) =>
    Effect.gen(function* () {
      const record = otpRecords.get(recordKey(email, purpose));
      if (!record) {
        return yield* Effect.fail(
          new Errors.AuthError({
            message: "OTP record not found",
          }),
        );
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
    Context.make(SessionService, sessionManager),
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
    sentOtps.splice(0, sentOtps.length);
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOtpError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOtpError");
    }
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
    if (real._tag === "Failure") {
      expect(real.failure._tag).toBe("EmailOtpError");
    }
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

  it("should not send sign-in OTPs to unknown emails when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* EmailOtp.make({
        disableSignUp: true,
        sendVerificationOtp: recordingSend,
      });
      yield* service.send("stranger@example.com", "sign-in");
    });

    // Anti-enumeration: succeeds silently.
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps.length).toBe(0);
    expect(otpRecords.size).toBe(0);
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOtpError");
    }
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

    // Anti-enumeration: both calls succeed, only the existing user gets a code.
    expect(sentOtps.length).toBe(1);
    expect(sentOtps[0]?.email).toBe("member@example.com");
    expect(sentOtps[0]?.purpose).toBe("forget-password");
    expect(otpRecords.size).toBe(1);
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOtpError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("ResendTooSoonError");
      expect((result.failure as { retryAfter: number }).retryAfter).toBeGreaterThan(0);
      expect((result.failure as { retryAfter: number }).retryAfter).toBeLessThanOrEqual(60_000);
    }
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
});
