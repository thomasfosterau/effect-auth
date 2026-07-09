import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import { Hooks } from "../Hooks.js";
import {
  makeEmailOTPService,
  type EmailOTPCreateUserInput,
  type EmailOTPPurpose,
  type EmailOTPRecord,
  EmailOTPStore,
  EmailOTPUserStore,
} from "./EmailOTP.js";
import { hashToken } from "../TokenHash.js";
import { make, SessionService } from "../session/SessionService.js";
import { SessionStore } from "../session/SessionStore.js";
import { UserStore } from "../session/UserStore.js";
import type { Session, User, SessionConfig } from "../Types.js";
import * as Errors from "../Errors.js";

const users = new Map<string, User>();
const usersByEmail = new Map<string, string>();
const otpRecords = new Map<string, EmailOTPRecord>();
const sessions = new Map<string, Session>();
const sentOTPs: Array<{ email: string; otp: string; purpose: EmailOTPPurpose }> = [];

const recordKey = (email: string, purpose: EmailOTPPurpose) => `${email}:${purpose}`;

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

  getCredentials: (_userId: string) => Effect.succeed(null),
};

const addUser = (user: User) => {
  users.set(user.id, user);
  usersByEmail.set(user.email, user.id);
};

const emailOTPUserStore = {
  getUserByEmail: (email: string) =>
    Effect.sync(() => {
      const userId = usersByEmail.get(email);
      return userId ? (users.get(userId) ?? null) : null;
    }),

  createUser: (input: EmailOTPCreateUserInput) =>
    Effect.sync(() => {
      const user: User = {
        id: `user-${users.size + 1}`,
        email: input.email,
        emailVerified: input.emailVerified,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
        attributes: {},
      };
      addUser(user);
      return user;
    }),
};

const emailOTPStore = {
  upsert: (record: EmailOTPRecord) =>
    Effect.sync(() => {
      otpRecords.set(recordKey(record.email, record.purpose), record);
      return record;
    }),

  get: (email: string, purpose: EmailOTPPurpose) =>
    Effect.sync(() => otpRecords.get(recordKey(email, purpose)) ?? null),

  delete: (email: string, purpose: EmailOTPPurpose) =>
    Effect.sync(() => {
      otpRecords.delete(recordKey(email, purpose));
    }),

  incrementAttempts: (email: string, purpose: EmailOTPPurpose) =>
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
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
    ),
  );

  return Context.merge(
    Context.make(SessionService, sessionManager),
    Context.merge(
      Context.make(EmailOTPStore, emailOTPStore),
      Context.make(EmailOTPUserStore, emailOTPUserStore),
    ),
  );
};

const recordingSend = (email: string, otp: string, purpose: EmailOTPPurpose) =>
  Effect.sync(() => {
    sentOTPs.push({ email, otp, purpose });
  });

describe("EmailOTPService", () => {
  beforeEach(() => {
    users.clear();
    usersByEmail.clear();
    otpRecords.clear();
    sessions.clear();
    sentOTPs.splice(0, sentOTPs.length);
  });

  it("should send a numeric OTP and store only its hash", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("new@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs.length).toBe(1);
    const sent = sentOTPs[0]!;
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
      const service = yield* makeEmailOTPService({
        otpLength: 8,
        sendVerificationOTP: recordingSend,
      });
      yield* service.send("repeat@example.com", "sign-in");
      yield* service.send("repeat@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs.length).toBe(2);
    expect(sentOTPs[0]?.otp).toMatch(/^\d{8}$/);
    // One active OTP per email + purpose: only the latest hash remains.
    expect(otpRecords.size).toBe(1);
    expect(otpRecords.get("repeat@example.com:sign-in")?.otpHash).toBe(hashToken(sentOTPs[1]!.otp));
  });

  it("should sign in a new user with a valid OTP, creating a verified user and session", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("  Fresh@Example.COM ", "sign-in");
      return yield* service.signIn("fresh@example.com", sentOTPs[0]!.otp, {
        sessionAttributes: { device: "test" },
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.email).toBe("fresh@example.com");
    // The OTP proves email ownership, so the new user is verified.
    expect(result.user.emailVerified).toBe(true);
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
      email: "known@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    });

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("known@example.com", "sign-in");
      return yield* service.signIn("known@example.com", sentOTPs[0]!.otp);
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
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("once@example.com", "sign-in");
      const otp = sentOTPs[0]!.otp;
      yield* service.signIn("once@example.com", otp);
      return yield* Effect.result(service.signIn("once@example.com", otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOTPError");
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
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      return yield* Effect.result(service.signIn("late@example.com", "123456"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOTPError");
    }
    expect(otpRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should increment attempts on a wrong OTP and delete the record when the limit is hit", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({
        maxAttempts: 3,
        sendVerificationOTP: recordingSend,
      });
      yield* service.send("guess@example.com", "sign-in");

      const first = yield* Effect.result(service.signIn("guess@example.com", "000000"));
      const second = yield* Effect.result(service.signIn("guess@example.com", "000001"));
      const third = yield* Effect.result(service.signIn("guess@example.com", "000002"));
      // Record has been deleted; even the real OTP no longer works.
      const real = yield* Effect.result(service.signIn("guess@example.com", sentOTPs[0]!.otp));

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
      expect(real.failure._tag).toBe("EmailOTPError");
    }
    expect(otpRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
    expect(users.size).toBe(0);
  });

  it("should allow the correct OTP after fewer than maxAttempts failures", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("fumble@example.com", "sign-in");
      yield* Effect.result(service.signIn("fumble@example.com", "000000"));
      return yield* service.signIn("fumble@example.com", sentOTPs[0]!.otp);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.email).toBe("fumble@example.com");
    expect(sessions.size).toBe(1);
  });

  it("should not send sign-in OTPs to unknown emails when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({
        disableSignUp: true,
        sendVerificationOTP: recordingSend,
      });
      yield* service.send("stranger@example.com", "sign-in");
    });

    // Anti-enumeration: succeeds silently.
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs.length).toBe(0);
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
      const service = yield* makeEmailOTPService({
        disableSignUp: true,
        sendVerificationOTP: recordingSend,
      });
      return yield* Effect.result(service.signIn("orphan@example.com", "123456"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOTPError");
    }
    expect(users.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should only send forget-password OTPs to existing users, succeeding either way", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-member",
      email: "member@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    });

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("missing@example.com", "forget-password");
      yield* service.send("member@example.com", "forget-password");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // Anti-enumeration: both calls succeed, only the existing user gets a code.
    expect(sentOTPs.length).toBe(1);
    expect(sentOTPs[0]?.email).toBe("member@example.com");
    expect(sentOTPs[0]?.purpose).toBe("forget-password");
    expect(otpRecords.size).toBe(1);
  });

  it("should verify email-verification OTPs via check without creating a session", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("verify@example.com", "email-verification");
      return yield* service.check("verify@example.com", sentOTPs[0]!.otp, "email-verification");
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
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("scoped@example.com", "email-verification");
      // A code issued for email-verification must not sign the user in.
      return yield* Effect.result(service.signIn("scoped@example.com", sentOTPs[0]!.otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("EmailOTPError");
    }
    expect(sessions.size).toBe(0);
  });

  it("should fail with ResendTooSoonError when a resend is within the cooldown window", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({
        sendVerificationOTP: recordingSend,
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
    expect(sentOTPs.length).toBe(1);
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
      const service = yield* makeEmailOTPService({
        sendVerificationOTP: recordingSend,
        resendCooldown: 60_000,
      });
      yield* service.send("user@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // A fresh OTP was issued after the cooldown elapsed.
    expect(sentOTPs.length).toBe(1);
    expect(otpRecords.size).toBe(1);
    // The new record has a fresh hash, not the seeded one.
    expect(otpRecords.get("user@example.com:sign-in")?.otpHash).toBe(hashToken(sentOTPs[0]!.otp));
  });

  it("should scope the cooldown to each purpose independently", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({
        sendVerificationOTP: recordingSend,
        resendCooldown: 60_000,
      });
      // First send for sign-in; immediate re-send for a different purpose is allowed.
      yield* service.send("user@example.com", "sign-in");
      yield* service.send("user@example.com", "email-verification");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs.length).toBe(2);
    expect(otpRecords.size).toBe(2);
  });

  it("should not apply the cooldown when resendCooldown is not configured", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeEmailOTPService({ sendVerificationOTP: recordingSend });
      yield* service.send("repeat@example.com", "sign-in");
      yield* service.send("repeat@example.com", "sign-in");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs.length).toBe(2);
    expect(otpRecords.size).toBe(1);
  });
});
