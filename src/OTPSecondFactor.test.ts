import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import { Hooks } from "./Hooks.js";
import {
  makeOTPSecondFactorService,
  OTPSecondFactorStore,
  type OTPSecondFactorRecord,
} from "./OTPSecondFactor.js";
import { make, SessionService } from "./session/SessionService.js";
import { SessionStore } from "./session/SessionStore.js";
import { UserStore } from "./session/UserStore.js";
import type { Session, SessionConfig, User } from "./Types.js";

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

const otpRecords = new Map<string, OTPSecondFactorRecord>(); // key: pendingToken
const sessions = new Map<string, Session>();
const users = new Map<string, User>();

const otpStore = {
  create: (record: OTPSecondFactorRecord) =>
    Effect.sync(() => {
      otpRecords.set(record.pendingToken, record);
      return record;
    }),

  get: (pendingToken: string) => Effect.sync(() => otpRecords.get(pendingToken) ?? null),

  update: (record: OTPSecondFactorRecord) =>
    Effect.sync(() => {
      otpRecords.set(record.pendingToken, record);
      return record;
    }),

  delete: (pendingToken: string) =>
    Effect.sync(() => {
      otpRecords.delete(pendingToken);
    }),
};

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
  update: (session: Session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  delete: (id: string) =>
    Effect.sync(() => {
      sessions.delete(id);
    }),
  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      for (const [id, s] of sessions.entries()) {
        if (s.userId === userId) sessions.delete(id);
      }
    }),
  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((s) => s.userId === userId)),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),
  getCredentials: (_userId: string) => Effect.succeed<string | null>(null),
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
    Context.make(OTPSecondFactorStore, otpStore),
  );
};

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const testUser: User = {
  id: "user-otp-1",
  email: "bob@example.com",
  emailVerified: true,
  createdAt: new Date(),
  updatedAt: new Date(),
  attributes: {},
};

beforeEach(() => {
  otpRecords.clear();
  sessions.clear();
  users.set(testUser.id, testUser);
});

// ---------------------------------------------------------------------------
// OTPSecondFactorService
// ---------------------------------------------------------------------------

describe("OTPSecondFactorService", () => {
  it("begin sends the OTP and returns a pending challenge", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      return yield* service.begin(testUser);
    });

    const challenge = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(challenge.token).toBeDefined();
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());
    expect(sentOTPs).toHaveLength(1);
    expect(sentOTPs[0]!.user.id).toBe(testUser.id);
    expect(sentOTPs[0]!.otp).toMatch(/^\d{6}$/);
    // Only the hash is stored
    const stored = otpRecords.get(challenge.token);
    expect(stored).toBeDefined();
    expect(stored!.otpHash).not.toBe(sentOTPs[0]!.otp);
    expect(stored!.attempts).toBe(0);
  });

  it("verify with the correct OTP creates a session", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      return yield* service.verify(challenge.token, sentOTPs[0]!.otp);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe(testUser.id);
    expect(result.session.userId).toBe(testUser.id);
    // Pending record consumed
    expect(otpRecords.size).toBe(0);
  });

  it("challenge is single-use: second verify after success fails", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      yield* service.verify(challenge.token, sentOTPs[0]!.otp);
      return yield* Effect.result(service.verify(challenge.token, sentOTPs[0]!.otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OTPSecondFactorError");
    }
  });

  it("verify with a wrong OTP fails and increments attempts", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      return yield* Effect.result(service.verify(challenge.token, "000000"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OTPSecondFactorError");
    }
    // Attempt counter incremented, record still present
    const stored = Array.from(otpRecords.values())[0];
    expect(stored?.attempts).toBe(1);
  });

  it("locks out after maxAttempts wrong guesses", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        maxAttempts: 3,
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);

      const r1 = yield* Effect.result(service.verify(challenge.token, "000001"));
      const r2 = yield* Effect.result(service.verify(challenge.token, "000002"));
      const r3 = yield* Effect.result(service.verify(challenge.token, "000003"));

      return { r1, r2, r3 };
    });

    const { r1, r2, r3 } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(r1._tag).toBe("Failure");
    expect(r2._tag).toBe("Failure");
    // Third attempt exhausts limit and deletes the record
    expect(r3._tag).toBe("Failure");
    if (r3._tag === "Failure") {
      expect(r3.failure._tag).toBe("OTPSecondFactorError");
      expect((r3.failure as any).message).toContain("attempts");
    }
    expect(otpRecords.size).toBe(0);
  });

  it("verify fails when the challenge has expired", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        expiresIn: 1, // 1 ms → immediately expired
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      yield* Effect.sleep("5 millis");
      return yield* Effect.result(service.verify(challenge.token, sentOTPs[0]!.otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("OTPSecondFactorError");
      expect((result.failure as any).message).toContain("expired");
    }
    // Expired pending record must be eagerly deleted
    expect(otpRecords.size).toBe(0);
  });

  it("respects a custom OTP length", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        otpLength: 8,
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });
      return yield* service.begin(testUser);
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOTPs[0]!.otp).toMatch(/^\d{8}$/);
  });

  it("OTP-second-factor full sign-in round-trip", async () => {
    const sentOTPs: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* makeOTPSecondFactorService({
        sendOTP: (user, otp) =>
          Effect.sync(() => {
            sentOTPs.push({ user, otp });
          }),
      });

      // Step 1: begin second factor (simulates what the gate's begin() does)
      const challenge = yield* service.begin(testUser);
      expect(challenge.token).toBeDefined();
      expect(sentOTPs).toHaveLength(1);

      // Step 2: verify with the delivered OTP
      const result = yield* service.verify(challenge.token, sentOTPs[0]!.otp, {
        sessionAttributes: { device: "mobile" },
      });

      return result;
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.userId).toBe(testUser.id);
    expect(result.session.userId).toBe(testUser.id);
    expect(result.session.attributes).toMatchObject({ device: "mobile" });
    expect(otpRecords.size).toBe(0);
  });
});
