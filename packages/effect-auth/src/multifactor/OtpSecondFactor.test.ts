import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Crypto, Effect, Result } from "effect";
import { Hooks } from "../Hooks.ts";
import * as PlatformCrypto from "../PlatformCrypto.ts";
import { OtpSecondFactorStore, type OtpSecondFactorRecord } from "./OtpSecondFactor.ts";
import * as OtpSecondFactor from "./OtpSecondFactor.ts";
import { make, SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import type { Session, SessionConfig, User } from "../Types.ts";

// The `index`th item a test double recorded; a missing one fails the test.
const recorded = <A>(items: ReadonlyArray<A>, index = 0): A => {
  const item = items[index];
  assert(item !== undefined, `expected a recorded item at index ${index}`);
  return item;
};

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

const otpRecords = new Map<string, OtpSecondFactorRecord>(); // key: pendingToken
const sessions = new Map<string, Session>();
const users = new Map<string, User>();

const otpStore = {
  create: (record: OtpSecondFactorRecord) =>
    Effect.sync(() => {
      otpRecords.set(record.pendingToken, record);
      return record;
    }),

  get: (pendingToken: string) => Effect.sync(() => otpRecords.get(pendingToken) ?? null),

  update: (record: OtpSecondFactorRecord) =>
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
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(Hooks.Default)),
  );

  return Context.merge(
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.make(OtpSecondFactorStore, otpStore),
    ),
    Context.make(Crypto.Crypto, PlatformCrypto.instance),
  );
};

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const testUser: User = {
  id: "user-otp-1",
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
// OtpSecondFactorService
// ---------------------------------------------------------------------------

describe("OtpSecondFactorService", () => {
  it("begin sends the OTP and returns a pending challenge", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      return yield* service.begin(testUser);
    });

    const challenge = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(challenge.token).toBeDefined();
    expect(challenge.expiresAt).toBeGreaterThan(Date.now());
    expect(sentOtps).toHaveLength(1);
    expect(recorded(sentOtps).user.id).toBe(testUser.id);
    expect(recorded(sentOtps).otp).toMatch(/^\d{6}$/);
    // Only the hash is stored
    const stored = otpRecords.get(challenge.token);
    assert(stored !== undefined, "the challenge stored an OTP record");
    expect(stored.otpHash).not.toBe(recorded(sentOtps).otp);
    expect(stored.attempts).toBe(0);
  });

  it("verify with the correct OTP creates a session", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      return yield* service.verify(challenge.token, recorded(sentOtps).otp);
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
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      yield* service.verify(challenge.token, recorded(sentOtps).otp);
      return yield* Effect.result(service.verify(challenge.token, recorded(sentOtps).otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OtpSecondFactorError");
  });

  it("verify with a wrong OTP fails and increments attempts", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      return yield* Effect.result(service.verify(challenge.token, "000000"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OtpSecondFactorError");
    // Attempt counter incremented, record still present
    const stored = Array.from(otpRecords.values())[0];
    expect(stored?.attempts).toBe(1);
  });

  it("locks out after maxAttempts wrong guesses", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        maxAttempts: 3,
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
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
    assert(Result.isFailure(r3));
    expect(r3.failure._tag).toBe("OtpSecondFactorError");
    expect(r3.failure.message).toContain("attempts");
    expect(otpRecords.size).toBe(0);
  });

  it("verify fails when the challenge has expired", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        expiresIn: 1, // 1 ms → immediately expired
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      const challenge = yield* service.begin(testUser);
      yield* Effect.sleep("5 millis");
      return yield* Effect.result(service.verify(challenge.token, recorded(sentOtps).otp));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("OtpSecondFactorError");
    expect(result.failure.message).toContain("expired");
    // Expired pending record must be eagerly deleted
    expect(otpRecords.size).toBe(0);
  });

  it("respects a custom OTP length", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        otpLength: 8,
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });
      return yield* service.begin(testUser);
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(recorded(sentOtps).otp).toMatch(/^\d{8}$/);
  });

  it("OTP-second-factor full sign-in round-trip", async () => {
    const sentOtps: Array<{ user: User; otp: string }> = [];
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* OtpSecondFactor.make({
        sendOtp: (user, otp) =>
          Effect.sync(() => {
            sentOtps.push({ user, otp });
          }),
      });

      // Step 1: begin second factor (simulates what the gate's begin() does)
      const challenge = yield* service.begin(testUser);
      expect(challenge.token).toBeDefined();
      expect(sentOtps).toHaveLength(1);

      // Step 2: verify with the delivered OTP
      const result = yield* service.verify(challenge.token, recorded(sentOtps).otp, {
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
