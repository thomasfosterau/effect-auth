import { assert, describe, it, expect, beforeEach, afterEach, vi } from "vite-plus/test";
import { Context, Crypto, Effect, Layer, Predicate, Result } from "effect";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  getPhoneNumber,
  type PhoneOtpRecord,
  type PhoneOtpPurpose,
  type PhoneOtpCreateUserInput,
  PhoneOtpStore,
  PhoneOtpUserStore,
} from "./PhoneOtp.ts";
import * as PhoneOtp from "./PhoneOtp.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { SessionStore } from "./SessionStore.ts";
import { SessionService, make as makeSessionService } from "./SessionService.ts";
import { UserStore } from "./UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import { Hooks } from "./Hooks.ts";
import type * as Types from "./Types.ts";
import {
  observable,
  type RecordState,
  runVerifySequence,
  verifySequences,
  wrongCode,
  zeroCrypto,
} from "./testing/Passwordless.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";

/** The no-op hooks, with the detached sends run in place so a test reads them on return. */
const TestHooks = Layer.merge(Hooks.Default, inlineDeliveryScheduler);

// --- in-memory state ---------------------------------------------------------
const users = new Map<string, Types.User>();
const identifierRecords = new Map<string, Identifier>();
const records = new Map<string, PhoneOtpRecord>();
const sessions = new Map<string, Types.Session>();
let seq = 0;

const identifiers = memoryIdentifierStore(identifierRecords);

const sentOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }> = [];

const key = (phone: string, purpose: PhoneOtpPurpose) => `${phone}:${purpose}`;

/** The name of each `PhoneOtpStore` call, in order. */
const storeOps: string[] = [];

const phoneOtpStore: typeof PhoneOtpStore.Service = {
  upsert: (record) =>
    Effect.sync(() => {
      storeOps.push("upsert");
      records.set(key(record.phoneNumber, record.purpose), record);
      return record;
    }),
  get: (phone, purpose) =>
    Effect.sync(() => {
      storeOps.push("get");
      return records.get(key(phone, purpose)) ?? null;
    }),
  delete: (phone, purpose) =>
    Effect.sync(() => {
      storeOps.push("delete");
      records.delete(key(phone, purpose));
    }),
  incrementAttempts: (phone, purpose) =>
    Effect.sync(() => {
      storeOps.push("incrementAttempts");
      const record = records.get(key(phone, purpose));
      if (!record) return 0;
      const updated = { ...record, attempts: record.attempts + 1 };
      records.set(key(phone, purpose), updated);
      return updated.attempts;
    }),
};

/** The `identifier` each `createUser` call was given. */
const createdWith: Array<PhoneOtpCreateUserInput["identifier"]> = [];

const phoneOtpUserStore: typeof PhoneOtpUserStore.Service = {
  createUser: (input) =>
    Effect.sync(() => {
      createdWith.push(input.identifier);
      const now = new Date();
      const user: Types.User = {
        id: `user-${++seq}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: now,
        updatedAt: now,
        attributes: {},
      };
      users.set(user.id, user);
      return { user, created: true };
    }),
};

// Seed an existing user with a phone identifier (the phone number lives in the
// identifier store now, not on the user record).
const seedPhoneUser = (phoneNumber: string, verified: boolean): Types.User => {
  const now = new Date();
  const user: Types.User = {
    id: `user-${++seq}`,
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
  users.set(user.id, user);
  const identifier = makeIdentifier({
    userId: user.id,
    type: "phone",
    value: phoneNumber,
    verified,
    ...(verified ? { verifiedAt: now } : {}),
  });
  identifierRecords.set(identifier.id, identifier);
  return user;
};

const sessionStore: typeof SessionStore.Service = {
  create: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  get: (sessionId) => Effect.sync(() => sessions.get(sessionId) ?? null),
  update: (session) =>
    Effect.sync(() => {
      sessions.set(session.id, session);
      return session;
    }),
  delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
};

const userStore: typeof UserStore.Service = {
  get: (userId) => Effect.sync(() => users.get(userId) ?? null),
};

const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60 * 24, idlePeriod: 1000 * 60 * 60 * 12 },
};

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      makeSessionService(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(TestHooks)),
  );
  return Context.merge(
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.merge(Context.make(IdentifierStore, identifiers), Context.make(UserStore, userStore)),
    ),
    Context.merge(
      Context.merge(
        Context.make(PhoneOtpStore, phoneOtpStore),
        Context.make(PhoneOtpUserStore, phoneOtpUserStore),
      ),
      Context.make(Crypto.Crypto, PlatformCrypto.instance),
    ),
  );
};

const recordingSend = (phoneNumber: string, otp: string, purpose: PhoneOtpPurpose) =>
  Effect.sync(() => void sentOtps.push({ phoneNumber, otp, purpose }));

const phoneNumberOf = (userId: string) => Effect.runPromise(getPhoneNumber(identifiers, userId));

describe("PhoneOtpService", () => {
  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    records.clear();
    sessions.clear();
    sentOtps.length = 0;
    storeOps.length = 0;
    seq = 0;
    createdWith.length = 0;
  });

  it("sends a numeric OTP and stores only its hash", async () => {
    const testContext = await makeTestContext();
    const program = Effect.gen(function* () {
      const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
      yield* service.send("+15551230000", "sign-in");
    });
    await Effect.runPromise(Effect.provide(program, testContext).pipe(Effect.provide(TestHooks)));

    expect(sentOtps).toHaveLength(1);
    const otp = sentOtps[0]!.otp;
    expect(otp).toMatch(/^\d{6}$/);
    const record = records.get("+15551230000:sign-in");
    expect(record?.otpHash).toBe(hashToken(otp));
    expect(record?.attempts).toBe(0);
  });

  it("signs in a new user, creating a verified phone identifier + session", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        yield* service.send("+15551231111", "sign-in");
        return yield* service.signIn("+15551231111", sentOtps[0]!.otp, {
          sessionAttributes: { device: "cli" },
        });
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );

    expect(await phoneNumberOf(result.user.id)).toBe("+15551231111");
    const identifier = await Effect.runPromise(identifiers.getByValue("phone", "+15551231111"));
    expect(identifier?.userId).toBe(result.user.id);
    expect(identifier?.verified).toBe(true);
    // The store was handed the number to create the user with (#380).
    expect(createdWith).toEqual([
      { type: "phone", value: "+15551231111", verified: true, verifiedAt: expect.any(Date) },
    ]);
    expect(result.session.userId).toBe(result.user.id);
  });

  it("signs in an existing user without creating a new one", async () => {
    const testContext = await makeTestContext();
    // Seed an existing phone user.
    seedPhoneUser("+15551232222", true);
    const before = users.size;

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        yield* service.send("+15551232222", "sign-in");
        return yield* service.signIn("+15551232222", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );

    expect(users.size).toBe(before);
    expect(await phoneNumberOf(result.user.id)).toBe("+15551232222");
  });

  it("rejects a replayed OTP (one-time use)", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        yield* service.send("+15551233333", "sign-in");
        const otp = sentOtps[0]!.otp;
        yield* service.signIn("+15551233333", otp);
        return yield* Effect.result(service.signIn("+15551233333", otp));
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(result._tag).toBe("Failure");
  });

  it("rejects expired OTPs and deletes the record", async () => {
    const testContext = await makeTestContext();
    records.set("+15551234444:sign-in", {
      phoneNumber: "+15551234444",
      otpHash: hashToken("123456"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now() - 10_000,
      expiresAt: Date.now() - 1,
    });
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        return yield* Effect.result(service.signIn("+15551234444", "123456"));
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(result._tag).toBe("Failure");
    expect(records.has("+15551234444:sign-in")).toBe(false);
  });

  it("enforces the attempt limit then invalidates the code", async () => {
    const testContext = await makeTestContext();
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend, maxAttempts: 3 });
        yield* service.send("+15551235555", "sign-in");
        const a = yield* Effect.result(service.signIn("+15551235555", "000000"));
        const b = yield* Effect.result(service.signIn("+15551235555", "000001"));
        const c = yield* Effect.result(service.signIn("+15551235555", "000002"));
        const real = yield* Effect.result(service.signIn("+15551235555", sentOtps[0]!.otp));
        return [a._tag, b._tag, c._tag, real._tag];
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(outcome).toEqual(["Failure", "Failure", "Failure", "Failure"]);
  });

  it("does not create a user or send when sign-up is disabled and no user exists, storing a marker", async () => {
    const testContext = await makeTestContext();
    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          sendOtp: recordingSend,
          disableSignUp: true,
        });
        yield* service.send("+15551236666", "sign-in");
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(sentOtps).toHaveLength(0);
    // An undelivered marker record stands in for the code (#417).
    expect(records.get("+15551236666:sign-in")?.attempts).toBe(0);
    expect(users.size).toBe(0);
  });

  it("verifies an existing user's phone number", async () => {
    const testContext = await makeTestContext();
    const created = seedPhoneUser("+15551237777", false);

    const updated = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        yield* service.send("+15551237777", "phone-verification");
        return yield* service.verifyPhoneNumber(created.id, "+15551237777", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(updated.id).toBe(created.id);
    const identifier = await Effect.runPromise(identifiers.getByValue("phone", "+15551237777"));
    expect(identifier?.userId).toBe(created.id);
    expect(identifier?.verified).toBe(true);
  });

  it("applies the normalizePhoneNumber hook for storage and lookup", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          sendOtp: recordingSend,
          normalizePhoneNumber: (raw) => Effect.succeed(raw.replace(/[^\d+]/g, "")),
        });
        yield* service.send("+1 (555) 123-8888", "sign-in");
        return yield* service.signIn("+15551238888", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(await phoneNumberOf(result.user.id)).toBe("+15551238888");
  });

  it("fails with ResendTooSoonError when a resend is within the cooldown window", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          sendOtp: recordingSend,
          resendCooldown: 60_000,
        });
        yield* service.send("+15559990001", "sign-in");
        return yield* Effect.result(service.send("+15559990001", "sign-in"));
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("ResendTooSoonError");
    expect((result.failure as { retryAfter: number }).retryAfter).toBeGreaterThan(0);
    expect((result.failure as { retryAfter: number }).retryAfter).toBeLessThanOrEqual(60_000);
    // The original OTP is preserved — no replacement was issued.
    expect(sentOtps).toHaveLength(1);
    expect(records.has("+15559990001:sign-in")).toBe(true);
  });

  it("allows a resend after the cooldown window has elapsed", async () => {
    const testContext = await makeTestContext();

    // Seed a record whose createdAt is older than the 60 s cooldown.
    records.set("+15559990002:sign-in", {
      phoneNumber: "+15559990002",
      otpHash: hashToken("000000"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now() - 70_000,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          sendOtp: recordingSend,
          resendCooldown: 60_000,
        });
        yield* service.send("+15559990002", "sign-in");
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );

    // A fresh OTP was issued after the cooldown elapsed.
    expect(sentOtps).toHaveLength(1);
    expect(records.has("+15559990002:sign-in")).toBe(true);
    // The new record has a fresh hash, not the seeded one.
    expect(records.get("+15559990002:sign-in")?.otpHash).toBe(hashToken(sentOtps[0]!.otp));
  });

  it("does not apply the cooldown when resendCooldown is not configured", async () => {
    const testContext = await makeTestContext();
    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ sendOtp: recordingSend });
        yield* service.send("+15559990003", "sign-in");
        yield* service.send("+15559990003", "sign-in");
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );
    expect(sentOtps).toHaveLength(2);
    expect(records.has("+15559990003:sign-in")).toBe(true);
  });

  // #415: with sign-up disabled, an unknown number must hit the cooldown exactly
  // as a known one does, or the second request's answer reveals the account.
  it("answers a known and an unknown number alike within the cooldown when sign-up is disabled", async () => {
    const testContext = await makeTestContext();
    seedPhoneUser("+15559990010", true);

    const { known, unknown } = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          disableSignUp: true,
          resendCooldown: 60_000,
          sendOtp: recordingSend,
        });
        const twice = (phoneNumber: string) =>
          Effect.all(
            [
              Effect.result(service.send(phoneNumber, "sign-in")),
              Effect.result(service.send(phoneNumber, "sign-in")),
            ],
            { concurrency: 1 },
          );
        return { known: yield* twice("+15559990010"), unknown: yield* twice("+15559990011") };
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
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
    // Only the account holder is sent a code; the unknown number holds an
    // undelivered record as its cooldown marker.
    expect(sentOtps.map((sent) => sent.phoneNumber)).toEqual(["+15559990010"]);
    expect(records.has("+15559990011:sign-in")).toBe(true);
    expect(users.size).toBe(1);
  });

  // #415: an unknown number's cooldown marker must never be redeemable. With
  // `zeroCrypto` the only code `send` can draw is all zeros, so a marker that
  // held an `otpLength`-digit code would match that guess.
  it("stores a cooldown marker for an unknown number that no code redeems", async () => {
    const testContext = await makeTestContext();
    seedPhoneUser("+15559990020", true);
    const otpLength = 6;
    const guess = "0".repeat(otpLength);

    const { marker, error } = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          otpLength,
          disableSignUp: true,
          resendCooldown: 60_000,
          sendOtp: recordingSend,
        }).pipe(Effect.provideService(Crypto.Crypto, zeroCrypto));
        yield* service.send("+15559990020", "sign-in");
        yield* service.send("+15559990021", "sign-in");
        const marker = records.get(key("+15559990021", "sign-in"));
        const error = yield* Effect.flip(service.signIn("+15559990021", guess));
        return { marker, error };
      }).pipe(Effect.provide(testContext), Effect.provide(TestHooks)),
    );

    // The stub draws only the all-zero code, as the account holder's shows.
    expect(sentOtps).toEqual([{ phoneNumber: "+15559990020", otp: guess, purpose: "sign-in" }]);
    expect(marker).toBeDefined();
    expect(marker?.otpHash).not.toBe(hashToken(guess));
    expect(error).toMatchObject({ _tag: "PhoneOtpError", message: "Invalid or expired OTP" });
    expect(users.size).toBe(1);
    expect(createdWith).toEqual([]);
  });
});

// #417: with sign-up disabled, `send` hides whether the number has an account,
// so verification must answer a number that holds an outstanding code exactly
// as it answers one that holds a marker record or nothing at all: through
// wrong codes, the attempt limit and expiry.
describe("PhoneOtpService verification where send hides the account (#417)", () => {
  const maxAttempts = 3;
  const expiresIn = 5 * 60 * 1000;
  const member = "+15559990100";
  const invalid = { _tag: "Failure", error: "PhoneOtpError", message: "Invalid or expired OTP" };

  beforeEach(() => {
    users.clear();
    identifierRecords.clear();
    records.clear();
    sessions.clear();
    sentOtps.length = 0;
    storeOps.length = 0;
    seq = 0;
    createdWith.length = 0;
    seedPhoneUser(member, true);
    vi.useFakeTimers({ toFake: ["Date"] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const recordOf = (phoneNumber: string) => (): RecordState | null => {
    const record = records.get(key(phoneNumber, "sign-in"));
    return record === undefined
      ? null
      : { attempts: record.attempts, lifetime: record.expiresAt - record.createdAt };
  };

  /** Run `sequence` for `phoneNumber`, requesting a code first when `send` is set. */
  const run = (
    disableSignUp: boolean,
    sequence: (typeof verifySequences)[number],
    phoneNumber: string,
    send: boolean,
  ) =>
    Effect.gen(function* () {
      const service = yield* PhoneOtp.make({
        maxAttempts,
        expiresIn,
        disableSignUp,
        sendOtp: recordingSend,
      });
      return yield* runVerifySequence(sequence, {
        maxAttempts,
        expiresIn,
        send: send ? service.send(phoneNumber, "sign-in") : undefined,
        verify: service.signIn(phoneNumber, wrongCode),
        record: recordOf(phoneNumber),
      });
    });

  const runPromise = <A, E>(
    program: Effect.Effect<
      A,
      E,
      | PhoneOtpStore
      | PhoneOtpUserStore
      | IdentifierStore
      | UserStore
      | SessionService
      | Crypto.Crypto
    >,
  ) =>
    makeTestContext().then((context) =>
      Effect.runPromise(program.pipe(Effect.provide(context), Effect.provide(TestHooks))),
    );

  it.each(verifySequences)("answers %s alike for every number", async (sequence) => {
    const { known, unknown, unrequested } = await runPromise(
      Effect.gen(function* () {
        return {
          known: yield* run(true, sequence, member, true),
          unknown: yield* run(true, sequence, "+15559990101", true),
          unrequested: yield* run(true, sequence, "+15559990102", false),
        };
      }),
    );

    // The unknown number's marker record is counted and expired exactly as
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
    // A number holding no record at all answers the same.
    expect(unrequested.map((step) => step.answer)).toEqual(known.map((step) => step.answer));
    expect(known.slice(1).map((step) => step.answer)).toEqual(known.slice(1).map(() => invalid));
    expect(sentOtps.map((sent) => sent.phoneNumber)).toEqual([member]);
  });

  it("keeps the expiry and attempt-limit answers where sign-up is enabled", async () => {
    const { wrong, expired } = await runPromise(
      Effect.gen(function* () {
        return {
          wrong: yield* run(false, "wrong codes", member, true),
          expired: yield* run(false, "expired code", member, true),
        };
      }),
    );

    const answer = (message: string) => ({ _tag: "Failure", error: "PhoneOtpError", message });
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
  });

  it("does the same store work to send to a known and an unknown number without a cooldown", async () => {
    const { knownOps, unknownOps } = await runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({ disableSignUp: true, sendOtp: recordingSend });
        yield* service.send(member, "sign-in");
        const knownOps = storeOps.splice(0);
        yield* service.send("+15559990101", "sign-in");
        return { knownOps, unknownOps: storeOps.splice(0) };
      }),
    );

    expect(unknownOps).toEqual(knownOps);
    expect(knownOps).toEqual(["upsert"]);
    expect(recordOf("+15559990101")()).toEqual(recordOf(member)());
  });

  it("answers a known number whose record has used every attempt generically", async () => {
    // The defensive branch: a record that reached `maxAttempts` without being
    // deleted. The correct code must answer the generic message as well.
    const { answer, record } = await runPromise(
      Effect.gen(function* () {
        const service = yield* PhoneOtp.make({
          maxAttempts,
          expiresIn,
          disableSignUp: true,
          sendOtp: recordingSend,
        });
        yield* service.send(member, "sign-in");
        const stored = records.get(key(member, "sign-in"))!;
        records.set(key(member, "sign-in"), { ...stored, attempts: maxAttempts });
        return {
          answer: observable(yield* Effect.result(service.signIn(member, sentOtps[0]!.otp))),
          record: recordOf(member)(),
        };
      }),
    );

    expect(answer).toEqual(invalid);
    expect(record).toBeNull();
  });

  it("keeps the specific expiry and attempt-limit messages for phone-verification", async () => {
    const created = seedPhoneUser("+15559990200", false);
    const phone = "+15559990200";
    const recordState = (): RecordState | null => {
      const record = records.get(key(phone, "phone-verification"));
      return record === undefined
        ? null
        : { attempts: record.attempts, lifetime: record.expiresAt - record.createdAt };
    };

    const { wrong, expired } = await runPromise(
      Effect.gen(function* () {
        const run = (sequence: (typeof verifySequences)[number]) =>
          Effect.gen(function* () {
            const service = yield* PhoneOtp.make({
              maxAttempts,
              expiresIn,
              disableSignUp: true,
              sendOtp: recordingSend,
            });
            return yield* runVerifySequence(sequence, {
              maxAttempts,
              expiresIn,
              send: service.send(phone, "phone-verification"),
              verify: service.verifyPhoneNumber(created.id, phone, wrongCode),
              record: recordState,
            });
          });
        return { wrong: yield* run("wrong codes"), expired: yield* run("expired code") };
      }),
    );

    const answer = (message: string) => ({ _tag: "Failure", error: "PhoneOtpError", message });
    expect(wrong.slice(1).map((step) => step.answer)).toEqual([
      answer("Invalid or expired OTP"),
      answer("Invalid or expired OTP"),
      answer("Too many attempts"),
      answer("Invalid or expired OTP"),
    ]);
    expect(expired.slice(1).map((step) => step.answer)).toEqual([
      answer("OTP has expired"),
      answer("Invalid or expired OTP"),
    ]);
  });
});
