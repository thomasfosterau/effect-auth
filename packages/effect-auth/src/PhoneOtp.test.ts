import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Effect } from "effect";
import {
  makePhoneOtpService,
  PhoneOtpStore,
  PhoneOtpUserStore,
  getPhoneNumber,
  type PhoneOtpRecord,
  type PhoneOtpPurpose,
} from "./PhoneOtp.js";
import { hashOtp } from "./EmailOtp.js";
import {
  makeSessionManager,
  SessionManager,
  SessionStore,
  UserStore,
  type SessionStore as SessionStoreType,
  type UserStore as UserStoreType,
} from "./Session.js";
import { Hooks } from "./Hooks.js";
import { UserNotFoundError } from "./Errors.js";
import type * as Types from "./Types.js";

// --- in-memory state ---------------------------------------------------------
const users = new Map<string, Types.User>();
const phoneToId = new Map<string, string>();
const records = new Map<string, PhoneOtpRecord>();
const sessions = new Map<string, Types.Session>();
let seq = 0;

const sentOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }> = [];

const key = (phone: string, purpose: PhoneOtpPurpose) => `${phone}:${purpose}`;

const phoneOtpStore: PhoneOtpStore = {
  upsert: (record) =>
    Effect.sync(() => {
      records.set(key(record.phoneNumber, record.purpose), record);
      return record;
    }),
  get: (phone, purpose) => Effect.sync(() => records.get(key(phone, purpose)) ?? null),
  delete: (phone, purpose) => Effect.sync(() => void records.delete(key(phone, purpose))),
  incrementAttempts: (phone, purpose) =>
    Effect.sync(() => {
      const record = records.get(key(phone, purpose));
      if (!record) return 0;
      const updated = { ...record, attempts: record.attempts + 1 };
      records.set(key(phone, purpose), updated);
      return updated.attempts;
    }),
};

const phoneOtpUserStore: PhoneOtpUserStore = {
  getUserByPhoneNumber: (phone) =>
    Effect.sync(() => {
      const id = phoneToId.get(phone);
      return id === undefined ? null : (users.get(id) ?? null);
    }),
  createUser: (input) =>
    Effect.sync(() => {
      const now = new Date();
      const user: Types.User = {
        id: `user-${++seq}`,
        email: `${input.phoneNumber}@phone.local`,
        emailVerified: false,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: now,
        updatedAt: now,
        attributes: {
          phoneNumber: input.phoneNumber,
          phoneNumberVerified: input.phoneNumberVerified,
        },
      };
      users.set(user.id, user);
      phoneToId.set(input.phoneNumber, user.id);
      return user;
    }),
  setPhoneNumberVerified: (userId, phone) =>
    Effect.suspend(() => {
      const user = users.get(userId);
      if (user === undefined) {
        return Effect.fail(new UserNotFoundError({ message: "not found", userId }));
      }
      const updated: Types.User = {
        ...user,
        updatedAt: new Date(),
        attributes: { ...user.attributes, phoneNumber: phone, phoneNumberVerified: true },
      };
      users.set(userId, updated);
      phoneToId.set(phone, userId);
      return Effect.succeed(updated);
    }),
};

const sessionStore: SessionStoreType = {
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

const userStore: UserStoreType = {
  get: (userId) => Effect.sync(() => users.get(userId) ?? null),
  getCredentials: (_userId) => Effect.succeed(null),
};

const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60 * 24, idlePeriod: 1000 * 60 * 60 * 12 },
};

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      makeSessionManager(sessionConfig),
      Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
    ),
  );
  return Context.merge(
    Context.make(SessionManager, sessionManager),
    Context.merge(
      Context.make(PhoneOtpStore, phoneOtpStore),
      Context.make(PhoneOtpUserStore, phoneOtpUserStore),
    ),
  );
};

const recordingSend = (phoneNumber: string, otp: string, purpose: PhoneOtpPurpose) =>
  Effect.sync(() => void sentOtps.push({ phoneNumber, otp, purpose }));

describe("PhoneOtpService", () => {
  beforeEach(() => {
    users.clear();
    phoneToId.clear();
    records.clear();
    sessions.clear();
    sentOtps.length = 0;
    seq = 0;
  });

  it("sends a numeric OTP and stores only its hash", async () => {
    const testContext = await makeTestContext();
    const program = Effect.gen(function* () {
      const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
      yield* service.send("+15551230000", "sign-in");
    });
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentOtps).toHaveLength(1);
    const otp = sentOtps[0]!.otp;
    expect(otp).toMatch(/^\d{6}$/);
    const record = records.get("+15551230000:sign-in");
    expect(record?.otpHash).toBe(hashOtp(otp));
    expect(record?.attempts).toBe(0);
  });

  it("signs in a new user, creating a phone-verified user + session", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
        yield* service.send("+15551231111", "sign-in");
        return yield* service.signIn("+15551231111", sentOtps[0]!.otp, {
          sessionAttributes: { device: "cli" },
        });
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );

    expect(getPhoneNumber(result.user)).toBe("+15551231111");
    expect(result.user.attributes["phoneNumberVerified"]).toBe(true);
    expect(result.session.userId).toBe(result.user.id);
  });

  it("signs in an existing user without creating a new one", async () => {
    const testContext = await makeTestContext();
    // Seed an existing phone user.
    phoneOtpUserStore
      .createUser({ phoneNumber: "+15551232222", phoneNumberVerified: true })
      .pipe(Effect.runSync);
    const before = users.size;

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
        yield* service.send("+15551232222", "sign-in");
        return yield* service.signIn("+15551232222", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );

    expect(users.size).toBe(before);
    expect(getPhoneNumber(result.user)).toBe("+15551232222");
  });

  it("rejects a replayed OTP (one-time use)", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
        yield* service.send("+15551233333", "sign-in");
        const otp = sentOtps[0]!.otp;
        yield* service.signIn("+15551233333", otp);
        return yield* Effect.result(service.signIn("+15551233333", otp));
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(result._tag).toBe("Failure");
  });

  it("rejects expired OTPs and deletes the record", async () => {
    const testContext = await makeTestContext();
    records.set("+15551234444:sign-in", {
      phoneNumber: "+15551234444",
      otpHash: hashOtp("123456"),
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now() - 10_000,
      expiresAt: Date.now() - 1,
    });
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
        return yield* Effect.result(service.signIn("+15551234444", "123456"));
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(result._tag).toBe("Failure");
    expect(records.has("+15551234444:sign-in")).toBe(false);
  });

  it("enforces the attempt limit then invalidates the code", async () => {
    const testContext = await makeTestContext();
    const outcome = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend, maxAttempts: 3 });
        yield* service.send("+15551235555", "sign-in");
        const a = yield* Effect.result(service.signIn("+15551235555", "000000"));
        const b = yield* Effect.result(service.signIn("+15551235555", "000001"));
        const c = yield* Effect.result(service.signIn("+15551235555", "000002"));
        const real = yield* Effect.result(service.signIn("+15551235555", sentOtps[0]!.otp));
        return [a._tag, b._tag, c._tag, real._tag];
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(outcome).toEqual(["Failure", "Failure", "Failure", "Failure"]);
  });

  it("does not create a user or send when sign-up is disabled and no user exists", async () => {
    const testContext = await makeTestContext();
    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({
          sendOtp: recordingSend,
          disableSignUp: true,
        });
        yield* service.send("+15551236666", "sign-in");
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(sentOtps).toHaveLength(0);
    expect(records.size).toBe(0);
  });

  it("verifies an existing user's phone number", async () => {
    const testContext = await makeTestContext();
    const created = phoneOtpUserStore
      .createUser({ phoneNumber: "+15551237777", phoneNumberVerified: false })
      .pipe(Effect.runSync);

    const updated = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({ sendOtp: recordingSend });
        yield* service.send("+15551237777", "phone-verification");
        return yield* service.verifyPhoneNumber(created.id, "+15551237777", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(updated.attributes["phoneNumberVerified"]).toBe(true);
  });

  it("applies the normalizePhoneNumber hook for storage and lookup", async () => {
    const testContext = await makeTestContext();
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* makePhoneOtpService({
          sendOtp: recordingSend,
          normalizePhoneNumber: (raw) => Effect.succeed(raw.replace(/[^\d+]/g, "")),
        });
        yield* service.send("+1 (555) 123-8888", "sign-in");
        return yield* service.signIn("+15551238888", sentOtps[0]!.otp);
      }).pipe(Effect.provide(testContext), Effect.provide(Hooks.Default)),
    );
    expect(getPhoneNumber(result.user)).toBe("+15551238888");
  });
});
