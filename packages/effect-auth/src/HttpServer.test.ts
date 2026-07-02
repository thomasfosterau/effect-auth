import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import { makeAuthClient } from "./HttpClient.js";
import {
  SessionManagerLayer,
  SessionStoreTag,
  UserStoreTag,
  type SessionStore,
  type UserStore,
} from "./Session.js";
import { AuthLifecycleServiceLayer } from "./AuthLifecycle.js";
import { EmailPasswordStoreTag, type EmailPasswordStore } from "./EmailPassword.js";
import { PasswordHasherTag, makeScryptHasher } from "./Password.js";
import {
  EmailVerificationServiceLayer,
  EmailVerificationStoreTag,
  type EmailVerification,
  type EmailVerificationStore,
} from "./EmailVerification.js";
import {
  PasswordResetServiceLayer,
  PasswordResetStoreTag,
  PasswordResetUserStoreTag,
  type PasswordResetStore,
  type PasswordResetToken,
  type PasswordResetUserStore,
} from "./PasswordReset.js";
import { UserServiceLayer, UserServiceStoreTag, type UserServiceStore } from "./User.js";
import { Hooks } from "./Hooks.js";
import {
  MagicLinkServiceLayer,
  MagicLinkStoreTag,
  MagicLinkUserStoreTag,
  type MagicLinkStore,
  type MagicLinkToken,
  type MagicLinkUserStore,
} from "./MagicLink.js";
import {
  EmailOtpServiceLayer,
  EmailOtpStoreTag,
  EmailOtpUserStoreTag,
  type EmailOtpPurpose,
  type EmailOtpRecord,
  type EmailOtpStore,
  type EmailOtpUserStore,
} from "./EmailOtp.js";
import {
  PendingTwoFactorStoreTag,
  TwoFactorGateLayer,
  TwoFactorServiceLayer,
  TwoFactorStoreTag,
  type PendingTwoFactor,
  type PendingTwoFactorStore,
  type TwoFactorRecord,
  type TwoFactorStore,
} from "./TwoFactor.js";
import {
  AccountManagementServiceLayer,
  AccountManagementStoreTag,
  type AccountManagementStore,
  type AccountToken,
} from "./AccountManagement.js";
import {
  AnonymousServiceLayer,
  AnonymousUserStoreTag,
  type AnonymousUserStore,
} from "./Anonymous.js";
import {
  PhoneOtpServiceLayer,
  PhoneOtpStoreTag,
  PhoneOtpUserStoreTag,
  type PhoneOtpPurpose,
  type PhoneOtpRecord,
  type PhoneOtpStore,
  type PhoneOtpUserStore,
} from "./PhoneOtp.js";
import { UsernameServiceLayer, UsernameStoreTag, type UsernameStore } from "./Username.js";
import { generateTOTP } from "./Otp.js";
import { SessionNotFoundError, UserNotFoundError } from "./Errors.js";
import type * as Types from "./Types.js";

const HOUR = 60 * 60 * 1000;
const SESSION_CONFIG: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
};
const PW = "password-123";
const PW2 = "new-password-456";

// One shared (stateless) hasher; low scrypt cost keeps the suite fast while
// still exercising real hashing end to end.
const hasher = makeScryptHasher({ cost: 16384 });

interface Fixture {
  /** The base `AuthServices` layer (no optional features). */
  readonly services: Layer.Layer<AuthServices>;
  /** Base layer + magic link, email OTP, two-factor (and the 2FA gate). */
  readonly featureServices: Layer.Layer<AuthServices>;
  readonly sentVerificationTokens: string[];
  readonly sentResetTokens: string[];
  readonly sentMagicLinkTokens: string[];
  readonly sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }>;
  readonly sentChangeEmail: Array<{ newEmail: string; token: string }>;
  readonly sentDeleteTokens: string[];
  readonly beforeDeleteCalls: string[];
  readonly sentPhoneOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }>;
  /** Register a username -> userId mapping for the username sign-in tests. */
  readonly registerUsername: (userId: string, username: string) => void;
}

/**
 * A fully functional fixture: real service implementations over shared
 * in-memory stores. Outbound email is captured into arrays so tests can
 * complete token/OTP roundtrips.
 */
const makeFixture = (): Fixture => {
  // --- shared in-memory state -----------------------------------------------
  const usersById = new Map<string, Types.User>();
  const userIdByEmail = new Map<string, string>();
  const passwordHashes = new Map<string, string>();
  const sessions = new Map<string, Types.Session>();
  const verifications = new Map<string, EmailVerification>();
  const resets = new Map<string, PasswordResetToken>();
  let userSeq = 0;

  const sentVerificationTokens: string[] = [];
  const sentResetTokens: string[] = [];
  const sentMagicLinkTokens: string[] = [];
  const sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }> = [];
  const sentChangeEmail: Array<{ newEmail: string; token: string }> = [];
  const sentDeleteTokens: string[] = [];
  const beforeDeleteCalls: string[] = [];
  const sentPhoneOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }> = [];

  const createUser = (input: {
    readonly email: string;
    readonly emailVerified?: boolean;
    readonly name?: string;
    readonly image?: string;
    readonly attributes?: Record<string, unknown>;
  }): Types.User => {
    const now = new Date();
    const user: Types.User = {
      id: `user-${++userSeq}`,
      email: input.email,
      emailVerified: input.emailVerified ?? false,
      ...(input.name !== undefined && { name: input.name }),
      ...(input.image !== undefined && { image: input.image }),
      createdAt: now,
      updatedAt: now,
      attributes: input.attributes ?? {},
    };
    usersById.set(user.id, user);
    userIdByEmail.set(user.email, user.id);
    return user;
  };

  const userByEmail = (email: string): Types.User | null => {
    const id = userIdByEmail.get(email);
    return id === undefined ? null : (usersById.get(id) ?? null);
  };

  const getUserById = (userId: string) =>
    Effect.suspend(() => {
      const user = usersById.get(userId);
      return user === undefined
        ? Effect.fail(new UserNotFoundError({ message: "User not found", userId }))
        : Effect.succeed(user);
    });

  // --- core stores -----------------------------------------------------------
  const sessionStore: SessionStore = {
    create: (session) =>
      Effect.sync(() => {
        sessions.set(session.id, session);
        return session;
      }),
    get: (sessionId) =>
      Effect.suspend(() => {
        const session = sessions.get(sessionId);
        return session === undefined
          ? Effect.fail(new SessionNotFoundError({ message: "Session not found", sessionId }))
          : Effect.succeed(session);
      }),
    update: (session) =>
      Effect.sync(() => {
        sessions.set(session.id, session);
        return session;
      }),
    delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId) =>
      Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
  };

  const userStore: UserStore = {
    get: getUserById,
    getCredentials: (userId) =>
      Effect.suspend(() => {
        const hash = passwordHashes.get(userId);
        return hash === undefined
          ? Effect.fail(new UserNotFoundError({ message: "No credentials", userId }))
          : Effect.succeed(hash);
      }),
  };

  const emailPasswordStore: EmailPasswordStore = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    createUser: (input) => Effect.sync(() => createUser(input)),
    getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const userServiceStore: UserServiceStore = {
    get: getUserById,
    getByEmail: (email) => Effect.sync(() => userByEmail(email)),
    update: (user) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        userIdByEmail.set(user.email, user.id);
        return user;
      }),
    delete: (userId) =>
      Effect.sync(() => {
        const user = usersById.get(userId);
        if (user !== undefined) {
          userIdByEmail.delete(user.email);
          usersById.delete(userId);
        }
      }),
  };

  const emailVerificationStore: EmailVerificationStore = {
    create: (verification) =>
      Effect.sync(() => {
        verifications.set(verification.token, verification);
        return verification;
      }),
    get: (token) => Effect.sync(() => verifications.get(token) ?? null),
    delete: (token) => Effect.sync(() => void verifications.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, v] of verifications)
          if (v.userId === userId) verifications.delete(token);
      }),
  };

  const passwordResetStore: PasswordResetStore = {
    create: (reset) =>
      Effect.sync(() => {
        resets.set(reset.token, reset);
        return reset;
      }),
    get: (token) => Effect.sync(() => resets.get(token) ?? null),
    delete: (token) => Effect.sync(() => void resets.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [token, reset] of resets) if (reset.userId === userId) resets.delete(token);
      }),
  };

  const passwordResetUserStore: PasswordResetUserStore = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const storeLayer = Layer.mergeAll(
    Layer.succeed(SessionStoreTag)(sessionStore),
    Layer.succeed(UserStoreTag)(userStore),
    Layer.succeed(EmailPasswordStoreTag)(emailPasswordStore),
    Layer.succeed(PasswordHasherTag)(hasher),
    Layer.succeed(EmailVerificationStoreTag)(emailVerificationStore),
    Layer.succeed(PasswordResetStoreTag)(passwordResetStore),
    Layer.succeed(PasswordResetUserStoreTag)(passwordResetUserStore),
    Layer.succeed(UserServiceStoreTag)(userServiceStore),
    Hooks.Default,
  );

  const services: Layer.Layer<AuthServices> = Layer.mergeAll(
    storeLayer,
    SessionManagerLayer(SESSION_CONFIG).pipe(Layer.provide(storeLayer)),
    AuthLifecycleServiceLayer(),
    EmailVerificationServiceLayer({
      sendEmail: (_to, token) => Effect.sync(() => void sentVerificationTokens.push(token)),
    }),
    PasswordResetServiceLayer({
      sendResetPassword: (_email, token) => Effect.sync(() => void sentResetTokens.push(token)),
    }),
    UserServiceLayer(),
  );

  // --- optional feature stores -----------------------------------------------
  const magicLinks = new Map<string, MagicLinkToken>();
  const magicLinkStore: MagicLinkStore = {
    create: (token) =>
      Effect.sync(() => {
        magicLinks.set(token.token, token);
        return token;
      }),
    get: (token) => Effect.sync(() => magicLinks.get(token) ?? null),
    delete: (token) => Effect.sync(() => void magicLinks.delete(token)),
    deleteByEmail: (email) =>
      Effect.sync(() => {
        for (const [key, link] of magicLinks) if (link.email === email) magicLinks.delete(key);
      }),
  };
  const magicLinkUserStore: MagicLinkUserStore = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    createUser: (input) => Effect.sync(() => createUser(input)),
  };

  const emailOtps = new Map<string, EmailOtpRecord>();
  const otpKey = (email: string, purpose: EmailOtpPurpose) => `${purpose}:${email}`;
  const emailOtpStore: EmailOtpStore = {
    upsert: (record) =>
      Effect.sync(() => {
        emailOtps.set(otpKey(record.email, record.purpose), record);
        return record;
      }),
    get: (email, purpose) => Effect.sync(() => emailOtps.get(otpKey(email, purpose)) ?? null),
    delete: (email, purpose) => Effect.sync(() => void emailOtps.delete(otpKey(email, purpose))),
    incrementAttempts: (email, purpose) =>
      Effect.sync(() => {
        const record = emailOtps.get(otpKey(email, purpose));
        if (record === undefined) return 0;
        const updated = { ...record, attempts: record.attempts + 1 };
        emailOtps.set(otpKey(email, purpose), updated);
        return updated.attempts;
      }),
  };
  const emailOtpUserStore: EmailOtpUserStore = {
    getUserByEmail: (email) => Effect.sync(() => userByEmail(email)),
    createUser: (input) => Effect.sync(() => createUser(input)),
  };

  const twoFactorRecords = new Map<string, TwoFactorRecord>();
  const twoFactorStore: TwoFactorStore = {
    get: (userId) => Effect.sync(() => twoFactorRecords.get(userId) ?? null),
    upsert: (record) =>
      Effect.sync(() => {
        twoFactorRecords.set(record.userId, record);
        return record;
      }),
    delete: (userId) => Effect.sync(() => void twoFactorRecords.delete(userId)),
  };
  const pendingTwoFactors = new Map<string, PendingTwoFactor>();
  const pendingTwoFactorStore: PendingTwoFactorStore = {
    create: (pending) =>
      Effect.sync(() => {
        pendingTwoFactors.set(pending.token, pending);
        return pending;
      }),
    get: (token) => Effect.sync(() => pendingTwoFactors.get(token) ?? null),
    delete: (token) => Effect.sync(() => void pendingTwoFactors.delete(token)),
  };

  const twoFactorLayer = Layer.mergeAll(
    TwoFactorServiceLayer({ issuer: "effect-auth-test" }),
    Layer.succeed(TwoFactorStoreTag)(twoFactorStore),
    Layer.succeed(PendingTwoFactorStoreTag)(pendingTwoFactorStore),
  );

  const accountTokens = new Map<string, AccountToken>();
  const accountStore: AccountManagementStore = {
    create: (token) =>
      Effect.sync(() => {
        accountTokens.set(token.token, token);
        return token;
      }),
    get: (token) => Effect.sync(() => accountTokens.get(token) ?? null),
    delete: (token) => Effect.sync(() => void accountTokens.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [t, rec] of accountTokens) if (rec.userId === userId) accountTokens.delete(t);
      }),
  };

  const phoneRecords = new Map<string, PhoneOtpRecord>();
  const phoneToUserId = new Map<string, string>();
  const phoneKey = (phone: string, purpose: PhoneOtpPurpose) => `${phone}:${purpose}`;
  const phoneOtpStore: PhoneOtpStore = {
    upsert: (record) =>
      Effect.sync(() => {
        phoneRecords.set(phoneKey(record.phoneNumber, record.purpose), record);
        return record;
      }),
    get: (phone, purpose) => Effect.sync(() => phoneRecords.get(phoneKey(phone, purpose)) ?? null),
    delete: (phone, purpose) =>
      Effect.sync(() => void phoneRecords.delete(phoneKey(phone, purpose))),
    incrementAttempts: (phone, purpose) =>
      Effect.sync(() => {
        const record = phoneRecords.get(phoneKey(phone, purpose));
        if (!record) return 0;
        const updated = { ...record, attempts: record.attempts + 1 };
        phoneRecords.set(phoneKey(phone, purpose), updated);
        return updated.attempts;
      }),
  };
  const phoneOtpUserStore: PhoneOtpUserStore = {
    getUserByPhoneNumber: (phone) =>
      Effect.sync(() => {
        const id = phoneToUserId.get(phone);
        return id === undefined ? null : (usersById.get(id) ?? null);
      }),
    createUser: (input) =>
      Effect.sync(() => {
        const user = createUser({
          email: `${input.phoneNumber}@phone.local`,
          attributes: {
            phoneNumber: input.phoneNumber,
            phoneNumberVerified: input.phoneNumberVerified,
          },
        });
        phoneToUserId.set(input.phoneNumber, user.id);
        return user;
      }),
    setPhoneNumberVerified: (userId, phone) =>
      Effect.suspend(() => {
        const user = usersById.get(userId);
        if (user === undefined) {
          return Effect.fail(new UserNotFoundError({ message: "not found", userId }));
        }
        const updated: Types.User = {
          ...user,
          updatedAt: new Date(),
          attributes: { ...user.attributes, phoneNumber: phone, phoneNumberVerified: true },
        };
        usersById.set(userId, updated);
        phoneToUserId.set(phone, userId);
        return Effect.succeed(updated);
      }),
  };

  const usernameToId = new Map<string, string>();
  const usernameStore: UsernameStore = {
    getUserByUsername: (username) =>
      Effect.sync(() => {
        const id = usernameToId.get(username);
        return id === undefined ? null : (usersById.get(id) ?? null);
      }),
    isUsernameTaken: (username) => Effect.sync(() => usernameToId.has(username)),
    setUsername: (userId, username) =>
      Effect.sync(() => {
        for (const [name, id] of usernameToId) if (id === userId) usernameToId.delete(name);
        usernameToId.set(username, userId);
      }),
  };

  let anonSeq = 0;
  const anonymousUserStore: AnonymousUserStore = {
    createAnonymousUser: () =>
      Effect.sync(() =>
        createUser({
          email: `anon-${++anonSeq}@anonymous.local`,
          attributes: { isAnonymous: true },
        }),
      ),
    deleteUser: (userId) =>
      Effect.sync(() => {
        const user = usersById.get(userId);
        if (user !== undefined) {
          userIdByEmail.delete(user.email);
          usersById.delete(userId);
        }
      }),
  };

  const featureServices: Layer.Layer<AuthServices> = Layer.mergeAll(
    services,
    AnonymousServiceLayer(),
    Layer.succeed(AnonymousUserStoreTag)(anonymousUserStore),
    UsernameServiceLayer(),
    Layer.succeed(UsernameStoreTag)(usernameStore),
    PhoneOtpServiceLayer({
      sendOtp: (phoneNumber, otp, purpose) =>
        Effect.sync(() => void sentPhoneOtps.push({ phoneNumber, otp, purpose })),
    }),
    Layer.succeed(PhoneOtpStoreTag)(phoneOtpStore),
    Layer.succeed(PhoneOtpUserStoreTag)(phoneOtpUserStore),
    AccountManagementServiceLayer({
      sendChangeEmailVerification: ({ newEmail, token }) =>
        Effect.sync(() => void sentChangeEmail.push({ newEmail, token })),
      sendDeleteAccountVerification: ({ token }) =>
        Effect.sync(() => void sentDeleteTokens.push(token)),
      beforeDelete: (user) => Effect.sync(() => void beforeDeleteCalls.push(user.id)),
    }),
    Layer.succeed(AccountManagementStoreTag)(accountStore),
    MagicLinkServiceLayer({
      sendMagicLink: (_email, token) => Effect.sync(() => void sentMagicLinkTokens.push(token)),
    }),
    Layer.succeed(MagicLinkStoreTag)(magicLinkStore),
    Layer.succeed(MagicLinkUserStoreTag)(magicLinkUserStore),
    EmailOtpServiceLayer({
      sendVerificationOtp: (email, otp, purpose) =>
        Effect.sync(() => void sentOtps.push({ email, otp, purpose })),
    }),
    Layer.succeed(EmailOtpStoreTag)(emailOtpStore),
    Layer.succeed(EmailOtpUserStoreTag)(emailOtpUserStore),
    twoFactorLayer,
    // The gate makes password sign-in return `secondFactor` for enrolled users.
    TwoFactorGateLayer.pipe(Layer.provide(twoFactorLayer)),
  );

  return {
    services,
    featureServices,
    sentVerificationTokens,
    sentResetTokens,
    sentMagicLinkTokens,
    sentOtps,
    sentChangeEmail,
    sentDeleteTokens,
    beforeDeleteCalls,
    sentPhoneOtps,
    registerUsername: (userId, username) => void usernameToId.set(username, userId),
  };
};

// --- request helpers ---------------------------------------------------------

type Handler = (request: Request) => Promise<Response>;

const handlerFor = (
  fixture: Fixture = makeFixture(),
  options?: {
    readonly features?: boolean;
    readonly prefix?: string;
    readonly trustedOrigins?: ReadonlyArray<string>;
  },
): Handler =>
  makeAuthWebHandler({
    services: options?.features ? fixture.featureServices : fixture.services,
    cookie: { secure: false },
    ...(options?.prefix !== undefined && { prefix: options.prefix }),
    ...(options?.trustedOrigins !== undefined && { trustedOrigins: options.trustedOrigins }),
  }).handler;

const jsonRequest = (
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
  method: string = "POST",
) =>
  new Request(`http://test${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    ...(body !== undefined && { body: JSON.stringify(body) }),
  });

const getRequest = (path: string, headers: Record<string, string> = {}) =>
  new Request(`http://test${path}`, { headers });

const deleteRequest = (path: string, headers: Record<string, string> = {}) =>
  new Request(`http://test${path}`, { method: "DELETE", headers });

const sessionIdFromSetCookie = (setCookie: string | null): string => {
  const match = /conduit_session=([^;]+)/.exec(setCookie ?? "");
  if (match === null) throw new Error(`no session cookie in: ${setCookie}`);
  return match[1];
};

const asCookie = (sessionId: string) => ({ cookie: `conduit_session=${sessionId}` });

/** Sign a user up and return their session id (from the cookie). */
const signUp = async (handler: Handler, email: string, password: string = PW): Promise<string> => {
  const res = await handler(jsonRequest("/sign-up", { email, password }));
  expect(res.status).toBe(200);
  return sessionIdFromSetCookie(res.headers.get("set-cookie"));
};

/** Sign an existing user in and return their session id. */
const signIn = async (handler: Handler, email: string, password: string = PW): Promise<string> => {
  const res = await handler(jsonRequest("/sign-in", { email, password }));
  expect(res.status).toBe(200);
  return sessionIdFromSetCookie(res.headers.get("set-cookie"));
};

// --- tests --------------------------------------------------------------------

describe("HTTP auth protocol", () => {
  it("signs up, sets a session cookie, and returns the user", async () => {
    const handler = handlerFor();
    const res = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: PW }));

    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
    const body = (await res.json()) as {
      user: { email: string; emailVerified: boolean };
      needsEmailVerification: boolean;
    };
    expect(body.user.email).toBe("a@b.com");
    expect(body.user.emailVerified).toBe(false);
    expect(body.needsEmailVerification).toBe(false);
  });

  it("resolves the current session from the cookie", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const res = await handler(getRequest("/session", asCookie(sid)));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string } };
    expect(body.user.email).toBe("a@b.com");
  });

  it("resolves the current session from an Authorization header", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const res = await handler(getRequest("/session", { authorization: `Bearer ${sid}` }));
    expect(res.status).toBe(200);
  });

  it("returns 401 for /session without a session", async () => {
    const handler = handlerFor();
    const res = await handler(getRequest("/session"));
    expect(res.status).toBe(401);
  });

  it("returns 401 for invalid sign-in credentials", async () => {
    const handler = handlerFor();
    await signUp(handler, "a@b.com");
    const res = await handler(jsonRequest("/sign-in", { email: "a@b.com", password: "wrong-pw" }));
    expect(res.status).toBe(401);
    const body = (await res.json()) as { _tag: string };
    expect(body._tag).toBe("Unauthorized");
  });

  it("signs in an existing user and returns a fresh cookie", async () => {
    const handler = handlerFor();
    await signUp(handler, "a@b.com");
    const res = await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("signs out, clears the cookie, and invalidates the session", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const out = await handler(jsonRequest("/sign-out", undefined, asCookie(sid)));
    expect(out.status).toBe(204);
    expect(out.headers.get("set-cookie")).toContain("conduit_session=");

    const after = await handler(getRequest("/session", asCookie(sid)));
    expect(after.status).toBe(401);
  });

  it("routes under a mount prefix", async () => {
    const handler = handlerFor(makeFixture(), { prefix: "/api/auth" });
    const res = await handler(jsonRequest("/api/auth/sign-up", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("works through the derived typed client (in-memory)", async () => {
    const handler = handlerFor();
    const fetchImpl = ((input: Request | string | URL, init?: RequestInit) =>
      handler(new Request(input as never, init))) as typeof globalThis.fetch;
    const ClientLayer = FetchHttpClient.layer.pipe(
      Layer.provide(Layer.succeed(FetchHttpClient.Fetch)(fetchImpl)),
    );

    const program = Effect.gen(function* () {
      const client = yield* makeAuthClient("http://test");
      return yield* client.auth.signUp({ payload: { email: "c@d.com", password: PW } });
    }).pipe(Effect.provide(ClientLayer));

    const result = await Effect.runPromise(program);
    expect(result.user.email).toBe("c@d.com");
    expect(result.needsEmailVerification).toBe(false);
  });
});

describe("session management endpoints", () => {
  it("lists the user's active sessions", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const sid2 = await signIn(handler, "a@b.com");

    const res = await handler(getRequest("/sessions", asCookie(sid1)));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Array<{ id: string }>;
    expect(body.map((s) => s.id).sort()).toEqual([sid1, sid2].sort());
  });

  it("requires authentication to list sessions", async () => {
    const handler = handlerFor();
    const res = await handler(getRequest("/sessions"));
    expect(res.status).toBe(401);
  });

  it("revokes a single session by id", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const sid2 = await signIn(handler, "a@b.com");

    const res = await handler(deleteRequest(`/sessions/${sid2}`, asCookie(sid1)));
    expect(res.status).toBe(204);

    expect((await handler(getRequest("/session", asCookie(sid2)))).status).toBe(401);
    expect((await handler(getRequest("/session", asCookie(sid1)))).status).toBe(200);
  });

  it("rejects revoking a session the user does not own", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const otherSid = await signUp(handler, "other@b.com");

    const res = await handler(deleteRequest(`/sessions/${otherSid}`, asCookie(sid1)));
    expect(res.status).toBe(400);
    // The other user's session is untouched.
    expect((await handler(getRequest("/session", asCookie(otherSid)))).status).toBe(200);
  });

  it("revokes all other sessions but keeps the current one", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const sid2 = await signIn(handler, "a@b.com");
    const sid3 = await signIn(handler, "a@b.com");

    const res = await handler(jsonRequest("/sessions/revoke-others", undefined, asCookie(sid1)));
    expect(res.status).toBe(204);

    expect((await handler(getRequest("/session", asCookie(sid1)))).status).toBe(200);
    expect((await handler(getRequest("/session", asCookie(sid2)))).status).toBe(401);
    expect((await handler(getRequest("/session", asCookie(sid3)))).status).toBe(401);
  });
});

describe("change-password and update-user", () => {
  it("changes the password and honors revokeOtherSessions", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const sid2 = await signIn(handler, "a@b.com");

    const res = await handler(
      jsonRequest(
        "/change-password",
        { currentPassword: PW, newPassword: PW2, revokeOtherSessions: true },
        asCookie(sid1),
      ),
    );
    expect(res.status).toBe(204);

    // The other session was revoked; the current one survives.
    expect((await handler(getRequest("/session", asCookie(sid2)))).status).toBe(401);
    expect((await handler(getRequest("/session", asCookie(sid1)))).status).toBe(200);

    // The old password no longer works; the new one does.
    expect(
      (await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW }))).status,
    ).toBe(401);
    expect(
      (await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW2 }))).status,
    ).toBe(200);
  });

  it("keeps other sessions when revokeOtherSessions is not set", async () => {
    const handler = handlerFor();
    const sid1 = await signUp(handler, "a@b.com");
    const sid2 = await signIn(handler, "a@b.com");

    const res = await handler(
      jsonRequest("/change-password", { currentPassword: PW, newPassword: PW2 }, asCookie(sid1)),
    );
    expect(res.status).toBe(204);
    expect((await handler(getRequest("/session", asCookie(sid2)))).status).toBe(200);
  });

  it("rejects a wrong current password with 400", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const res = await handler(
      jsonRequest(
        "/change-password",
        { currentPassword: "not-the-password", newPassword: PW2 },
        asCookie(sid),
      ),
    );
    expect(res.status).toBe(400);
    // Password unchanged.
    expect(
      (await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW }))).status,
    ).toBe(200);
  });

  it("updates the user's profile via PATCH /user", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const res = await handler(
      jsonRequest("/user", { name: "Ada Lovelace" }, asCookie(sid), "PATCH"),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { name?: string; email: string };
    expect(body.name).toBe("Ada Lovelace");
    expect(body.email).toBe("a@b.com");

    // The update is visible on subsequent session reads.
    const session = await handler(getRequest("/session", asCookie(sid)));
    const sessionBody = (await session.json()) as { user: { name?: string } };
    expect(sessionBody.user.name).toBe("Ada Lovelace");
  });

  it("requires authentication for PATCH /user", async () => {
    const handler = handlerFor();
    const res = await handler(jsonRequest("/user", { name: "x" }, {}, "PATCH"));
    expect(res.status).toBe(401);
  });
});

describe("email verification roundtrip", () => {
  it("sends a verification email and verifies the token", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture);
    await signUp(handler, "a@b.com");

    const send = await handler(jsonRequest("/email-verification/send", { email: "a@b.com" }));
    expect(send.status).toBe(200);
    expect(await send.json()).toEqual({ status: true });
    expect(fixture.sentVerificationTokens).toHaveLength(1);

    const token = fixture.sentVerificationTokens[0];
    const verify = await handler(jsonRequest("/email-verification/verify", { token }));
    expect(verify.status).toBe(200);
    const body = (await verify.json()) as { user: { emailVerified: boolean } };
    expect(body.user.emailVerified).toBe(true);
    // Auto sign-in after verification sets a session cookie.
    expect(verify.headers.get("set-cookie")).toContain("conduit_session=");

    // Tokens are single use.
    const replay = await handler(jsonRequest("/email-verification/verify", { token }));
    expect(replay.status).toBe(400);
  });

  it("acknowledges uniformly for unknown emails (anti-enumeration)", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture);

    const res = await handler(jsonRequest("/email-verification/send", { email: "no@one.com" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: true });
    expect(fixture.sentVerificationTokens).toHaveLength(0);
  });
});

describe("password reset roundtrip", () => {
  it("requests a reset, resets the password, and invalidates the token", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture);
    await signUp(handler, "a@b.com");

    const request = await handler(jsonRequest("/password-reset/request", { email: "a@b.com" }));
    expect(request.status).toBe(200);
    expect(await request.json()).toEqual({ status: true });
    expect(fixture.sentResetTokens).toHaveLength(1);

    const token = fixture.sentResetTokens[0];
    const reset = await handler(jsonRequest("/password-reset/reset", { token, newPassword: PW2 }));
    expect(reset.status).toBe(200);
    expect(await reset.json()).toEqual({ status: true });

    // Old password fails, new password works.
    expect(
      (await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW }))).status,
    ).toBe(401);
    expect(
      (await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW2 }))).status,
    ).toBe(200);

    // Reset tokens are single use.
    const replay = await handler(
      jsonRequest("/password-reset/reset", { token, newPassword: "another-pw-789" }),
    );
    expect(replay.status).toBe(400);
  });

  it("acknowledges uniformly for unknown emails (anti-enumeration)", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture);

    const res = await handler(jsonRequest("/password-reset/request", { email: "no@one.com" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: true });
    expect(fixture.sentResetTokens).toHaveLength(0);
  });
});

describe("CSRF protection (trusted origins)", () => {
  it("rejects state-changing requests from untrusted origins with 403", async () => {
    const handler = handlerFor(makeFixture(), {
      trustedOrigins: ["https://app.example.com"],
    });
    const res = await handler(
      jsonRequest(
        "/sign-up",
        { email: "a@b.com", password: PW },
        { origin: "https://evil.example" },
      ),
    );
    expect(res.status).toBe(403);
  });

  it("allows same-origin, trusted-origin, and origin-less requests", async () => {
    const handler = handlerFor(makeFixture(), {
      trustedOrigins: ["https://app.example.com"],
    });

    // Same origin as the request URL.
    const same = await handler(
      jsonRequest("/sign-up", { email: "s@b.com", password: PW }, { origin: "http://test" }),
    );
    expect(same.status).toBe(200);

    // Explicitly trusted cross-origin.
    const trusted = await handler(
      jsonRequest(
        "/sign-up",
        { email: "t@b.com", password: PW },
        { origin: "https://app.example.com" },
      ),
    );
    expect(trusted.status).toBe(200);

    // No Origin header (curl / server-to-server).
    const none = await handler(jsonRequest("/sign-up", { email: "n@b.com", password: PW }));
    expect(none.status).toBe(200);
  });

  it("does not block safe methods on origin mismatch", async () => {
    const handler = handlerFor(makeFixture(), { trustedOrigins: [] });
    const res = await handler(getRequest("/session", { origin: "https://evil.example" }));
    // Passes CSRF (GET) and reaches the handler, which answers 401.
    expect(res.status).toBe(401);
  });
});

describe("optional features return 404 when not configured", () => {
  it("answers 404 on feature endpoints with the base fixture", async () => {
    const handler = handlerFor(); // base services: no MagicLink/EmailOtp/TwoFactor layers
    const sid = await signUp(handler, "a@b.com");

    const magicLink = await handler(jsonRequest("/magic-link/send", { email: "a@b.com" }));
    expect(magicLink.status).toBe(404);
    expect(((await magicLink.json()) as { _tag: string })._tag).toBe("NotFound");

    const emailOtp = await handler(
      jsonRequest("/email-otp/send", { email: "a@b.com", purpose: "sign-in" }),
    );
    expect(emailOtp.status).toBe(404);

    const verifyTotp = await handler(
      jsonRequest("/two-factor/verify-totp", { token: "x", code: "000000" }),
    );
    expect(verifyTotp.status).toBe(404);

    const enable = await handler(
      jsonRequest("/two-factor/enable", { password: PW }, asCookie(sid)),
    );
    expect(enable.status).toBe(404);
  });
});

describe("magic link", () => {
  it("sends a link, verifies it into a session, and rejects replays", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    const send = await handler(jsonRequest("/magic-link/send", { email: "ml@example.com" }));
    expect(send.status).toBe(200);
    expect(await send.json()).toEqual({ status: true });
    expect(fixture.sentMagicLinkTokens).toHaveLength(1);

    const token = fixture.sentMagicLinkTokens[0];
    const verify = await handler(jsonRequest("/magic-link/verify", { token }));
    expect(verify.status).toBe(200);
    const body = (await verify.json()) as {
      user: { email: string; emailVerified: boolean };
      needsEmailVerification: boolean;
    };
    // A verified link proves email ownership: the user is auto-created verified.
    expect(body.user.email).toBe("ml@example.com");
    expect(body.user.emailVerified).toBe(true);
    expect(body.needsEmailVerification).toBe(false);

    const sid = sessionIdFromSetCookie(verify.headers.get("set-cookie"));
    expect((await handler(getRequest("/session", asCookie(sid)))).status).toBe(200);

    // Tokens are single use.
    const replay = await handler(jsonRequest("/magic-link/verify", { token }));
    expect(replay.status).toBe(400);
  });

  it("rejects unknown tokens with 400", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    const res = await handler(jsonRequest("/magic-link/verify", { token: "nope" }));
    expect(res.status).toBe(400);
  });
});

describe("email OTP", () => {
  it("sends a sign-in OTP and signs the user in with it", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    const send = await handler(
      jsonRequest("/email-otp/send", { email: "otp@example.com", purpose: "sign-in" }),
    );
    expect(send.status).toBe(200);
    expect(await send.json()).toEqual({ status: true });
    expect(fixture.sentOtps).toHaveLength(1);
    expect(fixture.sentOtps[0].purpose).toBe("sign-in");

    const otp = fixture.sentOtps[0].otp;
    const res = await handler(jsonRequest("/sign-in/email-otp", { email: "otp@example.com", otp }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string; emailVerified: boolean } };
    expect(body.user.email).toBe("otp@example.com");
    expect(body.user.emailVerified).toBe(true);

    const sid = sessionIdFromSetCookie(res.headers.get("set-cookie"));
    expect((await handler(getRequest("/session", asCookie(sid)))).status).toBe(200);
  });

  it("rejects wrong OTP attempts with 400", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    await handler(jsonRequest("/email-otp/send", { email: "otp@example.com", purpose: "sign-in" }));
    const otp = fixture.sentOtps[0].otp;
    const wrong = otp === "000000" ? "111111" : "000000";

    const res = await handler(
      jsonRequest("/sign-in/email-otp", { email: "otp@example.com", otp: wrong }),
    );
    expect(res.status).toBe(400);

    // The correct code still works after a single failed attempt.
    const ok = await handler(jsonRequest("/sign-in/email-otp", { email: "otp@example.com", otp }));
    expect(ok.status).toBe(200);
  });
});

describe("two-factor", () => {
  const totpFor = (secret: string) => Effect.runPromise(generateTOTP(secret));

  it("enables, confirms, gates sign-in, and redeems a TOTP challenge", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    // Wrong password cannot enable.
    const denied = await handler(
      jsonRequest("/two-factor/enable", { password: "wrong-password" }, asCookie(sid)),
    );
    expect(denied.status).toBe(400);

    const enable = await handler(
      jsonRequest("/two-factor/enable", { password: PW }, asCookie(sid)),
    );
    expect(enable.status).toBe(200);
    const enrollment = (await enable.json()) as {
      secret: string;
      totpUri: string;
      backupCodes: string[];
    };
    expect(enrollment.totpUri).toMatch(/^otpauth:\/\/totp\//);
    expect(enrollment.backupCodes).toHaveLength(10);

    // Until confirmed, sign-in is not gated.
    const ungated = await handler(
      jsonRequest("/sign-in", { email: "2fa@example.com", password: PW }),
    );
    expect(ungated.headers.get("set-cookie")).toContain("conduit_session=");

    const confirm = await handler(
      jsonRequest("/two-factor/confirm", { code: await totpFor(enrollment.secret) }, asCookie(sid)),
    );
    expect(confirm.status).toBe(200);
    expect(await confirm.json()).toEqual({ status: true });

    // Sign-in now returns a second-factor challenge and NO session cookie.
    const gated = await handler(
      jsonRequest("/sign-in", { email: "2fa@example.com", password: PW }),
    );
    expect(gated.status).toBe(200);
    expect(gated.headers.get("set-cookie")).toBeNull();
    const gatedBody = (await gated.json()) as {
      user: { email: string };
      secondFactor?: { token: string; expiresAt: number };
    };
    expect(gatedBody.secondFactor).toBeDefined();

    // Wrong TOTP code -> 401 (the challenge remains redeemable).
    const code = await totpFor(enrollment.secret);
    const badCode = code === "000000" ? "111111" : "000000";
    const rejected = await handler(
      jsonRequest("/two-factor/verify-totp", {
        token: gatedBody.secondFactor!.token,
        code: badCode,
      }),
    );
    expect(rejected.status).toBe(401);

    // Correct TOTP code redeems the challenge into a session.
    const verified = await handler(
      jsonRequest("/two-factor/verify-totp", { token: gatedBody.secondFactor!.token, code }),
    );
    expect(verified.status).toBe(200);
    const verifiedBody = (await verified.json()) as { user: { email: string } };
    expect(verifiedBody.user.email).toBe("2fa@example.com");
    const newSid = sessionIdFromSetCookie(verified.headers.get("set-cookie"));
    expect((await handler(getRequest("/session", asCookie(newSid)))).status).toBe(200);

    // The pending token was consumed (one-time use).
    const replay = await handler(
      jsonRequest("/two-factor/verify-totp", { token: gatedBody.secondFactor!.token, code }),
    );
    expect(replay.status).toBe(401);
  });

  it("redeems backup codes exactly once", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    const enable = await handler(
      jsonRequest("/two-factor/enable", { password: PW }, asCookie(sid)),
    );
    const enrollment = (await enable.json()) as { secret: string; backupCodes: string[] };
    await handler(
      jsonRequest("/two-factor/confirm", { code: await totpFor(enrollment.secret) }, asCookie(sid)),
    );

    const challengeToken = async (): Promise<string> => {
      const res = await handler(
        jsonRequest("/sign-in", { email: "2fa@example.com", password: PW }),
      );
      const body = (await res.json()) as { secondFactor?: { token: string } };
      expect(body.secondFactor).toBeDefined();
      return body.secondFactor!.token;
    };

    const backupCode = enrollment.backupCodes[0];
    const first = await handler(
      jsonRequest("/two-factor/verify-backup-code", {
        token: await challengeToken(),
        code: backupCode,
      }),
    );
    expect(first.status).toBe(200);
    expect(first.headers.get("set-cookie")).toContain("conduit_session=");

    // The same backup code cannot be used again.
    const second = await handler(
      jsonRequest("/two-factor/verify-backup-code", {
        token: await challengeToken(),
        code: backupCode,
      }),
    );
    expect(second.status).toBe(401);
  });

  it("regenerates backup codes and disables two-factor with the password", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    const enable = await handler(
      jsonRequest("/two-factor/enable", { password: PW }, asCookie(sid)),
    );
    const enrollment = (await enable.json()) as { secret: string; backupCodes: string[] };
    await handler(
      jsonRequest("/two-factor/confirm", { code: await totpFor(enrollment.secret) }, asCookie(sid)),
    );

    const regen = await handler(
      jsonRequest("/two-factor/regenerate-backup-codes", { password: PW }, asCookie(sid)),
    );
    expect(regen.status).toBe(200);
    const regenBody = (await regen.json()) as { backupCodes: string[] };
    expect(regenBody.backupCodes).toHaveLength(10);
    expect(regenBody.backupCodes).not.toEqual(enrollment.backupCodes);

    // Old backup codes were invalidated by regeneration.
    const gated = await handler(
      jsonRequest("/sign-in", { email: "2fa@example.com", password: PW }),
    );
    const gatedBody = (await gated.json()) as { secondFactor?: { token: string } };
    const staleCode = await handler(
      jsonRequest("/two-factor/verify-backup-code", {
        token: gatedBody.secondFactor!.token,
        code: enrollment.backupCodes[0],
      }),
    );
    expect(staleCode.status).toBe(401);

    // Disable requires the password; afterwards sign-in is no longer gated.
    const disableDenied = await handler(
      jsonRequest("/two-factor/disable", { password: "wrong-password" }, asCookie(sid)),
    );
    expect(disableDenied.status).toBe(400);

    const disable = await handler(
      jsonRequest("/two-factor/disable", { password: PW }, asCookie(sid)),
    );
    expect(disable.status).toBe(200);
    expect(await disable.json()).toEqual({ status: true });

    const after = await handler(
      jsonRequest("/sign-in", { email: "2fa@example.com", password: PW }),
    );
    expect(after.status).toBe(200);
    expect(after.headers.get("set-cookie")).toContain("conduit_session=");
  });
});

describe("HTTP username sign-in", () => {
  it("signs in with a username + password", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    // Create the account (email/password) and register a username for it.
    const up = await handler(jsonRequest("/sign-up", { email: "u@example.com", password: PW }));
    const user = ((await up.json()) as { user: { id: string } }).user;
    fixture.registerUsername(user.id, "cooluser");

    const res = await handler(
      jsonRequest("/sign-in/username", { username: "cooluser", password: PW }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("returns 401 for a wrong password or unknown username", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const up = await handler(jsonRequest("/sign-up", { email: "u2@example.com", password: PW }));
    const user = ((await up.json()) as { user: { id: string } }).user;
    fixture.registerUsername(user.id, "someone");

    const wrong = await handler(
      jsonRequest("/sign-in/username", { username: "someone", password: "nope" }),
    );
    expect(wrong.status).toBe(401);
    const unknown = await handler(
      jsonRequest("/sign-in/username", { username: "ghost", password: PW }),
    );
    expect(unknown.status).toBe(401);
  });

  it("returns 404 when username sign-in is not configured", async () => {
    const handler = handlerFor(makeFixture(), { features: false });
    const res = await handler(jsonRequest("/sign-in/username", { username: "x", password: PW }));
    expect(res.status).toBe(404);
  });
});

describe("HTTP phone OTP", () => {
  it("sends an OTP and signs in a new phone user end to end", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    const send = await handler(
      jsonRequest("/phone-otp/send", { phoneNumber: "+15551234567", purpose: "sign-in" }),
    );
    expect(send.status).toBe(200);
    expect(await send.json()).toEqual({ status: true });
    expect(fixture.sentPhoneOtps).toHaveLength(1);
    const otp = fixture.sentPhoneOtps[0]!.otp;

    const signIn = await handler(
      jsonRequest("/sign-in/phone-otp", { phoneNumber: "+15551234567", otp }),
    );
    expect(signIn.status).toBe(200);
    const sid = sessionIdFromSetCookie(signIn.headers.get("set-cookie"));

    const sess = await handler(getRequest("/session", asCookie(sid)));
    const body = (await sess.json()) as { user: { attributes: Record<string, unknown> } };
    expect(body.user.attributes["phoneNumber"]).toBe("+15551234567");
    expect(body.user.attributes["phoneNumberVerified"]).toBe(true);
  });

  it("rejects a wrong OTP with 400", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    await handler(
      jsonRequest("/phone-otp/send", { phoneNumber: "+15550000000", purpose: "sign-in" }),
    );
    const res = await handler(
      jsonRequest("/sign-in/phone-otp", { phoneNumber: "+15550000000", otp: "000000" }),
    );
    expect(res.status).toBe(400);
  });

  it("returns 404 when phone OTP is not configured", async () => {
    const handler = handlerFor(makeFixture(), { features: false });
    const res = await handler(
      jsonRequest("/phone-otp/send", { phoneNumber: "+15551234567", purpose: "sign-in" }),
    );
    expect(res.status).toBe(404);
  });
});

describe("HTTP anonymous sign-in", () => {
  it("creates a guest user + session and returns 404 when unconfigured", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    const res = await handler(jsonRequest("/sign-in/anonymous", undefined));
    expect(res.status).toBe(200);
    const sid = sessionIdFromSetCookie(res.headers.get("set-cookie"));

    const sess = await handler(getRequest("/session", asCookie(sid)));
    expect(sess.status).toBe(200);
    const body = (await sess.json()) as {
      user: { email: string; attributes: Record<string, unknown> };
    };
    expect(body.user.email).toMatch(/@anonymous\.local$/);
    expect(body.user.attributes["isAnonymous"]).toBe(true);
  });

  it("returns 404 when anonymous sign-in is not configured", async () => {
    const handler = handlerFor(makeFixture(), { features: false });
    const res = await handler(jsonRequest("/sign-in/anonymous", undefined));
    expect(res.status).toBe(404);
  });
});

describe("HTTP account management (change email / delete user)", () => {
  it("changes a user's email end to end", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "alice@example.com");

    const reqRes = await handler(
      jsonRequest("/change-email/request", { newEmail: "alice2@example.com" }, asCookie(sid)),
    );
    expect(reqRes.status).toBe(200);
    expect(await reqRes.json()).toEqual({ status: true });
    expect(fixture.sentChangeEmail).toHaveLength(1);
    const token = fixture.sentChangeEmail[0]!.token;

    const confRes = await handler(jsonRequest("/change-email/confirm", { token }));
    expect(confRes.status).toBe(200);

    // Email change revoked the old session; sign in with the new address.
    const newSid = await signIn(handler, "alice2@example.com");
    const sess = await handler(getRequest("/session", asCookie(newSid)));
    expect(sess.status).toBe(200);
    const body = (await sess.json()) as { user: { email: string; emailVerified: boolean } };
    expect(body.user.email).toBe("alice2@example.com");
    expect(body.user.emailVerified).toBe(true);
  });

  it("answers { status: true } without sending when the target email is taken", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    await signUp(handler, "bob@example.com");
    const sid = await signUp(handler, "alice@example.com");

    const res = await handler(
      jsonRequest("/change-email/request", { newEmail: "bob@example.com" }, asCookie(sid)),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: true });
    expect(fixture.sentChangeEmail).toHaveLength(0);
  });

  it("requires authentication for change-email/request", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    const res = await handler(jsonRequest("/change-email/request", { newEmail: "x@example.com" }));
    expect(res.status).toBe(401);
  });

  it("rejects an invalid change-email confirm token with 400", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    const res = await handler(jsonRequest("/change-email/confirm", { token: "nope" }));
    expect(res.status).toBe(400);
  });

  it("deletes the account end to end (cleanup callback + session revocation)", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "carol@example.com");

    const reqRes = await handler(jsonRequest("/delete-user/request", undefined, asCookie(sid)));
    expect(reqRes.status).toBe(200);
    expect(fixture.sentDeleteTokens).toHaveLength(1);
    const token = fixture.sentDeleteTokens[0]!;

    const confRes = await handler(jsonRequest("/delete-user/confirm", { token }));
    expect(confRes.status).toBe(200);
    expect(fixture.beforeDeleteCalls).toHaveLength(1);

    // Sessions were invalidated and the user is gone.
    const sess = await handler(getRequest("/session", asCookie(sid)));
    expect(sess.status).toBe(401);
  });

  it("returns 404 when account management is not configured", async () => {
    const handler = handlerFor(makeFixture(), { features: false });
    const res = await handler(jsonRequest("/change-email/confirm", { token: "whatever" }));
    expect(res.status).toBe(404);
  });
});
