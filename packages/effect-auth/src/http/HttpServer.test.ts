import { describe, it, expect } from "vite-plus/test";
import { Data, Effect, Fiber, FileSystem, Layer, Logger, Path, Redacted } from "effect";
import { Etag, FetchHttpClient, HttpPlatform, HttpRouter } from "effect/http";
import { HttpApiBuilder } from "effect/http-api";
import { BEARER_TOKEN_HEADER, type AuthServices } from "./HttpServer.ts";
import * as HttpServer from "./HttpServer.ts";
import * as HttpClient from "./HttpClient.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import { SessionService } from "../SessionService.ts";
import { AuthLifecycleService } from "../AuthLifecycle.ts";
import { EmailPasswordService, EmailPasswordStore } from "../email/EmailPassword.ts";
import { PasswordHasher } from "../password/Password.ts";
import * as Password from "../password/Password.ts";
import {
  EmailVerificationStore,
  type EmailVerification,
  EmailVerificationService,
} from "../email/EmailVerification.ts";
import {
  PasswordResetStore,
  PasswordResetUserStore,
  type PasswordResetToken,
  PasswordResetService,
} from "../password/PasswordReset.ts";
import { UserServiceStore, UserService } from "../User.ts";
import { hashToken } from "../TokenHash.ts";
import { composePlugins, Hooks } from "../Hooks.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "../Identifier.ts";
import {
  MagicLinkStore,
  MagicLinkUserStore,
  type MagicLinkToken,
  MagicLinkService,
} from "../MagicLink.ts";
import {
  EmailOtpStore,
  EmailOtpUserStore,
  type EmailOtpPurpose,
  type EmailOtpRecord,
  EmailOtpService,
} from "../email/EmailOtp.ts";
import {
  PendingMultiFactorStore,
  MultiFactorGateLayer,
  MultiFactorStore,
  type PendingMultiFactor,
  type MultiFactorRecord,
  MultiFactorService,
} from "../multifactor/MultiFactor.ts";
import {
  AccountManagementStore,
  type AccountToken,
  AccountManagementService,
} from "../AccountManagement.ts";
import { AnonymousUserStore, AnonymousService } from "../Anonymous.ts";
import {
  PhoneOtpStore,
  PhoneOtpUserStore,
  type PhoneOtpPurpose,
  type PhoneOtpRecord,
  PhoneOtpService,
} from "../PhoneOtp.ts";
import { UsernameService } from "../Username.ts";
import {
  DeviceAuthorizationStore,
  type DeviceAuthorizationRecord,
  DeviceAuthorizationService,
} from "../DeviceAuthorization.ts";
import { generateHotp, generateTotp } from "../multifactor/Otp.ts";
import type * as Types from "../Types.ts";
import { ClientIP, type TrustedProxyConfig } from "../ClientIP.ts";
import { ClientAddressConfigError, RateLimiterConfigError } from "../Errors.ts";
import { IPRateLimitPlugin } from "../plugins/IPRateLimit.ts";
import { NormalizeEmailPlugin } from "../plugins/NormalizeEmail.ts";
import { AuthApi } from "./HttpApi.ts";
import { RateLimiter, RateLimitStore, type RateLimitEntry } from "../RateLimit.ts";

const HOUR = 60 * 60 * 1000;
const SESSION_CONFIG: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
};
const PW = "password-123";
const PW2 = "new-password-456";

// One shared (stateless) hasher; low scrypt cost keeps the suite fast while
// still exercising real hashing end to end.
const hasher = Password.scryptHasher({ cost: 1024 });

interface Fixture {
  /** The base `AuthServices` layer (no optional features). */
  readonly services: Layer.Layer<AuthServices>;
  /** Base layer + magic link, email OTP, multi-factor (and the 2FA gate). */
  readonly featureServices: Layer.Layer<AuthServices>;
  /** `featureServices` with no `RateLimiter`, for the build check (#389). */
  readonly featureServicesWithoutRateLimiter: Layer.Layer<AuthServices>;
  readonly sentVerificationTokens: string[];
  readonly sentResetTokens: string[];
  readonly sentMagicLinkTokens: string[];
  readonly sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }>;
  readonly sentChangeEmail: Array<{ newEmail: string; token: string }>;
  readonly sentDeleteTokens: string[];
  readonly beforeDeleteCalls: string[];
  readonly sentPhoneOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }>;
  /** Register a verified `username` identifier for the username sign-in tests. */
  readonly registerUsername: (userId: string, username: string) => void;
  /** Number of session-store `get` reads so far (for the cookie-cache tests). */
  readonly sessionStoreReads: () => number;
}

/**
 * A fully functional fixture: real service implementations over shared
 * in-memory stores. Outbound email is captured into arrays so tests can
 * complete token/OTP roundtrips.
 */
const makeFixture = (
  options: {
    /** The `Hooks` stack in `services`. Default `Hooks.Default`. */
    readonly hooks?: Layer.Layer<Hooks> | undefined;
    /** Build the device service with `allowMissingRateLimiter: true` (#389). */
    readonly deviceAllowMissingRateLimiter?: boolean | undefined;
  } = {},
): Fixture => {
  // --- shared in-memory state -----------------------------------------------
  const usersById = new Map<string, Types.User>();
  const identifierRecords = new Map<string, Identifier>();
  const passwordHashes = new Map<string, string>();
  const sessions = new Map<string, Types.Session>();
  const verifications = new Map<string, EmailVerification>();
  const resets = new Map<string, PasswordResetToken>();
  let userSeq = 0;
  let sessionStoreReads = 0;

  const sentVerificationTokens: string[] = [];
  const sentResetTokens: string[] = [];
  const sentMagicLinkTokens: string[] = [];
  const sentOtps: Array<{ email: string; otp: string; purpose: EmailOtpPurpose }> = [];
  const sentChangeEmail: Array<{ newEmail: string; token: string }> = [];
  const sentDeleteTokens: string[] = [];
  const beforeDeleteCalls: string[] = [];
  const sentPhoneOtps: Array<{ phoneNumber: string; otp: string; purpose: PhoneOtpPurpose }> = [];

  // Users are surrogate-keyed: login handles (email/username/phone) live in
  // `identifierRecords` and are claimed by the services themselves.
  const createUser = (input: {
    readonly name?: string;
    readonly image?: string;
    readonly attributes?: Record<string, unknown>;
  }): Types.User => {
    const now = new Date();
    const user: Types.User = {
      id: `user-${++userSeq}`,
      ...(input.name !== undefined && { name: input.name }),
      ...(input.image !== undefined && { image: input.image }),
      createdAt: now,
      updatedAt: now,
      attributes: input.attributes ?? {},
    };
    usersById.set(user.id, user);
    return user;
  };

  const getUserById = (userId: string) => Effect.sync(() => usersById.get(userId) ?? null);

  // --- core stores -----------------------------------------------------------
  const sessionStore: typeof SessionStore.Service = {
    create: (session) =>
      Effect.sync(() => {
        sessions.set(session.id, session);
        return session;
      }),
    get: (sessionId) =>
      Effect.sync(() => {
        sessionStoreReads++;
        return sessions.get(sessionId) ?? null;
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

  const userStore: typeof UserStore.Service = {
    get: getUserById,
  };

  const emailPasswordStore: typeof EmailPasswordStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
    getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const userServiceStore: typeof UserServiceStore.Service = {
    get: getUserById,
    update: (user) =>
      Effect.sync(() => {
        usersById.set(user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void usersById.delete(userId)),
  };

  const emailVerificationStore: typeof EmailVerificationStore.Service = {
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

  const passwordResetStore: typeof PasswordResetStore.Service = {
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

  const passwordResetUserStore: typeof PasswordResetUserStore.Service = {
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };

  const storeLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(EmailPasswordStore)(emailPasswordStore),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(identifierRecords)),
    Layer.succeed(PasswordHasher)(hasher),
    Layer.succeed(EmailVerificationStore)(emailVerificationStore),
    Layer.succeed(PasswordResetStore)(passwordResetStore),
    Layer.succeed(PasswordResetUserStore)(passwordResetUserStore),
    Layer.succeed(UserServiceStore)(userServiceStore),
    options.hooks ?? Hooks.Default,
  );

  const sessionServiceLayer = SessionService.layer(SESSION_CONFIG).pipe(Layer.provide(storeLayer));

  // Stage 1: services needing only raw stores + Hooks + SessionService.
  const stage1 = Layer.mergeAll(
    storeLayer,
    sessionServiceLayer,
    UserService.layer().pipe(Layer.provide(storeLayer)),
    EmailVerificationService.layer({
      sendEmail: (_to, token) => Effect.sync(() => void sentVerificationTokens.push(token)),
    }).pipe(Layer.provide(storeLayer)),
  );

  // Stage 2: services needing stage-1 services (e.g. SessionService).
  const emailPasswordServiceLayer = EmailPasswordService.layer().pipe(Layer.provide(stage1));
  const passwordResetServiceLayer = PasswordResetService.layer({
    sendResetPassword: (_email, token) => Effect.sync(() => void sentResetTokens.push(token)),
  }).pipe(Layer.provide(stage1));
  const stage2 = Layer.mergeAll(stage1, emailPasswordServiceLayer, passwordResetServiceLayer);

  // Stage 3: AuthLifecycleService needs EmailPasswordService + others from stage 2.
  const authLifecycleServiceLayer = AuthLifecycleService.layer().pipe(Layer.provide(stage2));

  // `baseServices` keeps every output of the stage layers — the optional
  // feature services below are built on top of it and read the raw stores
  // (`UserStore`, `UserServiceStore`, `EmailPasswordStore`) directly, so
  // narrowing to `AuthServices` first would leave those in their `RIn`.
  // `services` is the same layer, narrowed to what the HTTP server asks for.
  const baseServices = Layer.mergeAll(stage2, authLifecycleServiceLayer);
  const services: Layer.Layer<AuthServices> = baseServices;

  // --- optional feature stores -----------------------------------------------
  const magicLinks = new Map<string, MagicLinkToken>();
  const magicLinkStore: typeof MagicLinkStore.Service = {
    create: (token) =>
      Effect.sync(() => {
        magicLinks.set(token.token, token);
        return token;
      }),
    get: (token) => Effect.sync(() => magicLinks.get(token) ?? null),
    getByEmail: (email) =>
      Effect.sync(() => {
        for (const link of magicLinks.values()) if (link.email === email) return link;
        return null;
      }),
    delete: (token) => Effect.sync(() => void magicLinks.delete(token)),
    deleteByEmail: (email) =>
      Effect.sync(() => {
        for (const [key, link] of magicLinks) if (link.email === email) magicLinks.delete(key);
      }),
  };
  const magicLinkUserStore: typeof MagicLinkUserStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
  };

  const emailOtps = new Map<string, EmailOtpRecord>();
  const otpKey = (email: string, purpose: EmailOtpPurpose) => `${purpose}:${email}`;
  const emailOtpStore: typeof EmailOtpStore.Service = {
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
  const emailOtpUserStore: typeof EmailOtpUserStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
  };

  const multiFactorRecords = new Map<string, MultiFactorRecord>();
  const multiFactorStore: typeof MultiFactorStore.Service = {
    get: (userId) => Effect.sync(() => multiFactorRecords.get(userId) ?? null),
    upsert: (record) =>
      Effect.sync(() => {
        multiFactorRecords.set(record.userId, record);
        return record;
      }),
    delete: (userId) => Effect.sync(() => void multiFactorRecords.delete(userId)),
  };
  const pendingMultiFactors = new Map<string, PendingMultiFactor>();
  const pendingMultiFactorStore: typeof PendingMultiFactorStore.Service = {
    create: (pending) =>
      Effect.sync(() => {
        pendingMultiFactors.set(pending.token, pending);
        return pending;
      }),
    get: (token) => Effect.sync(() => pendingMultiFactors.get(token) ?? null),
    delete: (token) => Effect.sync(() => void pendingMultiFactors.delete(token)),
  };

  const accountTokens = new Map<string, AccountToken>();
  const accountStore: typeof AccountManagementStore.Service = {
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
  const phoneKey = (phone: string, purpose: PhoneOtpPurpose) => `${phone}:${purpose}`;
  const phoneOtpStore: typeof PhoneOtpStore.Service = {
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
  // The phone number itself is claimed as a verified `phone` identifier by the
  // service; the user store only creates the bare profile row.
  const phoneOtpUserStore: typeof PhoneOtpUserStore.Service = {
    createUser: (input) => Effect.sync(() => ({ user: createUser(input), created: true })),
  };

  const deviceRecords = new Map<string, DeviceAuthorizationRecord>();
  const deviceStore: typeof DeviceAuthorizationStore.Service = {
    create: (record) =>
      Effect.sync(() => {
        deviceRecords.set(record.deviceCode, record);
        return record;
      }),
    getByDeviceCode: (deviceCode) => Effect.sync(() => deviceRecords.get(deviceCode) ?? null),
    getByUserCode: (userCode) =>
      Effect.sync(() => [...deviceRecords.values()].find((r) => r.userCode === userCode) ?? null),
    update: (record) =>
      Effect.sync(() => {
        deviceRecords.set(record.deviceCode, record);
        return record;
      }),
    delete: (deviceCode) => Effect.sync(() => void deviceRecords.delete(deviceCode)),
    claimApproval: (deviceCode) =>
      Effect.sync(() => {
        const record = deviceRecords.get(deviceCode);
        if (record === undefined || record.status !== "approved") return null;
        deviceRecords.delete(deviceCode);
        return record;
      }),
  };

  // Username handles are `username` identifiers (created verified); the old
  // dedicated UsernameStore no longer exists.
  const registerUsername = (userId: string, username: string): void => {
    const identifier = makeIdentifier({
      userId,
      type: "username",
      value: username,
      verified: true,
    });
    identifierRecords.set(identifier.id, identifier);
  };

  const anonymousUserStore: typeof AnonymousUserStore.Service = {
    createAnonymousUser: () => Effect.sync(() => createUser({ attributes: { isAnonymous: true } })),
    deleteUser: (userId) => Effect.sync(() => void usersById.delete(userId)),
  };

  // Every optional-feature store, merged with the base services layer:
  // enough to satisfy any feature service's construction-time dependencies
  // (their own store(s) plus SessionService/IdentifierStore/PasswordHasher/
  // UserStore/Hooks already provided by `baseServices`).
  const featureBase = Layer.mergeAll(
    baseServices,
    Layer.succeed(AnonymousUserStore)(anonymousUserStore),
    Layer.succeed(DeviceAuthorizationStore)(deviceStore),
    Layer.succeed(PhoneOtpStore)(phoneOtpStore),
    Layer.succeed(PhoneOtpUserStore)(phoneOtpUserStore),
    Layer.succeed(AccountManagementStore)(accountStore),
    Layer.succeed(MagicLinkStore)(magicLinkStore),
    Layer.succeed(MagicLinkUserStore)(magicLinkUserStore),
    Layer.succeed(EmailOtpStore)(emailOtpStore),
    Layer.succeed(EmailOtpUserStore)(emailOtpUserStore),
    Layer.succeed(MultiFactorStore)(multiFactorStore),
    Layer.succeed(PendingMultiFactorStore)(pendingMultiFactorStore),
  );

  const multiFactorServiceLayer = MultiFactorService.layer({ issuer: "effect-auth-test" }).pipe(
    Layer.provide(featureBase),
  );

  const featureServicesWithoutRateLimiter: Layer.Layer<AuthServices> = Layer.mergeAll(
    featureBase,
    AnonymousService.layer().pipe(Layer.provide(featureBase)),
    UsernameService.layer().pipe(Layer.provide(featureBase)),
    DeviceAuthorizationService.layer({
      verificationUri: "https://example.com/device",
      // interval 0 so back-to-back polls in a single test don't hit slow_down.
      interval: 0,
      allowMissingRateLimiter: options.deviceAllowMissingRateLimiter,
    }).pipe(Layer.provide(featureBase)),
    PhoneOtpService.layer({
      sendOtp: (phoneNumber, otp, purpose) =>
        Effect.sync(() => void sentPhoneOtps.push({ phoneNumber, otp, purpose })),
    }).pipe(Layer.provide(featureBase)),
    AccountManagementService.layer({
      sendChangeEmailVerification: ({ newEmail, token }) =>
        Effect.sync(() => void sentChangeEmail.push({ newEmail, token })),
      sendDeleteAccountVerification: ({ token }) =>
        Effect.sync(() => void sentDeleteTokens.push(token)),
      beforeDelete: (user) => Effect.sync(() => void beforeDeleteCalls.push(user.id)),
    }).pipe(Layer.provide(featureBase)),
    MagicLinkService.layer({
      sendMagicLink: (_email, token) => Effect.sync(() => void sentMagicLinkTokens.push(token)),
    }).pipe(Layer.provide(featureBase)),
    EmailOtpService.layer({
      sendVerificationOtp: (email, otp, purpose) =>
        Effect.sync(() => void sentOtps.push({ email, otp, purpose })),
    }).pipe(Layer.provide(featureBase)),
    multiFactorServiceLayer,
    // The gate makes password sign-in return `secondFactor` for enrolled users.
    MultiFactorGateLayer.pipe(Layer.provide(multiFactorServiceLayer)),
  );

  // The device user-code limit runs only with a RateLimiter (#389), so the feature
  // set that includes device authorization carries one.
  const featureServices = Layer.merge(
    featureServicesWithoutRateLimiter,
    memoryRateLimiterLayer(),
  ) as Layer.Layer<AuthServices>;

  return {
    services,
    featureServices,
    featureServicesWithoutRateLimiter,
    sentVerificationTokens,
    sentResetTokens,
    sentMagicLinkTokens,
    sentOtps,
    sentChangeEmail,
    sentDeleteTokens,
    beforeDeleteCalls,
    sentPhoneOtps,
    registerUsername,
    sessionStoreReads: () => sessionStoreReads,
  };
};

/** A `RateLimiter` over an in-memory store, for the limits that need one (#389). */
const memoryRateLimiterLayer = (): Layer.Layer<RateLimiter> =>
  RateLimiter.layer().pipe(Layer.provide(memoryRateLimitStoreLayer()));

/** An in-memory `RateLimitStore`. */
const memoryRateLimitStoreLayer = (): Layer.Layer<RateLimitStore> => {
  const entries = new Map<string, RateLimitEntry>();
  const store = {
    get: (key: string) => Effect.sync(() => entries.get(key) ?? null),
    set: (key: string, entry: RateLimitEntry, _ttl: number) =>
      Effect.sync(() => void entries.set(key, entry)),
    increment: (key: string, _ttl: number) =>
      Effect.sync(() => {
        const entry = entries.get(key);
        const count = (entry?.count ?? 0) + 1;
        if (entry) entries.set(key, { ...entry, count });
        return count;
      }),
    delete: (key: string) => Effect.sync(() => void entries.delete(key)),
  };
  return Layer.succeed(RateLimitStore, store);
};

// --- request helpers ---------------------------------------------------------

type Handler = (request: Request) => Promise<Response>;

const handlerFor = (
  fixture: Fixture = makeFixture(),
  options?: {
    readonly features?: boolean;
    readonly prefix?: string;
    readonly trustedOrigins?: ReadonlyArray<string>;
    readonly cache?: { readonly secret: string; readonly maxAge?: number };
    readonly multiSession?: { readonly maximumSessions?: number };
    readonly maxBodySize?: number;
    readonly secure?: boolean;
    readonly bearerMode?: boolean | "opt-in";
  },
): Handler =>
  HttpServer.make({
    services: options?.features ? fixture.featureServices : fixture.services,
    ...(options?.multiSession !== undefined && { multiSession: options.multiSession }),
    cookie: {
      secure: options?.secure ?? false,
      ...(options?.cache !== undefined && {
        cache: {
          enabled: true,
          secret: Redacted.make(options.cache.secret),
          ...(options.cache.maxAge !== undefined && { maxAge: options.cache.maxAge }),
        },
      }),
      ...(options?.bearerMode !== undefined && { bearerMode: options.bearerMode }),
    },
    ...(options?.prefix !== undefined && { prefix: options.prefix }),
    ...(options?.trustedOrigins !== undefined && { trustedOrigins: options.trustedOrigins }),
    ...(options?.maxBodySize !== undefined && { maxBodySize: options.maxBodySize }),
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

  it("applies __Host- cookie prefix when secure is true", async () => {
    const handler = handlerFor(makeFixture(), { secure: true });
    // Use a full https URL so the CSRF origin check passes for the same-origin case.
    const res = await handler(
      new Request("https://example.com/sign-up", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "a@b.com", password: PW }),
      }),
    );
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("__Host-conduit_session=");
    expect(setCookie).toContain("; Secure");
  });

  it("does not apply __Host- prefix when secure is false", async () => {
    const handler = handlerFor(makeFixture(), { secure: false });
    const res = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie");
    expect(setCookie).toContain("conduit_session=");
    expect(setCookie).not.toContain("__Host-");
  });

  it("works through the derived typed client (in-memory)", async () => {
    const handler = handlerFor();
    const fetchImpl = ((input: Request | string | URL, init?: RequestInit) =>
      handler(new Request(input as never, init))) as typeof globalThis.fetch;
    const ClientLayer = FetchHttpClient.layer.pipe(
      Layer.provide(Layer.succeed(FetchHttpClient.Fetch)(fetchImpl)),
    );

    const program = Effect.gen(function* () {
      const client = yield* HttpClient.client("http://test");
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
    expect(body.map((s) => s.id).sort()).toEqual([hashToken(sid1), hashToken(sid2)].sort());
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

describe("identifier endpoints", () => {
  it("lists the signed-in user's identifiers", async () => {
    const handler = handlerFor();
    const sid = await signUp(handler, "a@b.com");

    const res = await handler(getRequest("/identifiers", asCookie(sid)));
    expect(res.status).toBe(200);
    const list = (await res.json()) as Array<{
      id: string;
      type: string;
      value: string;
      verified: boolean;
      createdAt: number;
    }>;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ type: "email", value: "a@b.com", verified: false });
  });

  it("requires authentication to list identifiers", async () => {
    const handler = handlerFor();
    const res = await handler(getRequest("/identifiers"));
    expect(res.status).toBe(401);
  });

  it("deletes an identifier but refuses foreign, unknown, and last ones", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture);
    const up = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: PW }));
    expect(up.status).toBe(200);
    const userId = ((await up.json()) as { user: { id: string } }).user.id;
    const sid = sessionIdFromSetCookie(up.headers.get("set-cookie"));
    fixture.registerUsername(userId, "cooluser");
    const otherSid = await signUp(handler, "other@b.com");

    const listRes = await handler(getRequest("/identifiers", asCookie(sid)));
    const list = (await listRes.json()) as Array<{ id: string; type: string }>;
    expect(list).toHaveLength(2);
    const username = list.find((identifier) => identifier.type === "username")!;
    const email = list.find((identifier) => identifier.type === "email")!;

    // Another user cannot delete an identifier they do not own.
    const foreign = await handler(deleteRequest(`/identifiers/${username.id}`, asCookie(otherSid)));
    expect(foreign.status).toBe(400);

    // Unknown ids get the same 400 (anti-enumeration).
    const unknown = await handler(deleteRequest("/identifiers/nope", asCookie(sid)));
    expect(unknown.status).toBe(400);

    // The owner deletes their username identifier.
    const deleted = await handler(deleteRequest(`/identifiers/${username.id}`, asCookie(sid)));
    expect(deleted.status).toBe(204);
    const after = await handler(getRequest("/identifiers", asCookie(sid)));
    const remaining = (await after.json()) as Array<{ id: string }>;
    expect(remaining.map((identifier) => identifier.id)).toEqual([email.id]);

    // The account's only remaining identifier cannot be deleted.
    const last = await handler(deleteRequest(`/identifiers/${email.id}`, asCookie(sid)));
    expect(last.status).toBe(400);
  });

  it("requires authentication to delete an identifier", async () => {
    const handler = handlerFor();
    const res = await handler(deleteRequest("/identifiers/some-id"));
    expect(res.status).toBe(401);
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

  it("uses Referer as CSRF fallback when Origin is absent", async () => {
    const handler = handlerFor(makeFixture(), { trustedOrigins: [] });

    // Referer with a matching origin → allowed.
    const sameReferer = await handler(
      new Request("http://test/sign-up", {
        method: "POST",
        headers: { "content-type": "application/json", referer: "http://test/page" },
        body: JSON.stringify({ email: "a@b.com", password: PW }),
      }),
    );
    expect(sameReferer.status).toBe(200);

    // Referer with a cross-origin → blocked.
    const crossReferer = await handler(
      new Request("http://test/sign-up", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          referer: "https://evil.example/page",
        },
        body: JSON.stringify({ email: "b@b.com", password: PW }),
      }),
    );
    expect(crossReferer.status).toBe(403);
  });

  it("applies CSRF check to GET /token (JWT issuance)", async () => {
    const handler = handlerFor(makeFixture(), { trustedOrigins: [] });

    // GET /token with a cross-origin Referer should be blocked.
    const res = await handler(
      new Request("http://test/token", {
        method: "GET",
        headers: { referer: "https://evil.example/page" },
      }),
    );
    // Blocked by CSRF (not 401 or 404 — those would mean CSRF was bypassed).
    expect(res.status).toBe(403);
  });
});

describe("request body size limit", () => {
  it("rejects requests whose Content-Length exceeds maxBodySize with 413", async () => {
    const handler = handlerFor(makeFixture(), { maxBodySize: 100 });
    const res = await handler(
      new Request("http://test/sign-up", {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "101" },
        body: JSON.stringify({ email: "a@b.com", password: PW }),
      }),
    );
    expect(res.status).toBe(413);
    const body = (await res.json()) as { message: string };
    expect(body.message).toBe("Payload too large");
  });

  it("allows requests within the body size limit", async () => {
    const handler = handlerFor(makeFixture(), { maxBodySize: 65536 });
    const res = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(200);
  });

  it("allows requests when Content-Length is absent even if body would exceed limit", async () => {
    const handler = handlerFor(makeFixture(), { maxBodySize: 1 });
    // No Content-Length header — the check is advisory and cannot reject without reading.
    const res = await handler(
      new Request("http://test/sign-up", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "a@b.com", password: PW }),
      }),
    );
    // Should pass the size gate (no Content-Length) and either succeed or fail
    // for another reason (e.g. body actually read fine).
    expect(res.status).not.toBe(413);
  });
});

describe("mount prefix: 404 for out-of-prefix paths", () => {
  it("returns 404 for paths outside the configured prefix", async () => {
    const handler = handlerFor(makeFixture(), { prefix: "/api/auth" });
    const res = await handler(jsonRequest("/sign-up", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(404);
    const body = (await res.json()) as { message: string };
    expect(body.message).toBe("Not Found");
  });

  it("returns 404 for completely unrelated paths when prefix is set", async () => {
    const handler = handlerFor(makeFixture(), { prefix: "/api/auth" });
    const res = await handler(getRequest("/other-service/data"));
    expect(res.status).toBe(404);
  });

  it("routes prefixed paths correctly and leaves non-prefixed as 404", async () => {
    const handler = handlerFor(makeFixture(), { prefix: "/api/auth" });

    // Correct prefixed path → 200.
    const prefixed = await handler(
      jsonRequest("/api/auth/sign-up", { email: "a@b.com", password: PW }),
    );
    expect(prefixed.status).toBe(200);

    // Same path without prefix → 404.
    const unprefixed = await handler(jsonRequest("/sign-up", { email: "b@b.com", password: PW }));
    expect(unprefixed.status).toBe(404);
  });
});

describe("optional features return 404 when not configured", () => {
  it("answers 404 on feature endpoints with the base fixture", async () => {
    const handler = handlerFor(); // base services: no MagicLink/EmailOtp/MultiFactor layers
    const sid = await signUp(handler, "a@b.com");

    const magicLink = await handler(jsonRequest("/magic-link/send", { email: "a@b.com" }));
    expect(magicLink.status).toBe(404);
    expect(((await magicLink.json()) as { _tag: string })._tag).toBe("NotFound");

    const emailOtp = await handler(
      jsonRequest("/email-otp/send", { email: "a@b.com", purpose: "sign-in" }),
    );
    expect(emailOtp.status).toBe(404);

    const verifyTotp = await handler(
      jsonRequest("/multi-factor/verify-totp", { token: "x", code: "000000" }),
    );
    expect(verifyTotp.status).toBe(404);

    const enable = await handler(
      jsonRequest("/multi-factor/enable", { password: PW }, asCookie(sid)),
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

describe("multi-factor", () => {
  const totpFor = (secret: string) => Effect.runPromise(generateTotp(secret));
  // The previous time step's code (within the default ±1 window). Confirming
  // enrollment with it leaves the current step's code unused, so the replay
  // guard doesn't reject the later challenge redemption.
  const previousTotpFor = (secret: string) =>
    Effect.runPromise(generateHotp(secret, Math.floor(Date.now() / 1000 / 30) - 1));

  it("enables, confirms, gates sign-in, and redeems a TOTP challenge", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    // Wrong password cannot enable.
    const denied = await handler(
      jsonRequest("/multi-factor/enable", { password: "wrong-password" }, asCookie(sid)),
    );
    expect(denied.status).toBe(400);

    const enable = await handler(
      jsonRequest("/multi-factor/enable", { password: PW }, asCookie(sid)),
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
      jsonRequest(
        "/multi-factor/confirm",
        { code: await previousTotpFor(enrollment.secret) },
        asCookie(sid),
      ),
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
      jsonRequest("/multi-factor/verify-totp", {
        token: gatedBody.secondFactor!.token,
        code: badCode,
      }),
    );
    expect(rejected.status).toBe(401);

    // Correct TOTP code redeems the challenge into a session.
    const verified = await handler(
      jsonRequest("/multi-factor/verify-totp", { token: gatedBody.secondFactor!.token, code }),
    );
    expect(verified.status).toBe(200);
    const verifiedBody = (await verified.json()) as { user: { email: string } };
    expect(verifiedBody.user.email).toBe("2fa@example.com");
    const newSid = sessionIdFromSetCookie(verified.headers.get("set-cookie"));
    expect((await handler(getRequest("/session", asCookie(newSid)))).status).toBe(200);

    // The pending token was consumed (one-time use).
    const replay = await handler(
      jsonRequest("/multi-factor/verify-totp", { token: gatedBody.secondFactor!.token, code }),
    );
    expect(replay.status).toBe(401);
  });

  it("redeems backup codes exactly once", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    const enable = await handler(
      jsonRequest("/multi-factor/enable", { password: PW }, asCookie(sid)),
    );
    const enrollment = (await enable.json()) as { secret: string; backupCodes: string[] };
    await handler(
      jsonRequest(
        "/multi-factor/confirm",
        { code: await totpFor(enrollment.secret) },
        asCookie(sid),
      ),
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
      jsonRequest("/multi-factor/verify-backup-code", {
        token: await challengeToken(),
        code: backupCode,
      }),
    );
    expect(first.status).toBe(200);
    expect(first.headers.get("set-cookie")).toContain("conduit_session=");

    // The same backup code cannot be used again.
    const second = await handler(
      jsonRequest("/multi-factor/verify-backup-code", {
        token: await challengeToken(),
        code: backupCode,
      }),
    );
    expect(second.status).toBe(401);
  });

  it("regenerates backup codes and disables multi-factor with the password", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });
    const sid = await signUp(handler, "2fa@example.com");

    const enable = await handler(
      jsonRequest("/multi-factor/enable", { password: PW }, asCookie(sid)),
    );
    const enrollment = (await enable.json()) as { secret: string; backupCodes: string[] };
    await handler(
      jsonRequest(
        "/multi-factor/confirm",
        { code: await totpFor(enrollment.secret) },
        asCookie(sid),
      ),
    );

    const regen = await handler(
      jsonRequest("/multi-factor/regenerate-backup-codes", { password: PW }, asCookie(sid)),
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
      jsonRequest("/multi-factor/verify-backup-code", {
        token: gatedBody.secondFactor!.token,
        code: enrollment.backupCodes[0],
      }),
    );
    expect(staleCode.status).toBe(401);

    // Disable requires the password; afterwards sign-in is no longer gated.
    const disableDenied = await handler(
      jsonRequest("/multi-factor/disable", { password: "wrong-password" }, asCookie(sid)),
    );
    expect(disableDenied.status).toBe(400);

    const disable = await handler(
      jsonRequest("/multi-factor/disable", { password: PW }, asCookie(sid)),
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

describe("HTTP device authorization (RFC 8628)", () => {
  it("runs the full device flow: code -> approve -> token", async () => {
    const handler = handlerFor(makeFixture(), { features: true });

    const codeRes = await handler(jsonRequest("/device/code", {}));
    expect(codeRes.status).toBe(200);
    const code = (await codeRes.json()) as { deviceCode: string; userCode: string };

    // Polling before approval yields authorization_pending (400).
    const pending = await handler(jsonRequest("/device/token", { deviceCode: code.deviceCode }));
    expect(pending.status).toBe(400);
    expect(((await pending.json()) as { message: string }).message).toBe("authorization_pending");

    // Approve from an authenticated verification page.
    const sid = await signUp(handler, "device-user@example.com");
    const approve = await handler(
      jsonRequest("/device/approve", { userCode: code.userCode }, asCookie(sid)),
    );
    expect(approve.status).toBe(200);

    // Now the device gets a session.
    const token = await handler(jsonRequest("/device/token", { deviceCode: code.deviceCode }));
    expect(token.status).toBe(200);
    expect(token.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("requires authentication to approve a code", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    const codeRes = await handler(jsonRequest("/device/code", {}));
    const code = (await codeRes.json()) as { userCode: string };
    const res = await handler(jsonRequest("/device/approve", { userCode: code.userCode }));
    expect(res.status).toBe(401);
  });

  it("returns 404 when device authorization is not configured", async () => {
    const handler = handlerFor(makeFixture(), { features: false });
    const res = await handler(jsonRequest("/device/code", {}));
    expect(res.status).toBe(404);
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
    expect(sess.status).toBe(200);

    // The phone number was claimed as a verified `phone` identifier.
    const identifiers = await handler(getRequest("/identifiers", asCookie(sid)));
    expect(identifiers.status).toBe(200);
    const list = (await identifiers.json()) as Array<{
      type: string;
      value: string;
      verified: boolean;
    }>;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ type: "phone", value: "+15551234567", verified: true });
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
      user: { email?: string; attributes: Record<string, unknown> };
    };
    // Guest users have no login handle, so no derived email fields.
    expect(body.user.email).toBeUndefined();
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

const dataCookieFromSetCookie = (setCookie: string | null): string | null => {
  const match = /conduit_session_data=([^;]+)/.exec(setCookie ?? "");
  return match === null ? null : match[1]!;
};

const bothCookies = (sid: string, data: string) => ({
  cookie: `conduit_session=${sid}; conduit_session_data=${data}`,
});

describe("HTTP session cookie cache", () => {
  const SECRET = "cache-secret-cache-secret-1234567";

  it("serves /session from the cache cookie, avoiding a store read", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { cache: { secret: SECRET } });
    const sid = await signUp(handler, "cache@example.com");

    // First /session: cache miss -> store read + issues the data cookie. The
    // store-served response carries the derived email fields.
    const before = fixture.sessionStoreReads();
    const first = await handler(getRequest("/session", asCookie(sid)));
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as { user: { id: string; email?: string } };
    expect(firstBody.user.email).toBe("cache@example.com");
    const data = dataCookieFromSetCookie(first.headers.get("set-cookie"));
    expect(data).not.toBeNull();
    const afterFirst = fixture.sessionStoreReads();
    expect(afterFirst).toBeGreaterThan(before);

    // Second /session with the data cookie: cache hit -> no store read. The
    // cache-served response skips the identifier lookup, so the derived
    // email fields are omitted.
    const second = await handler(getRequest("/session", bothCookies(sid, data!)));
    expect(second.status).toBe(200);
    const body = (await second.json()) as { user: { id: string; email?: string } };
    expect(body.user.id).toBe(firstBody.user.id);
    expect(body.user.email).toBeUndefined();
    expect(fixture.sessionStoreReads()).toBe(afterFirst);
  });

  it("falls back to store validation when the signature is tampered", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { cache: { secret: SECRET } });
    const sid = await signUp(handler, "tamper@example.com");
    const first = await handler(getRequest("/session", asCookie(sid)));
    const data = dataCookieFromSetCookie(first.headers.get("set-cookie"))!;

    const before = fixture.sessionStoreReads();
    const tampered = data.slice(0, -1) + (data.endsWith("A") ? "B" : "A");
    const res = await handler(getRequest("/session", bothCookies(sid, tampered)));
    expect(res.status).toBe(200);
    expect(fixture.sessionStoreReads()).toBeGreaterThan(before);
  });

  it("falls back to store validation once the cache window has elapsed", async () => {
    const fixture = makeFixture();
    // maxAge 0 -> the cache cookie is already expired on the next request.
    const handler = handlerFor(fixture, { cache: { secret: SECRET, maxAge: 0 } });
    const sid = await signUp(handler, "expire@example.com");
    const first = await handler(getRequest("/session", asCookie(sid)));
    const data = dataCookieFromSetCookie(first.headers.get("set-cookie"))!;

    const before = fixture.sessionStoreReads();
    const res = await handler(getRequest("/session", bothCookies(sid, data)));
    expect(res.status).toBe(200);
    expect(fixture.sessionStoreReads()).toBeGreaterThan(before);
  });

  it("clears both the session and cache cookies on sign-out", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { cache: { secret: SECRET } });
    const sid = await signUp(handler, "out@example.com");
    await handler(getRequest("/session", asCookie(sid))); // seed the data cookie

    const out = await handler(jsonRequest("/sign-out", undefined, asCookie(sid)));
    expect(out.status).toBe(204);
    const setCookie = out.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("conduit_session=");
    expect(setCookie).toContain("conduit_session_data=");
  });
});

const setCookieValue = (res: Response, name: string): string | null => {
  for (const c of res.headers.getSetCookie()) {
    const m = new RegExp(`^${name}=([^;]*)`).exec(c);
    if (m) return m[1]!;
  }
  return null;
};

describe("HTTP multi-session", () => {
  it("accumulates sessions, lists, switches active, and revokes", async () => {
    const handler = handlerFor(makeFixture(), { multiSession: { maximumSessions: 5 } });

    // Sign in account A.
    const a = await handler(jsonRequest("/sign-up", { email: "a@example.com", password: PW }));
    const sidA = setCookieValue(a, "conduit_session")!;
    const multiA = setCookieValue(a, "conduit_session_multi")!;
    expect(multiA).toBe(sidA);

    // Sign in account B, carrying account A's device list.
    const b = await handler(
      jsonRequest(
        "/sign-up",
        { email: "b@example.com", password: PW },
        { cookie: `conduit_session_multi=${multiA}` },
      ),
    );
    const sidB = setCookieValue(b, "conduit_session")!;
    const multiB = setCookieValue(b, "conduit_session_multi")!;
    expect(multiB.split(".").sort()).toEqual([sidA, sidB].sort());

    const deviceCookie = `conduit_session=${sidB}; conduit_session_multi=${multiB}`;

    // List returns both accounts.
    const list = await handler(getRequest("/multi-session/list", { cookie: deviceCookie }));
    expect(list.status).toBe(200);
    const emails = ((await list.json()) as Array<{ user: { email: string } }>)
      .map((s) => s.user.email)
      .sort();
    expect(emails).toEqual(["a@example.com", "b@example.com"]);

    // Set active -> A: primary cookie swaps to A.
    const setActive = await handler(
      jsonRequest("/multi-session/set-active", { sessionId: sidA }, { cookie: deviceCookie }),
    );
    expect(setActive.status).toBe(200);
    expect(setCookieValue(setActive, "conduit_session")).toBe(sidA);

    // Revoke B: it drops from the list; A remains valid.
    const revoke = await handler(
      jsonRequest("/multi-session/revoke", { sessionId: sidB }, { cookie: deviceCookie }),
    );
    expect(revoke.status).toBe(200);
    const newMulti = setCookieValue(revoke, "conduit_session_multi")!;
    expect(newMulti.split(".").filter(Boolean)).toEqual([sidA]);
    // B's session is now invalid, A still works.
    expect(
      (await handler(getRequest("/session", { cookie: `conduit_session=${sidB}` }))).status,
    ).toBe(401);
    expect(
      (await handler(getRequest("/session", { cookie: `conduit_session=${sidA}` }))).status,
    ).toBe(200);
  });

  it("caps the device list at maximumSessions", async () => {
    const handler = handlerFor(makeFixture(), { multiSession: { maximumSessions: 2 } });
    let multi = "";
    let last = "";
    for (const email of ["1@e.com", "2@e.com", "3@e.com"]) {
      const res = await handler(
        jsonRequest(
          "/sign-up",
          { email, password: PW },
          { cookie: `conduit_session_multi=${multi}` },
        ),
      );
      multi = setCookieValue(res, "conduit_session_multi")!;
      last = setCookieValue(res, "conduit_session")!;
    }
    const ids = multi.split(".").filter(Boolean);
    expect(ids).toHaveLength(2);
    expect(ids).toContain(last); // newest retained
  });

  it("returns 404 for multi-session endpoints when not enabled", async () => {
    const handler = handlerFor(makeFixture());
    const res = await handler(getRequest("/multi-session/list"));
    expect(res.status).toBe(404);
  });
});

// Parse the Set-Cookie header for a named cookie and return its directives.
const parseCookieDirectives = (res: Response, name: string): Record<string, string | true> => {
  for (const header of res.headers.getSetCookie()) {
    const [pair, ...directives] = header.split(/;\s*/);
    if (pair!.startsWith(`${name}=`)) {
      const out: Record<string, string | true> = {};
      for (const d of directives) {
        const eq = d.indexOf("=");
        if (eq === -1) out[d.toLowerCase()] = true;
        else out[d.slice(0, eq).toLowerCase()] = d.slice(eq + 1);
      }
      return out;
    }
  }
  return {};
};

describe("rememberMe cookie behaviour", () => {
  it("sign-in without rememberMe emits a persistent cookie with Expires", async () => {
    const handler = handlerFor();
    await signUp(handler, "a@b.com");
    const res = await handler(jsonRequest("/sign-in", { email: "a@b.com", password: PW }));
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeDefined();
  });

  it("sign-in with rememberMe:true emits a persistent cookie with Expires", async () => {
    const handler = handlerFor();
    await signUp(handler, "a@b.com");
    const res = await handler(
      jsonRequest("/sign-in", { email: "a@b.com", password: PW, rememberMe: true }),
    );
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeDefined();
  });

  it("sign-in with rememberMe:false emits a browser-session cookie (no Expires, no Max-Age)", async () => {
    const handler = handlerFor();
    await signUp(handler, "a@b.com");
    const res = await handler(
      jsonRequest("/sign-in", { email: "a@b.com", password: PW, rememberMe: false }),
    );
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeUndefined();
    expect(directives["max-age"]).toBeUndefined();
  });

  it("sign-up always emits a persistent cookie regardless of rememberMe", async () => {
    const handler = handlerFor();
    const res = await handler(jsonRequest("/sign-up", { email: "b@b.com", password: PW }));
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeDefined();
  });

  it("username sign-in with rememberMe:false emits a browser-session cookie", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    const up = await handler(jsonRequest("/sign-up", { email: "u@b.com", password: PW }));
    expect(up.status).toBe(200);
    const userId = ((await up.json()) as { user: { id: string } }).user.id;
    fixture.registerUsername(userId, "testuser");

    const res = await handler(
      jsonRequest("/sign-in/username", { username: "testuser", password: PW, rememberMe: false }),
    );
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeUndefined();
    expect(directives["max-age"]).toBeUndefined();
  });

  it("username sign-in with rememberMe:true emits a persistent cookie", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true });

    const up = await handler(jsonRequest("/sign-up", { email: "u2@b.com", password: PW }));
    expect(up.status).toBe(200);
    const userId = ((await up.json()) as { user: { id: string } }).user.id;
    fixture.registerUsername(userId, "testuser2");

    const res = await handler(
      jsonRequest("/sign-in/username", { username: "testuser2", password: PW, rememberMe: true }),
    );
    expect(res.status).toBe(200);
    const directives = parseCookieDirectives(res, "conduit_session");
    expect(directives["expires"]).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Bearer mode
// ---------------------------------------------------------------------------

describe("bearer mode", () => {
  it("opt-in: sign-in without x-use-bearer does NOT emit set-auth-token", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: "opt-in" });
    await handler(jsonRequest("/sign-up", { email: "bearer@test.com", password: PW }));
    const res = await handler(jsonRequest("/sign-in", { email: "bearer@test.com", password: PW }));
    expect(res.status).toBe(200);
    expect(res.headers.get(BEARER_TOKEN_HEADER)).toBeNull();
    // Cookie still set in opt-in mode when x-use-bearer absent
    expect(res.headers.get("set-cookie")).toContain("conduit_session=");
  });

  it("opt-in: sign-in with x-use-bearer: 1 emits set-auth-token header", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: "opt-in" });
    await handler(jsonRequest("/sign-up", { email: "bearer@test.com", password: PW }));
    const res = await handler(
      jsonRequest("/sign-in", { email: "bearer@test.com", password: PW }, { "x-use-bearer": "1" }),
    );
    expect(res.status).toBe(200);
    const token = res.headers.get(BEARER_TOKEN_HEADER);
    expect(typeof token).toBe("string");
    expect(token!.length).toBeGreaterThan(0);
  });

  it("opt-in: token from set-auth-token can be used as Authorization: Bearer", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: "opt-in" });
    await handler(jsonRequest("/sign-up", { email: "bearer@test.com", password: PW }));
    const signInRes = await handler(
      jsonRequest("/sign-in", { email: "bearer@test.com", password: PW }, { "x-use-bearer": "1" }),
    );
    expect(signInRes.status).toBe(200);
    const rawToken = signInRes.headers.get(BEARER_TOKEN_HEADER)!;

    const sessionRes = await handler(
      getRequest("/session", { authorization: `Bearer ${rawToken}` }),
    );
    expect(sessionRes.status).toBe(200);
    const body = (await sessionRes.json()) as { user: { email: string } };
    expect(body.user.email).toBe("bearer@test.com");
  });

  it("opt-in: sign-up with x-use-bearer: 1 also emits set-auth-token", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: "opt-in" });
    const res = await handler(
      jsonRequest("/sign-up", { email: "bearer2@test.com", password: PW }, { "x-use-bearer": "1" }),
    );
    expect(res.status).toBe(200);
    const token = res.headers.get(BEARER_TOKEN_HEADER);
    expect(typeof token).toBe("string");
    expect(token!.length).toBeGreaterThan(0);
  });

  it("always mode: every session-issuing response carries set-auth-token", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: true });

    const signUpRes = await handler(
      jsonRequest("/sign-up", { email: "always@test.com", password: PW }),
    );
    expect(signUpRes.status).toBe(200);
    const signUpToken = signUpRes.headers.get(BEARER_TOKEN_HEADER);
    expect(typeof signUpToken).toBe("string");
    expect(signUpToken!.length).toBeGreaterThan(0);

    // Token from sign-up is usable as a bearer token
    const sessionRes = await handler(
      getRequest("/session", { authorization: `Bearer ${signUpToken}` }),
    );
    expect(sessionRes.status).toBe(200);
    const body = (await sessionRes.json()) as { user: { email: string } };
    expect(body.user.email).toBe("always@test.com");
  });

  it("always mode: set-auth-token is present without x-use-bearer header", async () => {
    const handler = handlerFor(makeFixture(), { bearerMode: true });
    const res = await handler(jsonRequest("/sign-up", { email: "always2@test.com", password: PW }));
    expect(res.status).toBe(200);
    // No x-use-bearer sent — header still present in "always" mode
    expect(res.headers.get(BEARER_TOKEN_HEADER)).not.toBeNull();
  });

  it("bearerMode false (default): no set-auth-token header even with x-use-bearer", async () => {
    const handler = handlerFor(makeFixture());
    const res = await handler(
      jsonRequest("/sign-up", { email: "nobear@test.com", password: PW }, { "x-use-bearer": "1" }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get(BEARER_TOKEN_HEADER)).toBeNull();
  });

  it("opt-in: magic-link verify with x-use-bearer emits set-auth-token", async () => {
    const fixture = makeFixture();
    const handler = handlerFor(fixture, { features: true, bearerMode: "opt-in" });

    // Register user
    await handler(jsonRequest("/sign-up", { email: "ml@test.com", password: PW }));
    // Send magic link
    await handler(jsonRequest("/magic-link/send", { email: "ml@test.com" }));
    const token = fixture.sentMagicLinkTokens.at(-1)!;

    // Verify with x-use-bearer
    const verifyRes = await handler(
      jsonRequest("/magic-link/verify", { token }, { "x-use-bearer": "1" }),
    );
    expect(verifyRes.status).toBe(200);
    const bearerToken = verifyRes.headers.get(BEARER_TOKEN_HEADER);
    expect(typeof bearerToken).toBe("string");
    expect(bearerToken!.length).toBeGreaterThan(0);

    // Use the bearer token to fetch session
    const sessionRes = await handler(
      getRequest("/session", { authorization: `Bearer ${bearerToken}` }),
    );
    expect(sessionRes.status).toBe(200);
    const body = (await sessionRes.json()) as { user: { email: string } };
    expect(body.user.email).toBe("ml@test.com");
  });
});

describe("client IP at the HTTP boundary", () => {
  // One sign-in attempt per window per resolved client address.
  const signInOncePerHour = {
    rules: [{ path: "/sign-in", methods: ["POST"], maxRequests: 1, windowMs: HOUR }],
  };

  // Builds the limited handler and returns every limiter key it touched, so a
  // test can see which bucket (if any) a request was counted under.
  const limitedHandler = (
    options: {
      readonly trustedProxy?: TrustedProxyConfig | undefined;
      readonly allowMissingClientIp?: boolean | undefined;
    } = {},
  ): { readonly handler: Handler; readonly keys: ReadonlySet<string> } => {
    const entries = new Map<string, RateLimitEntry>();
    const keys = new Set<string>();
    const store = {
      get: (key: string) =>
        Effect.sync(() => {
          keys.add(key);
          return entries.get(key) ?? null;
        }),
      set: (key: string, entry: RateLimitEntry, _ttl: number) =>
        Effect.sync(() => {
          keys.add(key);
          entries.set(key, entry);
        }),
      increment: (key: string, _ttl: number) =>
        Effect.sync(() => {
          keys.add(key);
          const entry = entries.get(key);
          const count = (entry?.count ?? 0) + 1;
          if (entry) entries.set(key, { ...entry, count });
          return count;
        }),
      delete: (key: string) => Effect.sync(() => void entries.delete(key)),
    };
    const limiter = RateLimiter.layer().pipe(Layer.provide(Layer.succeed(RateLimitStore, store)));
    const services = Layer.merge(makeFixture().services, limiter) as Layer.Layer<AuthServices>;
    const handler = HttpServer.make({
      services,
      cookie: { secure: false },
      ipRateLimit: signInOncePerHour,
      trustedProxy: options.trustedProxy,
      allowMissingClientIp: options.allowMissingClientIp,
    }).handler;
    return { handler, keys };
  };

  // A sign-in for an unknown account: the limiter runs before the handler, so
  // the response status only shows whether the attempt was refused.
  const attempt = (handler: Handler, cfConnectingIp: string, xForwardedFor: string) =>
    handler(
      jsonRequest(
        "/sign-in",
        { email: "nobody@example.com", password: PW },
        {
          "cf-connecting-ip": cfConnectingIp,
          "x-forwarded-for": xForwardedFor,
        },
      ),
    );

  it("keys the limit on CF-Connecting-IP and ignores X-Forwarded-For under ClientIP.cloudflare", async () => {
    const { handler } = limitedHandler({ trustedProxy: ClientIP.cloudflare });

    expect((await attempt(handler, "203.0.113.1", "6.6.6.6")).status).not.toBe(429);
    // A different visitor behind the same edge has a bucket of their own.
    expect((await attempt(handler, "203.0.113.2", "7.7.7.7")).status).not.toBe(429);
    // The same visitor, with a different forged X-Forwarded-For, is still limited.
    expect((await attempt(handler, "203.0.113.1", "8.8.8.8")).status).toBe(429);
  });

  it("fails the build when ipRateLimit has no trustedProxy and no opt-out", () => {
    // A Web Request has no socket address, so the limiter would have nothing to key on.
    expect(() => limitedHandler()).toThrow(HttpServer.ClientAddressConfigError);
    expect(() => limitedHandler({ trustedProxy: undefined })).toThrow(
      HttpServer.ClientAddressConfigError,
    );
  });

  it("builds with a trustedProxy or with the allowMissingClientIp opt-out", () => {
    expect(() => limitedHandler({ trustedProxy: ClientIP.cloudflare })).not.toThrow();
    expect(() => limitedHandler({ allowMissingClientIp: true })).not.toThrow();
  });

  it("refuses an address-less request to a limited endpoint, counts nothing, and leaves other endpoints alone", async () => {
    const { handler, keys } = limitedHandler({ allowMissingClientIp: true });

    // Two address-less sign-ins: both refused, neither counted under a shared bucket.
    for (let i = 0; i < 2; i++) {
      const res = await handler(
        jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
      );
      expect(res.status).toBe(429);
      expect(await res.json()).toEqual({
        message: expect.stringContaining("Client address unavailable"),
      });
    }
    expect([...keys]).toEqual([]);

    // An endpoint with no rule is not limited, so it needs no address.
    const session = await handler(getRequest("/session"));
    expect(session.status).not.toBe(429);
  });

  it("refuses a request whose forwarded address is unusable and no socket, without a shared bucket", async () => {
    const { handler, keys } = limitedHandler({ trustedProxy: ClientIP.cloudflare });

    // A malformed header, a comma-separated list, and no header at all resolve
    // no address, so each is refused rather than sharing one bucket.
    expect((await attempt(handler, "not-an-ip", "6.6.6.6")).status).toBe(429);
    expect((await attempt(handler, "203.0.113.1, 198.51.100.7", "6.6.6.6")).status).toBe(429);
    const bare = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(bare.status).toBe(429);
    expect([...keys]).toEqual([]);

    // A valid address is still keyed on its own: the refusals used no bucket.
    expect((await attempt(handler, "203.0.113.1", "6.6.6.6")).status).not.toBe(429);
    expect(keys.size).toBeGreaterThan(0);
    for (const key of keys) expect(key.endsWith("203.0.113.1")).toBe(true);
  });
});

/**
 * The auth API composed by hand from the exported group layers, outside
 * `Http.make`: no startup check, no `ClientIP` middleware (#389).
 */
const handBuiltHandler = (services: Layer.Layer<AuthServices>): Handler => {
  const platform = Layer.mergeAll(Etag.layer, Path.layer, HttpPlatform.layer).pipe(
    Layer.provideMerge(FileSystem.layerNoop({})),
  );
  const api = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(HttpServer.authGroupLayer({ secure: false })),
    Layer.provide(HttpServer.scimGroupLayer()),
    Layer.provide(platform),
  );
  // The handlers' phantom requirements are satisfied by `services` at runtime;
  // `Http.make` narrows its handler the same way.
  return HttpRouter.toWebHandler(api.pipe(Layer.provideMerge(services)), {
    disableLogger: true,
  }).handler as unknown as (request: Request) => Promise<Response>;
};

/** A hooks stack with `IPRateLimitPlugin` (one sign-in per hour per address). */
const ipRateLimitHooks = (): Layer.Layer<Hooks> =>
  // NormalizeEmailPlugin runs after it, so the check sees through the stack.
  composePlugins([
    IPRateLimitPlugin({ signIn: { maxRequests: 1, windowMs: HOUR } }),
    NormalizeEmailPlugin,
  ]).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(RateLimiter.layer()),
    Layer.provide(memoryRateLimitStoreLayer()),
  );

describe("rate limits need a RateLimiter when make is called (#389)", () => {
  it("throws RateLimiterConfigError from make when ipRateLimit has no RateLimiter", () => {
    const fixture = makeFixture();
    expect(() =>
      HttpServer.make({
        services: fixture.services,
        cookie: { secure: false },
        trustedProxy: ClientIP.cloudflare,
        ipRateLimit: {},
      }),
    ).toThrow(RateLimiterConfigError);
    expect(() =>
      HttpServer.make({
        services: fixture.services,
        trustedProxy: ClientIP.cloudflare,
        ipRateLimit: {},
      }),
    ).toThrow(/ipRateLimit configured with no RateLimiter/);
  });

  it("throws from make when the device service has no RateLimiter for the user-code limit", () => {
    const fixture = makeFixture();
    expect(() =>
      HttpServer.make({
        services: fixture.featureServicesWithoutRateLimiter,
        cookie: { secure: false },
      }),
    ).toThrow(/the device user-code limit \(approve and deny\) configured with no RateLimiter/);
  });

  it("builds without a RateLimiter when the device service opts out, and leaves approve/deny unlimited", async () => {
    const fixture = makeFixture({ deviceAllowMissingRateLimiter: true });
    const { handler } = HttpServer.make({
      services: fixture.featureServicesWithoutRateLimiter,
      cookie: { secure: false },
    });
    // An unknown code is a 400 every time: no limiter, by explicit choice.
    for (let i = 0; i < 7; i++) {
      const res = await handler(jsonRequest("/device/deny", { userCode: "BCDF-GHJK" }));
      expect(res.status).toBe(400);
    }
  });

  it("limits device approve/deny to 5 attempts per user code when a RateLimiter is in services", async () => {
    const handler = handlerFor(makeFixture(), { features: true });
    for (let i = 0; i < 5; i++) {
      const res = await handler(jsonRequest("/device/deny", { userCode: "BCDF-GHJK" }));
      expect(res.status).toBe(400);
    }
    const sixth = await handler(jsonRequest("/device/deny", { userCode: "BCDF-GHJK" }));
    expect(sixth.status).toBe(429);
  });

  it("builds and serves when a RateLimiter is in services", async () => {
    const fixture = makeFixture();
    const { handler } = HttpServer.make({
      services: Layer.merge(
        fixture.services,
        memoryRateLimiterLayer(),
      ) as Layer.Layer<AuthServices>,
      cookie: { secure: false },
      trustedProxy: ClientIP.cloudflare,
      ipRateLimit: {},
    });

    const res = await handler(
      jsonRequest(
        "/sign-in",
        { email: "nobody@example.com", password: PW },
        { "cf-connecting-ip": "203.0.113.5" },
      ),
    );
    expect(res.status).toBe(401);
  });

  it("builds without any rate limit, with no RateLimiter", async () => {
    const fixture = makeFixture();
    const { handler } = HttpServer.make({
      services: fixture.services,
      cookie: { secure: false },
    });

    const res = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(res.status).toBe(401);
  });

  it("builds services once, for the check and the handler, and releases them on dispose", async () => {
    let builds = 0;
    let released = 0;
    const counted = Layer.effectDiscard(
      Effect.acquireRelease(
        Effect.sync(() => void builds++),
        () => Effect.sync(() => void released++),
      ),
    );
    const fixture = makeFixture();
    const { handler, dispose } = HttpServer.make({
      services: Layer.merge(fixture.services, counted) as Layer.Layer<AuthServices>,
      cookie: { secure: false },
    });
    expect(builds).toBe(1);
    const res = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(res.status).toBe(401);
    expect(builds).toBe(1);
    expect(released).toBe(0);
    await dispose();
    expect(released).toBe(1);
  });

  it("releases the services it built when make throws", () => {
    let released = 0;
    const counted = Layer.effectDiscard(
      Effect.acquireRelease(Effect.void, () => Effect.sync(() => void released++)),
    );
    const fixture = makeFixture();
    expect(() =>
      HttpServer.make({
        services: Layer.merge(fixture.services, counted) as Layer.Layer<AuthServices>,
        trustedProxy: ClientIP.cloudflare,
        ipRateLimit: {},
      }),
    ).toThrow(RateLimiterConfigError);
    expect(released).toBe(1);
  });

  it("fails the handler's build instead when services build asynchronously", async () => {
    // make cannot see services that finish building after it returns, so it
    // cannot throw. The same check then fails the build: every request rejects.
    const fixture = makeFixture();
    const asyncStep = Layer.effectDiscard(Effect.promise(() => Promise.resolve()));
    const { handler } = HttpServer.make({
      services: Layer.merge(fixture.services, asyncStep) as Layer.Layer<AuthServices>,
      cookie: { secure: false },
      trustedProxy: ClientIP.cloudflare,
      ipRateLimit: {},
    });

    await expect(
      handler(jsonRequest("/sign-in", { email: "nobody@example.com", password: PW })),
    ).rejects.toBeInstanceOf(RateLimiterConfigError);
  });
});

describe("IPRateLimitPlugin needs a client-address source under make (#389)", () => {
  it("throws ClientAddressConfigError from make with no trustedProxy and no opt-out", () => {
    const fixture = makeFixture({ hooks: ipRateLimitHooks() });
    expect(() =>
      HttpServer.make({ services: fixture.services, cookie: { secure: false } }),
    ).toThrow(ClientAddressConfigError);
    expect(() => HttpServer.make({ services: fixture.services })).toThrow(
      /IPRateLimitPlugin keys its limits on the client address/,
    );
  });

  it("builds with trustedProxy and keys each address on its own budget", async () => {
    const fixture = makeFixture({ hooks: ipRateLimitHooks() });
    const { handler } = HttpServer.make({
      services: fixture.services,
      cookie: { secure: false },
      trustedProxy: ClientIP.cloudflare,
    });
    const signIn = (ip: string) =>
      handler(
        jsonRequest(
          "/sign-in",
          { email: "nobody@example.com", password: PW },
          { "cf-connecting-ip": ip },
        ),
      );

    expect((await signIn("203.0.113.20")).status).toBe(401);
    expect((await signIn("203.0.113.20")).status).toBe(429);
    expect((await signIn("203.0.113.21")).status).toBe(401);
  });

  it("refuses an address-less sign-in with 429 when the app opts out with allowMissingClientIp", async () => {
    const fixture = makeFixture({ hooks: ipRateLimitHooks() });
    const { handler } = HttpServer.make({
      services: fixture.services,
      cookie: { secure: false },
      allowMissingClientIp: true,
    });

    const res = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({
      message: "Client address unavailable; this request cannot be rate limited",
    });
  });
});

describe("the exported group layers outside make refuse rather than skip (#389)", () => {
  it("refuses device approve/deny with 429 when no RateLimiter is in scope, and logs it as an error", async () => {
    const logs: Array<{ readonly level: string; readonly message: string }> = [];
    const collector = Logger.make((options) => {
      logs.push({ level: options.logLevel, message: String(options.message) });
    });
    const handler = handBuiltHandler(
      Layer.merge(
        makeFixture().featureServicesWithoutRateLimiter,
        Logger.layer([collector]),
      ) as Layer.Layer<AuthServices>,
    );
    const res = await handler(jsonRequest("/device/deny", { userCode: "BCDF-GHJK" }));
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({
      message: "No RateLimiter in services; this request cannot be rate limited",
    });
    // The misconfiguration reaches the server log, not only the response.
    expect(logs).toContainEqual({
      level: "Error",
      message:
        "[effect-auth] the device user-code limit is configured with no RateLimiter in services; the request is refused",
    });
  });

  it("runs device approve/deny without the limit when the device service opts out", async () => {
    const handler = handBuiltHandler(
      makeFixture({ deviceAllowMissingRateLimiter: true }).featureServicesWithoutRateLimiter,
    );
    const res = await handler(jsonRequest("/device/deny", { userCode: "BCDF-GHJK" }));
    expect(res.status).toBe(400);
  });

  it("refuses a sign-in through IPRateLimitPlugin with 429 when no ClientIP is in scope", async () => {
    const handler = handBuiltHandler(makeFixture({ hooks: ipRateLimitHooks() }).services);
    const res = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({
      message: "No ClientIP service in scope; this request cannot be rate limited",
    });
  });
});

/** What `thunk` throws, or a failed assertion when it returns. */
const thrownBy = (thunk: () => unknown): unknown => {
  try {
    thunk();
  } catch (error) {
    return error;
  }
  return expect.unreachable("expected a throw");
};

/** Let the event loop run a few macrotasks (setImmediate callbacks). */
const macrotasks = async (count: number): Promise<void> => {
  for (let i = 0; i < count; i++) await new Promise((resolve) => setImmediate(resolve));
};

class BootError extends Data.TaggedError("BootError")<{ readonly reason: string }> {}

describe("make builds services synchronously, up to their exit (#402)", () => {
  it("returns while a fiber that services forked keeps running, and dispose stops it", async () => {
    // A busy fiber the build forks and never awaits. make must not wait for it.
    // If it did, make would only return once this fiber died at the bound below,
    // so the bound turns a hang into a failed assertion.
    const BOUND = 10_000;
    let returned = false;
    let spins = 0;
    let interrupted = false;
    const busy = Layer.effectDiscard(
      Effect.forkScoped(
        Effect.forever(
          Effect.andThen(
            Effect.yieldNow,
            Effect.sync(() => {
              spins++;
              if (!returned && spins >= BOUND) throw new Error("make waited on a forked fiber");
            }),
          ),
        ).pipe(Effect.onInterrupt(() => Effect.sync(() => void (interrupted = true)))),
      ),
    );
    const fixture = makeFixture();

    const { handler, dispose } = HttpServer.make({
      // provideMerge builds `busy` on the build's own fiber, after the rest.
      services: busy.pipe(Layer.provideMerge(fixture.services)) as Layer.Layer<AuthServices>,
      cookie: { secure: false },
    });
    returned = true;
    expect(spins).toBeLessThan(BOUND);

    // The fiber runs on after make returns, and the handler is served beside it.
    const res = await handler(
      jsonRequest("/sign-in", { email: "nobody@example.com", password: PW }),
    );
    expect(res.status).toBe(401);
    const running = spins;
    await macrotasks(3);
    expect(spins).toBeGreaterThan(running);
    expect(interrupted).toBe(false);

    await dispose();
    expect(interrupted).toBe(true);
    const stopped = spins;
    await macrotasks(3);
    expect(spins).toBe(stopped);
  });

  it("returns when services build asynchronously beside a busy forked fiber", async () => {
    // The build waits on asynchronous work while a forked fiber stays busy. make
    // returns at once and leaves the build to finish later (the fallback below).
    const BOUND = 10_000;
    let returned = false;
    let spins = 0;
    const busy = Layer.effectDiscard(
      Effect.forkScoped(
        Effect.forever(
          Effect.andThen(
            Effect.yieldNow,
            Effect.sync(() => {
              spins++;
              if (!returned && spins >= BOUND) throw new Error("make waited on a forked fiber");
            }),
          ),
        ),
      ),
    );
    const asyncStep = Layer.effectDiscard(Effect.promise(() => Promise.resolve()));
    const fixture = makeFixture();

    const { handler, dispose } = HttpServer.make({
      services: Layer.mergeAll(fixture.services, busy, asyncStep) as Layer.Layer<AuthServices>,
      cookie: { secure: false },
      trustedProxy: ClientIP.cloudflare,
      ipRateLimit: {},
    });
    returned = true;
    expect(spins).toBeLessThan(BOUND);
    const atReturn = spins;
    await macrotasks(3);
    expect(spins).toBeGreaterThan(atReturn);

    // The startup check runs when the build finishes, and fails the handler's build.
    await expect(
      handler(jsonRequest("/sign-in", { email: "nobody@example.com", password: PW })),
    ).rejects.toBeInstanceOf(RateLimiterConfigError);
    await dispose();
  });

  it("throws a typed failure of the services build from make, and releases what it built", () => {
    let released = 0;
    const counted = Layer.effectDiscard(
      Effect.acquireRelease(Effect.void, () => Effect.sync(() => void released++)),
    );
    const failure = new BootError({ reason: "no database" });
    // provideMerge builds `counted` before the failing layer runs.
    const services = Layer.effectDiscard(Effect.fail(failure)).pipe(
      Layer.provideMerge(Layer.merge(makeFixture().services, counted)),
    ) as unknown as Layer.Layer<AuthServices>;

    expect(thrownBy(() => HttpServer.make({ services, cookie: { secure: false } }))).toBe(failure);
    expect(released).toBe(1);
  });

  it("throws a defect of the services build from make as the defect itself", () => {
    let released = 0;
    const counted = Layer.effectDiscard(
      Effect.acquireRelease(Effect.void, () => Effect.sync(() => void released++)),
    );
    const defect = new Error("services could not start");
    const services = Layer.effectDiscard(Effect.die(defect)).pipe(
      Layer.provideMerge(Layer.merge(makeFixture().services, counted)),
    ) as Layer.Layer<AuthServices>;

    expect(thrownBy(() => HttpServer.make({ services, cookie: { secure: false } }))).toBe(defect);
    expect(released).toBe(1);
  });

  it("hands a fiber the build left running to the default scheduler when make throws", async () => {
    // A detached fiber outlives the services scope that make closes before it
    // throws. It must still run once make has thrown, not wait on make's queue.
    // The bound turns a make that waits on it into a failed assertion.
    const BOUND = 10_000;
    let thrown = false;
    let spins = 0;
    let detached: Fiber.Fiber<never> | undefined;
    const spinner = Layer.effectDiscard(
      Effect.forkDetach(
        Effect.forever(
          Effect.andThen(
            Effect.yieldNow,
            Effect.sync(() => {
              spins++;
              if (!thrown && spins >= BOUND) throw new Error("make waited on a forked fiber");
            }),
          ),
        ),
      ).pipe(Effect.tap((fiber) => Effect.sync(() => void (detached = fiber)))),
    );
    const failure = new BootError({ reason: "after the fork" });
    const services = Layer.effectDiscard(Effect.fail(failure)).pipe(
      Layer.provideMerge(spinner),
      Layer.provideMerge(makeFixture().services),
    ) as unknown as Layer.Layer<AuthServices>;

    expect(thrownBy(() => HttpServer.make({ services, cookie: { secure: false } }))).toBe(failure);
    thrown = true;
    expect(spins).toBeLessThan(BOUND);
    const atThrow = spins;
    await macrotasks(3);
    expect(spins).toBeGreaterThan(atThrow);
    await Effect.runPromise(Fiber.interrupt(detached!));
  });
});
