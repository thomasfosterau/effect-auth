import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer, Redacted } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { BEARER_TOKEN_HEADER, type AuthServices } from "./HttpServer.ts";
import * as HTTPServer from "./HttpServer.ts";
import * as HTTPClient from "./HttpClient.ts";
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
import { Hooks } from "../Hooks.ts";
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
  EmailOTPStore,
  EmailOTPUserStore,
  type EmailOTPPurpose,
  type EmailOTPRecord,
  EmailOTPService,
} from "../email/EmailOTP.ts";
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
  PhoneOTPStore,
  PhoneOTPUserStore,
  type PhoneOTPPurpose,
  type PhoneOTPRecord,
  PhoneOTPService,
} from "../PhoneOTP.ts";
import { UsernameService } from "../Username.ts";
import {
  DeviceAuthorizationStore,
  type DeviceAuthorizationRecord,
  DeviceAuthorizationService,
} from "../DeviceAuthorization.ts";
import { generateHOTP, generateTOTP } from "../multifactor/OTP.ts";
import type * as Types from "../Types.ts";

const HOUR = 60 * 60 * 1000;
const SESSION_CONFIG: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: HOUR, idlePeriod: HOUR },
};
const PW = "password-123";
const PW2 = "new-password-456";

// One shared (stateless) hasher; low scrypt cost keeps the suite fast while
// still exercising real hashing end to end.
const hasher = Password.scryptHasher({ cost: 16384 });

interface Fixture {
  /** The base `AuthServices` layer (no optional features). */
  readonly services: Layer.Layer<AuthServices>;
  /** Base layer + magic link, email OTP, multi-factor (and the 2FA gate). */
  readonly featureServices: Layer.Layer<AuthServices>;
  readonly sentVerificationTokens: string[];
  readonly sentResetTokens: string[];
  readonly sentMagicLinkTokens: string[];
  readonly sentOTPs: Array<{ email: string; otp: string; purpose: EmailOTPPurpose }>;
  readonly sentChangeEmail: Array<{ newEmail: string; token: string }>;
  readonly sentDeleteTokens: string[];
  readonly beforeDeleteCalls: string[];
  readonly sentPhoneOTPs: Array<{ phoneNumber: string; otp: string; purpose: PhoneOTPPurpose }>;
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
const makeFixture = (): Fixture => {
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
  const sentOTPs: Array<{ email: string; otp: string; purpose: EmailOTPPurpose }> = [];
  const sentChangeEmail: Array<{ newEmail: string; token: string }> = [];
  const sentDeleteTokens: string[] = [];
  const beforeDeleteCalls: string[] = [];
  const sentPhoneOTPs: Array<{ phoneNumber: string; otp: string; purpose: PhoneOTPPurpose }> = [];

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
    getCredentials: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  };

  const emailPasswordStore: typeof EmailPasswordStore.Service = {
    createUser: (input) => Effect.sync(() => createUser(input)),
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
    Hooks.Default,
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

  const services: Layer.Layer<AuthServices> = Layer.mergeAll(stage2, authLifecycleServiceLayer);

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
    createUser: (input) => Effect.sync(() => createUser(input)),
  };

  const emailOTPs = new Map<string, EmailOTPRecord>();
  const otpKey = (email: string, purpose: EmailOTPPurpose) => `${purpose}:${email}`;
  const emailOTPStore: typeof EmailOTPStore.Service = {
    upsert: (record) =>
      Effect.sync(() => {
        emailOTPs.set(otpKey(record.email, record.purpose), record);
        return record;
      }),
    get: (email, purpose) => Effect.sync(() => emailOTPs.get(otpKey(email, purpose)) ?? null),
    delete: (email, purpose) => Effect.sync(() => void emailOTPs.delete(otpKey(email, purpose))),
    incrementAttempts: (email, purpose) =>
      Effect.sync(() => {
        const record = emailOTPs.get(otpKey(email, purpose));
        if (record === undefined) return 0;
        const updated = { ...record, attempts: record.attempts + 1 };
        emailOTPs.set(otpKey(email, purpose), updated);
        return updated.attempts;
      }),
  };
  const emailOTPUserStore: typeof EmailOTPUserStore.Service = {
    createUser: (input) => Effect.sync(() => createUser(input)),
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

  const phoneRecords = new Map<string, PhoneOTPRecord>();
  const phoneKey = (phone: string, purpose: PhoneOTPPurpose) => `${phone}:${purpose}`;
  const phoneOTPStore: typeof PhoneOTPStore.Service = {
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
  const phoneOTPUserStore: typeof PhoneOTPUserStore.Service = {
    createUser: (input) => Effect.sync(() => createUser(input)),
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

  // Every optional-feature store, merged with the base `services` layer:
  // enough to satisfy any feature service's construction-time dependencies
  // (their own store(s) plus SessionService/IdentifierStore/PasswordHasher/
  // UserStore/Hooks already provided by `services`).
  const featureBase = Layer.mergeAll(
    services,
    Layer.succeed(AnonymousUserStore)(anonymousUserStore),
    Layer.succeed(DeviceAuthorizationStore)(deviceStore),
    Layer.succeed(PhoneOTPStore)(phoneOTPStore),
    Layer.succeed(PhoneOTPUserStore)(phoneOTPUserStore),
    Layer.succeed(AccountManagementStore)(accountStore),
    Layer.succeed(MagicLinkStore)(magicLinkStore),
    Layer.succeed(MagicLinkUserStore)(magicLinkUserStore),
    Layer.succeed(EmailOTPStore)(emailOTPStore),
    Layer.succeed(EmailOTPUserStore)(emailOTPUserStore),
    Layer.succeed(MultiFactorStore)(multiFactorStore),
    Layer.succeed(PendingMultiFactorStore)(pendingMultiFactorStore),
  );

  const multiFactorServiceLayer = MultiFactorService.layer({ issuer: "effect-auth-test" }).pipe(
    Layer.provide(featureBase),
  );

  const featureServices: Layer.Layer<AuthServices> = Layer.mergeAll(
    featureBase,
    AnonymousService.layer().pipe(Layer.provide(featureBase)),
    UsernameService.layer().pipe(Layer.provide(featureBase)),
    DeviceAuthorizationService.layer({
      verificationUri: "https://example.com/device",
      // interval 0 so back-to-back polls in a single test don't hit slow_down.
      interval: 0,
    }).pipe(Layer.provide(featureBase)),
    PhoneOTPService.layer({
      sendOTP: (phoneNumber, otp, purpose) =>
        Effect.sync(() => void sentPhoneOTPs.push({ phoneNumber, otp, purpose })),
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
    EmailOTPService.layer({
      sendVerificationOTP: (email, otp, purpose) =>
        Effect.sync(() => void sentOTPs.push({ email, otp, purpose })),
    }).pipe(Layer.provide(featureBase)),
    multiFactorServiceLayer,
    // The gate makes password sign-in return `secondFactor` for enrolled users.
    MultiFactorGateLayer.pipe(Layer.provide(multiFactorServiceLayer)),
  );

  return {
    services,
    featureServices,
    sentVerificationTokens,
    sentResetTokens,
    sentMagicLinkTokens,
    sentOTPs,
    sentChangeEmail,
    sentDeleteTokens,
    beforeDeleteCalls,
    sentPhoneOTPs,
    registerUsername,
    sessionStoreReads: () => sessionStoreReads,
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
    readonly cache?: { readonly secret: string; readonly maxAge?: number };
    readonly multiSession?: { readonly maximumSessions?: number };
    readonly maxBodySize?: number;
    readonly secure?: boolean;
    readonly bearerMode?: boolean | "opt-in";
  },
): Handler =>
  HTTPServer.make({
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
      const client = yield* HTTPClient.client("http://test");
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
    const handler = handlerFor(); // base services: no MagicLink/EmailOTP/MultiFactor layers
    const sid = await signUp(handler, "a@b.com");

    const magicLink = await handler(jsonRequest("/magic-link/send", { email: "a@b.com" }));
    expect(magicLink.status).toBe(404);
    expect(((await magicLink.json()) as { _tag: string })._tag).toBe("NotFound");

    const emailOTP = await handler(
      jsonRequest("/email-otp/send", { email: "a@b.com", purpose: "sign-in" }),
    );
    expect(emailOTP.status).toBe(404);

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
    expect(fixture.sentOTPs).toHaveLength(1);
    expect(fixture.sentOTPs[0].purpose).toBe("sign-in");

    const otp = fixture.sentOTPs[0].otp;
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
    const otp = fixture.sentOTPs[0].otp;
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
  const totpFor = (secret: string) => Effect.runPromise(generateTOTP(secret));
  // The previous time step's code (within the default ±1 window). Confirming
  // enrollment with it leaves the current step's code unused, so the replay
  // guard doesn't reject the later challenge redemption.
  const previousTotpFor = (secret: string) =>
    Effect.runPromise(generateHOTP(secret, Math.floor(Date.now() / 1000 / 30) - 1));

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
    expect(fixture.sentPhoneOTPs).toHaveLength(1);
    const otp = fixture.sentPhoneOTPs[0]!.otp;

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
