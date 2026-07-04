import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import { UserNotFoundError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import { SessionManager, SessionStore, UserStore, type SessionManagerShape } from "./Session.js";
import { UserServiceStore, UserService } from "./User.js";
import { AuthLifecycleService } from "./AuthLifecycle.js";
import { EmailPasswordStore } from "./EmailPassword.js";
import { PasswordHasher } from "./Password.js";
import { EmailVerificationService, EmailVerificationStore } from "./EmailVerification.js";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./PasswordReset.js";
import { makeAuthWebHandler, type AuthServices } from "./HttpServer.js";
import { OAuthUserStore, type OAuthUserStoreShape } from "./OAuth.js";
import { makeGoogleOneTapService, GoogleOneTapError, GoogleOneTapService } from "./GoogleOneTap.js";
import type * as Types from "./Types.js";

const CLIENT_ID = "client-123.apps.googleusercontent.com";
const JWKS_ENDPOINT = "https://fake-google.test/certs";

// --- A fake Google: an ES256 key + JWT signer + JWKS document -----------------

const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const KID = "test-key-1";
const JWKS = {
  keys: [{ ...(publicKey.export({ format: "jwk" }) as object), kid: KID, alg: "ES256" }],
};

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

const signCredential = (claims: Record<string, unknown>): string => {
  const header = { alg: "ES256", kid: KID, typ: "JWT" };
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature = crypto.sign("sha256", Buffer.from(signingInput, "utf8"), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${signature.toString("base64url")}`;
};

const validClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: "https://accounts.google.com",
  aud: CLIENT_ID,
  sub: "google-user-1",
  email: "alice@gmail.test",
  email_verified: true,
  name: "Alice",
  picture: "https://img.test/alice.png",
  exp: Math.floor(Date.now() / 1000) + 300,
  iat: Math.floor(Date.now() / 1000),
  ...overrides,
});

/** Swap `globalThis.fetch` for a canned JWKS response while `thunk` runs. */
const withJwks = async <A>(thunk: () => Promise<A>): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(JSON.stringify(JWKS), { headers: { "content-type": "application/json" } }),
    )) as typeof fetch;
  try {
    return await thunk();
  } finally {
    globalThis.fetch = original;
  }
};

// --- Service-level tests --------------------------------------------------------

const makeStores = () => {
  const users = new Map<string, Types.User>();
  const usersByEmail = new Map<string, Types.User>();
  let userSeq = 0;

  const userStore: OAuthUserStoreShape = {
    getUser: (userId) => {
      const u = users.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    getUserByEmail: (email) => Effect.succeed(usersByEmail.get(email) ?? null),
    createUser: (input) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          email: input.email,
          emailVerified: input.emailVerified,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        users.set(user.id, user);
        usersByEmail.set(user.email, user);
        return user;
      }),
  };
  const sessionManager: SessionManagerShape = {
    createSession: (userId) =>
      Effect.succeed({
        id: `s-${userId}`,
        userId,
        expiresAt: new Date(Date.now() + 3600_000),
        createdAt: new Date(),
        lastActivityAt: new Date(),
        attributes: {},
      }),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const layer = Layer.mergeAll(
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(SessionManager)(sessionManager),
    Hooks.Default,
  );
  return { layer, users };
};

describe("GoogleOneTapService", () => {
  const config = { clientId: CLIENT_ID, jwksEndpoint: JWKS_ENDPOINT };

  it("verifies a credential and provisions the user once", async () => {
    const { layer, users } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));

    const { first, second } = await withJwks(() =>
      Effect.runPromise(
        Effect.gen(function* () {
          const first = yield* service.signIn(signCredential(validClaims()));
          const second = yield* service.signIn(signCredential(validClaims()));
          return { first, second };
        }).pipe(Effect.provide(layer)),
      ),
    );

    expect(first.isNewUser).toBe(true);
    expect(first.user.email).toBe("alice@gmail.test");
    expect(first.user.emailVerified).toBe(true);
    expect(first.user.name).toBe("Alice");
    expect(first.session.userId).toBe(first.user.id);
    expect(first.claims["sub"]).toBe("google-user-1");
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(users.size).toBe(1);
  });

  it("accepts the bare `accounts.google.com` issuer", async () => {
    const { layer } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const result = await withJwks(() =>
      Effect.runPromise(
        service
          .signIn(signCredential(validClaims({ iss: "accounts.google.com" })))
          .pipe(Effect.provide(layer)),
      ),
    );
    expect(result.user.email).toBe("alice@gmail.test");
  });

  it("rejects wrong audience, wrong issuer, expiry, unverified email, and bad signatures", async () => {
    const { layer } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));

    const credentials = [
      signCredential(validClaims({ aud: "someone-else" })),
      signCredential(validClaims({ iss: "https://evil.test" })),
      signCredential(validClaims({ exp: Math.floor(Date.now() / 1000) - 10 })),
      signCredential(validClaims({ email_verified: false })),
      `${signCredential(validClaims()).slice(0, -8)}AAAAAAAA`,
    ];

    for (const credential of credentials) {
      const err = await withJwks(() =>
        Effect.runPromise(Effect.flip(service.signIn(credential)).pipe(Effect.provide(layer))),
      );
      expect(err).toBeInstanceOf(GoogleOneTapError);
    }
  });
});

// --- HTTP layer ------------------------------------------------------------------

const makeHttpFixture = () => {
  const usersById = new Map<string, Types.User>();
  const usersByEmail = new Map<string, Types.User>();
  const sessions = new Map<string, Types.Session>();
  let userSeq = 0;

  const oauthUserStore: OAuthUserStoreShape = {
    getUser: (userId) => {
      const u = usersById.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    getUserByEmail: (email) => Effect.succeed(usersByEmail.get(email) ?? null),
    createUser: (input) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          email: input.email,
          emailVerified: input.emailVerified,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        usersById.set(user.id, user);
        usersByEmail.set(user.email, user);
        return user;
      }),
  };
  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId: string) => Effect.succeed(null),
  };
  const userServiceStore = {
    get: userStore.get,
    getByEmail: (email: string) => Effect.succeed(usersByEmail.get(email) ?? null),
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: () => Effect.void,
    listByUserId: () => Effect.succeed([]),
  };

  const base = Layer.mergeAll(
    SessionManager.layer({
      sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
    }).pipe(
      Layer.provide(
        Layer.mergeAll(
          Layer.succeed(SessionStore)(sessionStore as never),
          Layer.succeed(UserStore)(userStore),
        ),
      ),
    ),
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordStore)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(EmailVerificationStore)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
    Layer.succeed(PasswordResetStore)(undefined as never),
    Layer.succeed(PasswordResetUserStore)(undefined as never),
  );

  const oneTapLayer = Layer.mergeAll(
    GoogleOneTapService.layer({ clientId: CLIENT_ID, jwksEndpoint: JWKS_ENDPOINT }),
    Layer.succeed(OAuthUserStore)(oauthUserStore),
  );

  return {
    handler: makeAuthWebHandler({
      services: Layer.mergeAll(base, oneTapLayer) as Layer.Layer<AuthServices>,
      cookie: { secure: false, lastLoginMethod: true },
    }).handler,
    handlerWithoutOneTap: makeAuthWebHandler({
      services: base as Layer.Layer<AuthServices>,
      cookie: { secure: false },
    }).handler,
  };
};

const post = (path: string, body: unknown): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("HTTP Google One Tap endpoint", () => {
  it("signs in with a valid credential and sets cookies", async () => {
    const fx = makeHttpFixture();
    const res = await withJwks(() =>
      fx.handler(post("/sign-in/google-one-tap", { credential: signCredential(validClaims()) })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string } };
    expect(body.user.email).toBe("alice@gmail.test");
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((c) => c.startsWith("conduit_session="))).toBe(true);
    expect(cookies.some((c) => c.startsWith("conduit_session_last_method=google"))).toBe(true);
  });

  it("answers 401 for an invalid credential", async () => {
    const fx = makeHttpFixture();
    const res = await withJwks(() =>
      fx.handler(
        post("/sign-in/google-one-tap", {
          credential: signCredential(validClaims({ aud: "someone-else" })),
        }),
      ),
    );
    expect(res.status).toBe(401);
  });

  it("returns 404 when One Tap is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutOneTap(post("/sign-in/google-one-tap", { credential: "x" }));
    expect(res.status).toBe(404);
  });
});
