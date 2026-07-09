import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import { UserNotFoundError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import { SessionService } from "./session/SessionService.js";
import { SessionStore } from "./session/SessionStore.js";
import { UserStore } from "./session/UserStore.js";
import type { SessionServiceShape } from "./session/SessionService.js";
import { UserServiceStore, UserService } from "./User.js";
import { AuthLifecycleService } from "./AuthLifecycle.js";
import { EmailPasswordStore } from "./email/EmailPassword.js";
import { PasswordHasher } from "./password/Password.js";
import { EmailVerificationService, EmailVerificationStore } from "./email/EmailVerification.js";
import {
  PasswordResetService,
  PasswordResetStore,
  PasswordResetUserStore,
} from "./password/PasswordReset.js";
import { makeAuthWebHandler, type AuthServices } from "./http/HTTPServer.js";
import { OAuthUserStore, type OAuthUserStoreShape } from "./oauth/OAuth.js";
import {
  makeGoogleOneTapService,
  GoogleOneTapError,
  GoogleOneTapService,
  GoogleOneTapNonceStore,
  type GoogleOneTapNonceStoreShape,
} from "./GoogleOneTap.js";
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

/** Hash a nonce the same way GoogleOneTap.ts does (SHA-256 hex). */
const hashNonce = (nonce: string): string =>
  crypto.createHash("sha256").update(nonce, "utf8").digest("hex");

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

// ---------------------------------------------------------------------------
// In-memory nonce store for tests
// ---------------------------------------------------------------------------

const makeMemoryNonceStore = (): GoogleOneTapNonceStoreShape => {
  const store = new Map<string, { expiresAt: number }>();
  return {
    create: (nonce, expiresAt) =>
      Effect.sync(() => {
        store.set(nonce, { expiresAt });
      }),
    get: (nonce) => Effect.sync(() => store.get(nonce) ?? null),
    delete: (nonce) =>
      Effect.sync(() => {
        store.delete(nonce);
      }),
  };
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
  const sessionManager: SessionServiceShape = {
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

  const nonceStore = makeMemoryNonceStore();

  const layer = Layer.mergeAll(
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(GoogleOneTapNonceStore)(nonceStore),
    Hooks.Default,
  );
  return { layer, users, nonceStore };
};

describe("GoogleOneTapService", () => {
  const config = { clientId: CLIENT_ID, jwksEndpoint: JWKS_ENDPOINT };

  it("verifies a credential and provisions the user once", async () => {
    const { layer, users, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));

    const nonce1 = "test-nonce-1";
    const nonce2 = "test-nonce-2";
    await Effect.runPromise(
      Effect.all([
        nonceStore.create(nonce1, Date.now() + 60_000),
        nonceStore.create(nonce2, Date.now() + 60_000),
      ]),
    );

    const { first, second } = await withJwks(() =>
      Effect.runPromise(
        Effect.gen(function* () {
          const first = yield* service.signIn(
            signCredential(validClaims({ nonce: hashNonce(nonce1) })),
            nonce1,
          );
          const second = yield* service.signIn(
            signCredential(validClaims({ nonce: hashNonce(nonce2) })),
            nonce2,
          );
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
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const nonce = "test-nonce-bare-iss";
    await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));
    const result = await withJwks(() =>
      Effect.runPromise(
        service
          .signIn(
            signCredential(validClaims({ iss: "accounts.google.com", nonce: hashNonce(nonce) })),
            nonce,
          )
          .pipe(Effect.provide(layer)),
      ),
    );
    expect(result.user.email).toBe("alice@gmail.test");
  });

  it("rejects wrong audience, wrong issuer, expiry, unverified email, and bad signatures", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));

    const nonces = ["n1", "n2", "n3", "n4", "n5"];
    for (const n of nonces) {
      await Effect.runPromise(nonceStore.create(n, Date.now() + 60_000));
    }

    const cases: [string, string][] = [
      [
        signCredential(validClaims({ aud: "someone-else", nonce: hashNonce(nonces[0]) })),
        nonces[0],
      ],
      [
        signCredential(validClaims({ iss: "https://evil.test", nonce: hashNonce(nonces[1]) })),
        nonces[1],
      ],
      [
        signCredential(
          validClaims({ exp: Math.floor(Date.now() / 1000) - 10, nonce: hashNonce(nonces[2]) }),
        ),
        nonces[2],
      ],
      [
        signCredential(validClaims({ email_verified: false, nonce: hashNonce(nonces[3]) })),
        nonces[3],
      ],
      [
        `${signCredential(validClaims({ nonce: hashNonce(nonces[4]) })).slice(0, -8)}AAAAAAAA`,
        nonces[4],
      ],
    ];

    for (const [credential, nonce] of cases) {
      // Re-create nonce if already consumed by a previous failure
      await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));
      const err = await withJwks(() =>
        Effect.runPromise(
          Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer)),
        ),
      );
      expect(err).toBeInstanceOf(GoogleOneTapError);
    }
  });

  it("rejects a replayed id_token (nonce already consumed)", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const nonce = "replay-nonce";
    await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));

    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    // First sign-in succeeds and consumes the nonce
    await withJwks(() =>
      Effect.runPromise(service.signIn(credential, nonce).pipe(Effect.provide(layer))),
    );

    // Second attempt with the same credential + nonce is rejected
    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    expect(err).toBeInstanceOf(GoogleOneTapError);
    expect((err as GoogleOneTapError).message).toMatch(/unknown|already.used/i);
  });

  it("rejects a nonce that was never issued", async () => {
    const { layer } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const nonce = "never-issued";
    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    expect(err).toBeInstanceOf(GoogleOneTapError);
    expect((err as GoogleOneTapError).message).toMatch(/unknown|already.used/i);
  });

  it("rejects an expired nonce", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const nonce = "expired-nonce";
    // Create with a timestamp that is already in the past
    await Effect.runPromise(nonceStore.create(nonce, Date.now() - 1));
    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    expect(err).toBeInstanceOf(GoogleOneTapError);
    expect((err as GoogleOneTapError).message).toMatch(/expired/i);
  });

  it("rejects when nonce in id_token does not match the supplied nonce", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(makeGoogleOneTapService(config));
    const nonce = "correct-nonce";
    await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));

    // Token signed with a different nonce hash
    const credential = signCredential(validClaims({ nonce: hashNonce("wrong-nonce") }));

    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    expect(err).toBeInstanceOf(GoogleOneTapError);
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

  const nonceStore = makeMemoryNonceStore();

  const base = Layer.mergeAll(
    SessionService.layer({
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
    Layer.succeed(GoogleOneTapNonceStore)(nonceStore),
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
    nonceStore,
  };
};

const get = (path: string): Request => new Request(`http://test${path}`, { method: "GET" });

const post = (path: string, body: unknown): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

describe("HTTP Google One Tap endpoint", () => {
  it("GET /sign-in/google-one-tap/nonce returns a nonce", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { nonce: string };
    expect(typeof body.nonce).toBe("string");
    expect(body.nonce.length).toBeGreaterThan(0);
  });

  it("signs in with a valid credential + nonce and sets cookies", async () => {
    const fx = makeHttpFixture();

    // Obtain a server-issued nonce
    const nonceRes = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    const { nonce } = (await nonceRes.json()) as { nonce: string };

    const res = await withJwks(() =>
      fx.handler(
        post("/sign-in/google-one-tap", {
          credential: signCredential(validClaims({ nonce: hashNonce(nonce) })),
          nonce,
        }),
      ),
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
    const nonceRes = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    const { nonce } = (await nonceRes.json()) as { nonce: string };

    const res = await withJwks(() =>
      fx.handler(
        post("/sign-in/google-one-tap", {
          credential: signCredential(validClaims({ aud: "someone-else", nonce: hashNonce(nonce) })),
          nonce,
        }),
      ),
    );
    expect(res.status).toBe(401);
  });

  it("answers 401 for a replayed credential (nonce already used)", async () => {
    const fx = makeHttpFixture();
    const nonceRes = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    const { nonce } = (await nonceRes.json()) as { nonce: string };
    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    // First sign-in consumes the nonce
    const first = await withJwks(() =>
      fx.handler(post("/sign-in/google-one-tap", { credential, nonce })),
    );
    expect(first.status).toBe(200);

    // Replay with the same credential and nonce is rejected
    const replay = await withJwks(() =>
      fx.handler(post("/sign-in/google-one-tap", { credential, nonce })),
    );
    expect(replay.status).toBe(401);
  });

  it("returns 404 when One Tap is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutOneTap(
      post("/sign-in/google-one-tap", { credential: "x", nonce: "y" }),
    );
    expect(res.status).toBe(404);
  });
});
