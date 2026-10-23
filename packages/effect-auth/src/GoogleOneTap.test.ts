import { assert, describe, it, expect } from "vite-plus/test";
import { memoryEmailPasswordStore } from "./testing/MemoryStores.ts";
import { Array as Arr, Effect, Layer, Predicate, Schema } from "effect";
import * as Cipher from "./Cipher.ts";
import { UserNotFoundError } from "./Errors.ts";
import { Hooks } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import { hashToken } from "./TokenHash.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { UserServiceStore, UserService } from "./User.ts";
import { AuthLifecycleService } from "./AuthLifecycle.ts";
import { EmailPasswordService, EmailPasswordStore } from "./email/EmailPassword.ts";
import { PasswordHasher } from "./password/Password.ts";
import { EmailVerificationService } from "./email/EmailVerification.ts";
import { PasswordResetService } from "./password/PasswordReset.ts";
import * as HttpServer from "./http/HttpServer.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { type OAuthCreateUserInput, OAuthUserStore } from "./oauth/OAuth.ts";
import { GoogleOneTapError, GoogleOneTapService, GoogleOneTapNonceStore } from "./GoogleOneTap.ts";
import * as GoogleOneTap from "./GoogleOneTap.ts";
import type * as Types from "./Types.ts";

const CLIENT_ID = "client-123.apps.googleusercontent.com";
const JWKS_ENDPOINT = "https://fake-google.test/certs";

// --- A fake Google: an ES256 key + JWT signer + JWKS document -----------------

const { publicKeyJwk, privateKeyPem } = Cipher.generateJwsKeyPair("ES256");
const KID = "test-key-1";
const JWKS = {
  keys: [{ ...publicKeyJwk, kid: KID, alg: "ES256" }],
};

const encodeJson = Schema.encodeSync(Schema.fromJsonString(Schema.Json));

/** A JSON response body, decoded against the shape the test reads from it. */
const jsonBody = async <S extends Schema.ConstraintDecoder<unknown>>(
  response: Response,
  schema: S,
): Promise<S["Type"]> => Schema.decodeUnknownSync(schema)(await response.json());

const NonceBody = Schema.Struct({ nonce: Schema.String });

const b64 = (value: Schema.Json): string =>
  Buffer.from(encodeJson(value), "utf8").toString("base64url");

const signCredential = (claims: Schema.JsonObject): string => {
  const header = { alg: "ES256", kid: KID, typ: "JWT" };
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature = Cipher.signJws("ES256", Buffer.from(signingInput, "utf8"), privateKeyPem);
  return `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
};

/** Hash a nonce the same way GoogleOneTap.ts does (SHA-256 hex). */
const hashNonce = hashToken;

const validClaims = (overrides: Schema.JsonObject = {}): Schema.JsonObject => ({
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
  globalThis.fetch = () => Promise.resolve(Response.json(JWKS));
  return new Promise<A>((resolve) => resolve(thunk())).finally(() => {
    globalThis.fetch = original;
  });
};

// ---------------------------------------------------------------------------
// In-memory nonce store for tests
// ---------------------------------------------------------------------------

const makeMemoryNonceStore = (): typeof GoogleOneTapNonceStore.Service => {
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
  const identifierRecords = new Map<string, Identifier>();
  const identifiers = memoryIdentifierStore(identifierRecords);
  let userSeq = 0;
  /** The `identifier` each `createUser` call was given. */
  const createdWith: Array<OAuthCreateUserInput["identifier"]> = [];

  const userStore: typeof OAuthUserStore.Service = {
    getUser: (userId) => {
      const u = users.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input) =>
      Effect.sync(() => {
        createdWith.push(input.identifier);
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        users.set(user.id, user);
        return { user, created: true };
      }),
  };
  const coreUserStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
  };
  const sessionsCleared: Array<string> = [];
  const sessionManager: typeof SessionService.Service = {
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
    invalidateUserSessions: (userId) => Effect.sync(() => void sessionsCleared.push(userId)),
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const nonceStore = makeMemoryNonceStore();
  const passwordHashes = new Map<string, string>();

  const layer = Layer.mergeAll(
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(IdentifierStore)(identifiers),
    Layer.succeed(UserStore)(coreUserStore),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(EmailPasswordStore)(
      memoryEmailPasswordStore({ users: new Map(), passwordHashes }),
    ),
    Layer.succeed(GoogleOneTapNonceStore)(nonceStore),
    Hooks.Default,
    PlatformCrypto.layer,
  );
  return { layer, users, identifiers, createdWith, nonceStore, passwordHashes, sessionsCleared };
};

describe("GoogleOneTapService", () => {
  const config = { clientId: CLIENT_ID, jwksEndpoint: JWKS_ENDPOINT };

  it("verifies a credential and provisions the user once", async () => {
    const { layer, users, identifiers, createdWith, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));

    const nonce1 = "test-nonce-1";
    const nonce2 = "test-nonce-2";
    await Effect.runPromise(
      Effect.all(
        [
          nonceStore.create(nonce1, Date.now() + 60_000),
          nonceStore.create(nonce2, Date.now() + 60_000),
        ],
        { concurrency: 1 },
      ),
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
    const emailIdentifier = await Effect.runPromise(
      identifiers.getByValue("email", "alice@gmail.test"),
    );
    expect(emailIdentifier?.userId).toBe(first.user.id);
    expect(emailIdentifier?.verified).toBe(true);
    // The store was handed the address to create the user with (#380).
    expect(createdWith).toEqual([
      { type: "email", value: "alice@gmail.test", verified: true, verifiedAt: expect.any(Date) },
    ]);
    expect(first.user.name).toBe("Alice");
    expect(first.session.userId).toBe(first.user.id);
    expect(first.claims["sub"]).toBe("google-user-1");
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(users.size).toBe(1);
  });

  it("accepts the bare `accounts.google.com` issuer", async () => {
    const { layer, identifiers, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
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
    const emailIdentifier = await Effect.runPromise(
      identifiers.getByValue("email", "alice@gmail.test"),
    );
    expect(emailIdentifier?.userId).toBe(result.user.id);
  });

  it("rejects wrong audience, wrong issuer, expiry, unverified email, and bad signatures", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));

    const nonces = ["n1", "n2", "n3", "n4", "n5"];
    await Arr.reduce(nonces, Promise.resolve(), async (previous, n) => {
      await previous;
      await Effect.runPromise(nonceStore.create(n, Date.now() + 60_000));
    });

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

    await Arr.reduce(cases, Promise.resolve(), async (previous, [credential, nonce]) => {
      await previous;
      // Re-create nonce if already consumed by a previous failure
      await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));
      const err = await withJwks(() =>
        Effect.runPromise(
          Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer)),
        ),
      );
      expect(err).toBeInstanceOf(GoogleOneTapError);
    });
  });

  it("clears a squatter's password and sessions when Google proves the address (#440)", async () => {
    const { layer, users, identifiers, nonceStore, passwordHashes, sessionsCleared } = makeStores();
    // A squatter signed up with the address and a password they know; it was
    // never verified.
    const now = new Date();
    users.set("user-squat", { id: "user-squat", createdAt: now, updatedAt: now, attributes: {} });
    await Effect.runPromise(
      identifiers.create(
        makeIdentifier({ userId: "user-squat", type: "email", value: "alice@gmail.test" }),
      ),
    );
    passwordHashes.set("user-squat", "squatter-hash");

    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
    const nonce = "squat-nonce";
    await Effect.runPromise(nonceStore.create(nonce, Date.now() + 60_000));
    const result = await withJwks(() =>
      Effect.runPromise(
        service
          .signIn(signCredential(validClaims({ nonce: hashNonce(nonce) })), nonce)
          .pipe(Effect.provide(layer)),
      ),
    );

    expect(result.user.id).toBe("user-squat");
    expect(passwordHashes.has("user-squat")).toBe(false);
    expect(sessionsCleared).toEqual(["user-squat"]);
    const identifier = await Effect.runPromise(identifiers.getByValue("email", "alice@gmail.test"));
    expect(identifier?.verified).toBe(true);
  });

  it("rejects a replayed id_token (nonce already consumed)", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
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
    assert.instanceOf(err, GoogleOneTapError);
    expect(err.message).toMatch(/unknown|already.used/i);
  });

  it("rejects a nonce that was never issued", async () => {
    const { layer } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
    const nonce = "never-issued";
    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    assert.instanceOf(err, GoogleOneTapError);
    expect(err.message).toMatch(/unknown|already.used/i);
  });

  it("rejects an expired nonce", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
    const nonce = "expired-nonce";
    // Create with a timestamp that is already in the past
    await Effect.runPromise(nonceStore.create(nonce, Date.now() - 1));
    const credential = signCredential(validClaims({ nonce: hashNonce(nonce) }));

    const err = await withJwks(() =>
      Effect.runPromise(Effect.flip(service.signIn(credential, nonce)).pipe(Effect.provide(layer))),
    );
    assert.instanceOf(err, GoogleOneTapError);
    expect(err.message).toMatch(/expired/i);
  });

  it("rejects when nonce in id_token does not match the supplied nonce", async () => {
    const { layer, nonceStore } = makeStores();
    const service = await Effect.runPromise(Effect.provide(GoogleOneTap.make(config), layer));
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
  const identifierRecords = new Map<string, Identifier>();
  const identifierStore = memoryIdentifierStore(identifierRecords);
  const sessions = new Map<string, Types.Session>();
  let userSeq = 0;

  const oauthUserStore: typeof OAuthUserStore.Service = {
    getUser: (userId) => {
      const u = usersById.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    createUser: (input) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `u${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        usersById.set(user.id, user);
        return { user, created: true };
      }),
  };
  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
  };
  const userServiceStore = {
    get: userStore.get,
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore: typeof SessionStore.Service = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: () => Effect.void,
    listByUserId: () => Effect.succeed([]),
  };

  const nonceStore = makeMemoryNonceStore();

  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(
    Layer.provide(
      Layer.mergeAll(
        Layer.succeed(SessionStore)(sessionStore),
        Layer.succeed(UserStore)(userStore),
        Hooks.Default,
      ),
    ),
  );

  // SAFETY: the `undefined` services complete `AuthServices` for
  // `HttpServer.make`; no One Tap route these tests drive calls them.
  const base = Layer.mergeAll(
    sessionServiceLayer,
    UserService.layer().pipe(Layer.provide(Layer.succeed(UserServiceStore)(userServiceStore))),
    Layer.succeed(UserServiceStore)(userServiceStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Hooks.Default,
    Layer.succeed(AuthLifecycleService)(undefined as never),
    Layer.succeed(EmailPasswordService)(undefined as never),
    Layer.succeed(PasswordHasher)(undefined as never),
    Layer.succeed(EmailVerificationService)(undefined as never),
    Layer.succeed(PasswordResetService)(undefined as never),
  );

  const oneTapDeps = Layer.mergeAll(
    Layer.succeed(OAuthUserStore)(oauthUserStore),
    Layer.succeed(IdentifierStore)(identifierStore),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(GoogleOneTapNonceStore)(nonceStore),
    Layer.succeed(EmailPasswordStore)(memoryEmailPasswordStore()),
    sessionServiceLayer,
  );

  const oneTapLayer = Layer.mergeAll(
    GoogleOneTapService.layer({ clientId: CLIENT_ID, jwksEndpoint: JWKS_ENDPOINT }).pipe(
      Layer.provide(oneTapDeps),
    ),
    Layer.succeed(OAuthUserStore)(oauthUserStore),
    Layer.succeed(GoogleOneTapNonceStore)(nonceStore),
  );

  return {
    handler: HttpServer.make({
      services: Layer.mergeAll(base, oneTapLayer),
      cookie: { secure: false, lastLoginMethod: true },
    }).handler,
    handlerWithoutOneTap: HttpServer.make({
      services: base,
      cookie: { secure: false },
    }).handler,
    nonceStore,
  };
};

const get = (path: string): Request => new Request(`http://test${path}`, { method: "GET" });

const post = (path: string, body: Schema.Json): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: encodeJson(body),
  });

describe("HTTP Google One Tap endpoint", () => {
  it("GET /sign-in/google-one-tap/nonce returns a nonce", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    expect(res.status).toBe(200);
    const body = await jsonBody(res, NonceBody);
    expect(Predicate.isString(body.nonce)).toBe(true);
    expect(body.nonce.length).toBeGreaterThan(0);
  });

  it("signs in with a valid credential + nonce and sets cookies", async () => {
    const fx = makeHttpFixture();

    // Obtain a server-issued nonce
    const nonceRes = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    const { nonce } = await jsonBody(nonceRes, NonceBody);

    const res = await withJwks(() =>
      fx.handler(
        post("/sign-in/google-one-tap", {
          credential: signCredential(validClaims({ nonce: hashNonce(nonce) })),
          nonce,
        }),
      ),
    );
    expect(res.status).toBe(200);
    const body = await jsonBody(
      res,
      Schema.Struct({ user: Schema.Struct({ email: Schema.String }) }),
    );
    expect(body.user.email).toBe("alice@gmail.test");
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((c) => c.startsWith("conduit_session="))).toBe(true);
    expect(cookies.some((c) => c.startsWith("conduit_session_last_method=google"))).toBe(true);
  });

  it("answers 401 for an invalid credential", async () => {
    const fx = makeHttpFixture();
    const nonceRes = await fx.handler(get("/sign-in/google-one-tap/nonce"));
    const { nonce } = await jsonBody(nonceRes, NonceBody);

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
    const { nonce } = await jsonBody(nonceRes, NonceBody);
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
