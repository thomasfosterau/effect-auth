import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as crypto from "node:crypto";
import { Hooks } from "./Hooks.js";
import { SessionStore, UserStore, type UserStoreShape, SessionManager } from "./Session.js";
import { hashToken } from "./TokenHash.js";
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
import { JwtKeyStore, type JwtKeyPair, type JwtKeyStoreShape, JwtService } from "./Jwt.js";
import { generatePKCE, verifyIdToken } from "./OAuth/OAuth.js";
import {
  makeOidcProviderService,
  OidcClientStore,
  OidcCodeStore,
  OidcTokenStore,
  OidcConsentStore,
  OidcProviderError,
  hashOidcSecret,
  type OidcAuthorizationCode,
  type OidcClient,
  type OidcClientStoreShape,
  type OidcCodeStoreShape,
  type OidcConsent,
  type OidcConsentStoreShape,
  type OidcToken,
  type OidcTokenStoreShape,
  OidcProviderService,
} from "./OidcProvider.js";
import type * as Types from "./Types.js";

const ISSUER = "http://idp.test/api/auth";

// -----------------------------------------------------------------------------
// In-memory stores
// -----------------------------------------------------------------------------

const makeOidcStores = () => {
  const clients = new Map<string, OidcClient>();
  const codes = new Map<string, OidcAuthorizationCode>();
  const tokens = new Map<string, OidcToken>();
  const consents = new Map<string, OidcConsent>();
  const jwtKeys: JwtKeyPair[] = [];

  const clientStore: OidcClientStoreShape = {
    create: (c) => Effect.sync(() => (clients.set(c.clientId, c), c)),
    getByClientId: (id) => Effect.succeed(clients.get(id) ?? null),
    update: (c) => Effect.sync(() => (clients.set(c.clientId, c), c)),
    delete: (id) => Effect.sync(() => void clients.delete(id)),
    list: () => Effect.succeed([...clients.values()]),
  };
  const codeStore: OidcCodeStoreShape = {
    create: (c) => Effect.sync(() => (codes.set(c.codeHash, c), c)),
    get: (hash) => Effect.succeed(codes.get(hash) ?? null),
    delete: (hash) => Effect.sync(() => void codes.delete(hash)),
  };
  const tokenStore: OidcTokenStoreShape = {
    create: (t) => Effect.sync(() => (tokens.set(t.tokenHash, t), t)),
    get: (hash) => Effect.succeed(tokens.get(hash) ?? null),
    delete: (hash) => Effect.sync(() => void tokens.delete(hash)),
  };
  const consentStore: OidcConsentStoreShape = {
    get: (userId, clientId) => Effect.succeed(consents.get(`${userId}:${clientId}`) ?? null),
    upsert: (c) => Effect.sync(() => (consents.set(`${c.userId}:${c.clientId}`, c), c)),
    delete: (userId, clientId) => Effect.sync(() => void consents.delete(`${userId}:${clientId}`)),
  };
  const jwtKeyStore: JwtKeyStoreShape = {
    getActive: () => Effect.succeed(jwtKeys[0] ?? null),
    create: (pair) => Effect.sync(() => (jwtKeys.push(pair), pair)),
    list: () => Effect.succeed([...jwtKeys]),
  };

  return { clientStore, codeStore, tokenStore, consentStore, jwtKeyStore, clients, codes, tokens };
};

// -----------------------------------------------------------------------------
// Service-level tests
// -----------------------------------------------------------------------------

const makeUser = (id: string, email: string): Types.User => {
  const now = new Date();
  return {
    id,
    email,
    emailVerified: true,
    name: "Test User",
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
};

describe("OidcProviderService", () => {
  const config = {
    issuer: ISSUER,
    loginPage: "http://idp.test/login",
    consentPage: "http://idp.test/consent",
  };

  const setup = () => {
    const stores = makeOidcStores();
    const layer = Layer.mergeAll(
      Layer.succeed(OidcClientStore)(stores.clientStore),
      Layer.succeed(OidcCodeStore)(stores.codeStore),
      Layer.succeed(OidcTokenStore)(stores.tokenStore),
      Layer.succeed(OidcConsentStore)(stores.consentStore),
    );
    return { stores, layer };
  };

  it("registers web clients with a secret and native clients without", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(makeOidcProviderService(config));

    const { web, native } = await Effect.runPromise(
      Effect.gen(function* () {
        const web = yield* service.registerClient({
          name: "Web App",
          redirectUris: ["https://rp.test/callback"],
        });
        const native = yield* service.registerClient({
          name: "CLI",
          redirectUris: ["http://127.0.0.1:8123/callback"],
          type: "native",
        });
        return { web, native };
      }).pipe(Effect.provide(layer)),
    );

    expect(web.clientSecret).toBeDefined();
    expect(web.client.type).toBe("web");
    expect(web.client.clientSecretHash).toBe(hashOidcSecret(web.clientSecret!));
    expect(native.clientSecret).toBeUndefined();
    expect(native.client.type).toBe("native");
  });

  it("rejects registration without redirect URIs", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(makeOidcProviderService(config));
    const err = await Effect.runPromise(
      Effect.flip(service.registerClient({ name: "x", redirectUris: [] })).pipe(
        Effect.provide(layer),
      ),
    );
    expect(err).toBeInstanceOf(OidcProviderError);
  });

  it("refuses to redirect for unknown clients or unregistered redirect URIs", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(makeOidcProviderService(config));
    const user = makeUser("u1", "u1@test");

    const { unknownClient, badRedirect } = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
        });
        const unknownClient = yield* Effect.flip(
          service.authorize(user, {
            responseType: "code",
            clientId: "nope",
            redirectUri: "https://rp.test/callback",
            scope: "openid",
          }),
        );
        const badRedirect = yield* Effect.flip(
          service.authorize(user, {
            responseType: "code",
            clientId: client.clientId,
            redirectUri: "https://evil.test/callback",
            scope: "openid",
          }),
        );
        return { unknownClient, badRedirect };
      }).pipe(Effect.provide(layer)),
    );

    expect(unknownClient).toBeInstanceOf(OidcProviderError);
    expect(badRedirect).toBeInstanceOf(OidcProviderError);
  });

  it("redirects spec-level errors back to the client", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(makeOidcProviderService(config));
    const user = makeUser("u1", "u1@test");

    const results = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "App",
          redirectUris: ["https://rp.test/callback"],
          skipConsent: true,
        });
        const base = {
          clientId: client.clientId,
          redirectUri: "https://rp.test/callback",
          state: "s1",
        };
        const badResponseType = yield* service.authorize(user, {
          ...base,
          responseType: "token",
          scope: "openid",
        });
        const badScope = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "openid admin:everything",
        });
        const missingOpenid = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "profile",
        });
        const plainPkce = yield* service.authorize(user, {
          ...base,
          responseType: "code",
          scope: "openid",
          codeChallenge: "challenge",
          codeChallengeMethod: "plain",
        });
        return { badResponseType, badScope, missingOpenid, plainPkce };
      }).pipe(Effect.provide(layer)),
    );

    for (const [result, error] of [
      [results.badResponseType, "unsupported_response_type"],
      [results.badScope, "invalid_scope"],
      [results.missingOpenid, "invalid_scope"],
      [results.plainPkce, "invalid_request"],
    ] as const) {
      expect(result.type).toBe("error");
      const url = new URL(result.redirectTo);
      expect(url.origin + url.pathname).toBe("https://rp.test/callback");
      expect(url.searchParams.get("error")).toBe(error);
      expect(url.searchParams.get("state")).toBe("s1");
    }
  });

  it("requires PKCE from native (public) clients", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(makeOidcProviderService(config));
    const user = makeUser("u1", "u1@test");

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const { client } = yield* service.registerClient({
          name: "CLI",
          redirectUris: ["http://127.0.0.1:8123/callback"],
          type: "native",
          skipConsent: true,
        });
        return yield* service.authorize(user, {
          responseType: "code",
          clientId: client.clientId,
          redirectUri: "http://127.0.0.1:8123/callback",
          scope: "openid",
        });
      }).pipe(Effect.provide(layer)),
    );

    expect(result.type).toBe("error");
    expect(new URL(result.redirectTo).searchParams.get("error")).toBe("invalid_request");
  });

  it("resolves trusted config clients without touching the store", async () => {
    const { layer } = setup();
    const service = await Effect.runPromise(
      makeOidcProviderService({
        ...config,
        trustedClients: [
          {
            clientId: "first-party",
            clientSecret: "shh",
            name: "First Party",
            redirectUris: ["https://fp.test/cb"],
          },
        ],
      }),
    );
    const user = makeUser("u1", "u1@test");

    const result = await Effect.runPromise(
      service
        .authorize(user, {
          responseType: "code",
          clientId: "first-party",
          redirectUri: "https://fp.test/cb",
          scope: "openid",
        })
        .pipe(Effect.provide(layer)),
    );

    // Trusted clients skip consent by default.
    expect(result.type).toBe("code");
    expect(new URL(result.redirectTo).searchParams.get("code")).toBeTruthy();
  });
});

// -----------------------------------------------------------------------------
// HTTP layer: full end-to-end flow
// -----------------------------------------------------------------------------

/** A web handler wired with the OIDC provider endpoints over in-memory stores. */
const makeHttpFixture = () => {
  const usersById = new Map<string, Types.User>();
  const sessions = new Map<string, Types.Session>();
  const oidc = makeOidcStores();
  let userSeq = 0;

  const seedUser = (email: string, attributes: Record<string, unknown> = {}): string => {
    const id = `u${++userSeq}`;
    const now = new Date();
    usersById.set(id, {
      id,
      email,
      emailVerified: true,
      name: `User ${id}`,
      createdAt: now,
      updatedAt: now,
      attributes,
    });
    return id;
  };
  const makeSession = (userId: string): string => {
    const rawToken = crypto.randomBytes(12).toString("hex");
    const tokenHash = hashToken(rawToken);
    const now = new Date();
    sessions.set(tokenHash, {
      id: tokenHash,
      userId,
      expiresAt: new Date(Date.now() + 3600_000),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });
    return rawToken;
  };

  const userStore: UserStoreShape = {
    get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId) => Effect.succeed(null),
  };
  const userServiceStore = {
    get: userStore.get,
    getByEmail: () => Effect.succeed(null),
    update: (user: Types.User) => Effect.sync(() => (usersById.set(user.id, user), user)),
    delete: () => Effect.void,
  };
  const sessionStore = {
    create: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (id: string) => Effect.sync(() => sessions.get(id) ?? null),
    update: (s: Types.Session) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (id: string) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: (userId: string) =>
      Effect.sync(() => {
        for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
      }),
    listByUserId: (userId: string) =>
      Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
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

  const oidcLayer = Layer.mergeAll(
    OidcProviderService.layer({
      issuer: ISSUER,
      loginPage: "http://idp.test/login",
      consentPage: "http://idp.test/consent",
    }),
    JwtService.layer({ issuer: ISSUER }),
    Layer.succeed(OidcClientStore)(oidc.clientStore),
    Layer.succeed(OidcCodeStore)(oidc.codeStore),
    Layer.succeed(OidcTokenStore)(oidc.tokenStore),
    Layer.succeed(OidcConsentStore)(oidc.consentStore),
    Layer.succeed(JwtKeyStore)(oidc.jwtKeyStore),
    // resolveOidcProvider needs the core user store in the ambient context.
    Layer.succeed(UserStore)(userStore),
  );

  const withOidc = Layer.mergeAll(base, oidcLayer) as Layer.Layer<AuthServices>;
  const withoutOidc = base as Layer.Layer<AuthServices>;

  return {
    seedUser,
    makeSession,
    handler: makeAuthWebHandler({ services: withOidc, cookie: { secure: false } }).handler,
    handlerWithoutOidc: makeAuthWebHandler({ services: withoutOidc, cookie: { secure: false } })
      .handler,
  };
};

const post = (path: string, body: unknown, sessionId?: string): Request =>
  new Request(`http://idp.test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
    },
    body: JSON.stringify(body),
  });

const get = (
  path: string,
  query: Record<string, string> = {},
  options: { sessionId?: string; bearer?: string } = {},
): Request => {
  const url = new URL(`http://idp.test${path}`);
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  return new Request(url, {
    headers: {
      ...(options.sessionId !== undefined
        ? { cookie: `conduit_session=${options.sessionId}` }
        : {}),
      ...(options.bearer !== undefined ? { authorization: `Bearer ${options.bearer}` } : {}),
    },
  });
};

/** Swap `globalThis.fetch` for a canned JWKS response while `thunk` runs. */
const withJwksFetch = async <A>(jwks: unknown, thunk: () => Promise<A>): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } }),
    )) as typeof fetch;
  try {
    return await thunk();
  } finally {
    globalThis.fetch = original;
  }
};

describe("HTTP OIDC provider endpoints", () => {
  it("runs the full flow: register -> authorize -> token (PKCE) -> id_token/JWKS -> userinfo -> refresh", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userId = fx.seedUser("alice@idp.test");
    const userSid = fx.makeSession(userId);

    // 1. Register a client (admin-gated; non-admins are rejected).
    const denied = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"] },
        fx.makeSession(fx.seedUser("pleb@idp.test")),
      ),
    );
    expect(denied.status).toBe(403);

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    expect(registered.status).toBe(200);
    const { client, clientSecret } = (await registered.json()) as {
      client: { clientId: string };
      clientSecret: string;
    };
    expect(clientSecret).toBeTruthy();

    // 2. Authorize with the user's session cookie (+ PKCE + nonce).
    const pkce = await Effect.runPromise(generatePKCE());
    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid profile email offline_access",
          state: "st-1",
          code_challenge: pkce.codeChallenge,
          code_challenge_method: "S256",
          nonce: "n-1",
        },
        { sessionId: userSid },
      ),
    );
    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.get("location")!);
    expect(location.origin + location.pathname).toBe("https://rp.test/cb");
    expect(location.searchParams.get("state")).toBe("st-1");
    const code = location.searchParams.get("code")!;
    expect(code).toBeTruthy();

    // 3. Exchange the code (PKCE verifier + client secret).
    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      refresh_token: string;
      id_token: string;
      scope: string;
    };
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.scope).toBe("openid profile email offline_access");

    // A code is single use.
    const replay = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(replay.status).toBe(400);

    // 4. Verify the id_token against the published JWKS.
    const jwksRes = await fx.handler(get("/.well-known/jwks.json"));
    expect(jwksRes.status).toBe(200);
    const jwks = (await jwksRes.json()) as { keys: unknown[] };
    expect(jwks.keys.length).toBeGreaterThan(0);

    const claims = await withJwksFetch(jwks, () =>
      Effect.runPromise(
        verifyIdToken(tokens.id_token, {
          provider: "test",
          jwksEndpoint: "http://idp.test/api/auth/.well-known/jwks.json",
          issuer: ISSUER,
          audience: client.clientId,
          nonce: "n-1",
        }),
      ),
    );
    expect(claims["sub"]).toBe(userId);
    expect(claims["email"]).toBe("alice@idp.test");
    expect(claims["email_verified"]).toBe(true);

    // 5. UserInfo with the bearer access token.
    const userinfo = await fx.handler(get("/oauth2/userinfo", {}, { bearer: tokens.access_token }));
    expect(userinfo.status).toBe(200);
    const info = (await userinfo.json()) as Record<string, unknown>;
    expect(info["sub"]).toBe(userId);
    expect(info["email"]).toBe("alice@idp.test");
    expect(info["name"]).toBe(`User ${userId}`);

    const noToken = await fx.handler(get("/oauth2/userinfo"));
    expect(noToken.status).toBe(401);

    // 6. Refresh grant rotates tokens (client auth via Basic header).
    const basic = Buffer.from(`${client.clientId}:${clientSecret}`).toString("base64");
    const refreshRes = await fx.handler(
      new Request("http://idp.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Basic ${basic}` },
        body: JSON.stringify({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
      }),
    );
    expect(refreshRes.status).toBe(200);
    const rotated = (await refreshRes.json()) as {
      access_token: string;
      refresh_token: string;
      id_token: string;
    };
    expect(rotated.access_token).not.toBe(tokens.access_token);
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
    expect(rotated.id_token).toBeTruthy();

    // The old refresh token is burned; the rotated one still works.
    const reuse = await fx.handler(
      post("/oauth2/token", {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(reuse.status).toBe(400);
    expect(((await reuse.json()) as { message: string }).message).toBe("invalid_grant");

    // The rotated access token is live.
    const userinfo2 = await fx.handler(
      get("/oauth2/userinfo", {}, { bearer: rotated.access_token }),
    );
    expect(userinfo2.status).toBe(200);
  });

  it("walks unauthenticated users through the login page and consent through the consent page", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("bob@idp.test"));

    const registered = await fx.handler(
      post("/oauth2/register", { name: "RP", redirectUris: ["https://rp.test/cb"] }, adminSid),
    );
    const { client, clientSecret } = (await registered.json()) as {
      client: { clientId: string };
      clientSecret: string;
    };

    const authorizeQuery = {
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: "https://rp.test/cb",
      scope: "openid email",
      state: "st-2",
    };

    // No session: 302 to the login page with the original URL attached.
    const anonymous = await fx.handler(get("/oauth2/authorize", authorizeQuery));
    expect(anonymous.status).toBe(302);
    const loginUrl = new URL(anonymous.headers.get("location")!);
    expect(loginUrl.origin + loginUrl.pathname).toBe("http://idp.test/login");
    expect(loginUrl.searchParams.get("redirect_to")).toContain("/oauth2/authorize");

    // Signed in, consent not yet granted: 302 to the consent page.
    const needsConsent = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    expect(needsConsent.status).toBe(302);
    const consentUrl = new URL(needsConsent.headers.get("location")!);
    expect(consentUrl.origin + consentUrl.pathname).toBe("http://idp.test/consent");
    expect(consentUrl.searchParams.get("client_id")).toBe(client.clientId);
    expect(consentUrl.searchParams.get("scope")).toBe("openid email");
    const consentCode = consentUrl.searchParams.get("consent_code")!;

    // Denying redirects back with access_denied.
    const deniedConsent = await fx.handler(
      post("/oauth2/consent", { consentCode, accept: false }, userSid),
    );
    expect(deniedConsent.status).toBe(200);
    const deniedRedirect = new URL(
      ((await deniedConsent.json()) as { redirectTo: string }).redirectTo,
    );
    expect(deniedRedirect.searchParams.get("error")).toBe("access_denied");
    expect(deniedRedirect.searchParams.get("state")).toBe("st-2");

    // A consent code is single use.
    const reused = await fx.handler(
      post("/oauth2/consent", { consentCode, accept: true }, userSid),
    );
    expect(reused.status).toBe(400);

    // Run authorize again and accept this time.
    const again = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    const consentCode2 = new URL(again.headers.get("location")!).searchParams.get("consent_code")!;
    const accepted = await fx.handler(
      post("/oauth2/consent", { consentCode: consentCode2, accept: true }, userSid),
    );
    expect(accepted.status).toBe(200);
    const acceptedRedirect = new URL(
      ((await accepted.json()) as { redirectTo: string }).redirectTo,
    );
    const code = acceptedRedirect.searchParams.get("code")!;
    expect(code).toBeTruthy();
    expect(acceptedRedirect.searchParams.get("state")).toBe("st-2");

    // The consent-issued code exchanges normally.
    const tokenRes = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code,
        redirect_uri: "https://rp.test/cb",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(tokenRes.status).toBe(200);

    // Consent is remembered: the next authorize goes straight to the client.
    const remembered = await fx.handler(
      get("/oauth2/authorize", authorizeQuery, { sessionId: userSid }),
    );
    const rememberedUrl = new URL(remembered.headers.get("location")!);
    expect(rememberedUrl.origin + rememberedUrl.pathname).toBe("https://rp.test/cb");
    expect(rememberedUrl.searchParams.get("code")).toBeTruthy();
  });

  it("rejects a token exchange with a wrong PKCE verifier or wrong secret", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("carol@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = (await registered.json()) as {
      client: { clientId: string };
      clientSecret: string;
    };

    const pkce = await Effect.runPromise(generatePKCE());
    const authorizeOnce = async () => {
      const res = await fx.handler(
        get(
          "/oauth2/authorize",
          {
            response_type: "code",
            client_id: client.clientId,
            redirect_uri: "https://rp.test/cb",
            scope: "openid",
            code_challenge: pkce.codeChallenge,
            code_challenge_method: "S256",
          },
          { sessionId: userSid },
        ),
      );
      return new URL(res.headers.get("location")!).searchParams.get("code")!;
    };

    // Wrong PKCE verifier -> invalid_grant.
    const badVerifier = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code: await authorizeOnce(),
        redirect_uri: "https://rp.test/cb",
        code_verifier: "wrong-verifier",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(badVerifier.status).toBe(400);
    expect(((await badVerifier.json()) as { message: string }).message).toBe("invalid_grant");

    // Wrong client secret -> 401 invalid_client.
    const badSecret = await fx.handler(
      post("/oauth2/token", {
        grant_type: "authorization_code",
        code: await authorizeOnce(),
        redirect_uri: "https://rp.test/cb",
        code_verifier: pkce.codeVerifier,
        client_id: client.clientId,
        client_secret: "wrong-secret",
      }),
    );
    expect(badSecret.status).toBe(401);
    expect(((await badSecret.json()) as { message: string }).message).toBe("invalid_client");

    // Unsupported grant type -> 400.
    const badGrant = await fx.handler(
      post("/oauth2/token", {
        grant_type: "password",
        client_id: client.clientId,
        client_secret: clientSecret,
      }),
    );
    expect(badGrant.status).toBe(400);
    expect(((await badGrant.json()) as { message: string }).message).toBe("unsupported_grant_type");
  });

  it("accepts a form-urlencoded token request", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@idp.test", { role: "admin" }));
    const userSid = fx.makeSession(fx.seedUser("dave@idp.test"));

    const registered = await fx.handler(
      post(
        "/oauth2/register",
        { name: "RP", redirectUris: ["https://rp.test/cb"], skipConsent: true },
        adminSid,
      ),
    );
    const { client, clientSecret } = (await registered.json()) as {
      client: { clientId: string };
      clientSecret: string;
    };

    const authorize = await fx.handler(
      get(
        "/oauth2/authorize",
        {
          response_type: "code",
          client_id: client.clientId,
          redirect_uri: "https://rp.test/cb",
          scope: "openid",
        },
        { sessionId: userSid },
      ),
    );
    const code = new URL(authorize.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fx.handler(
      new Request("http://idp.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: "https://rp.test/cb",
          client_id: client.clientId,
          client_secret: clientSecret,
        }).toString(),
      }),
    );
    expect(tokenRes.status).toBe(200);
    expect(((await tokenRes.json()) as { access_token: string }).access_token).toBeTruthy();
  });

  it("serves the discovery document", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handler(get("/.well-known/openid-configuration"));
    expect(res.status).toBe(200);
    const doc = (await res.json()) as Record<string, unknown>;
    expect(doc["issuer"]).toBe(ISSUER);
    expect(doc["authorization_endpoint"]).toBe(`${ISSUER}/oauth2/authorize`);
    expect(doc["token_endpoint"]).toBe(`${ISSUER}/oauth2/token`);
    expect(doc["userinfo_endpoint"]).toBe(`${ISSUER}/oauth2/userinfo`);
    expect(doc["jwks_uri"]).toBe(`${ISSUER}/.well-known/jwks.json`);
    expect(doc["code_challenge_methods_supported"]).toEqual(["S256"]);
  });

  it("returns 404 when the OIDC provider is not configured", async () => {
    const fx = makeHttpFixture();
    const discovery = await fx.handlerWithoutOidc(get("/.well-known/openid-configuration"));
    expect(discovery.status).toBe(404);
    const token = await fx.handlerWithoutOidc(
      post("/oauth2/token", { grant_type: "authorization_code" }),
    );
    expect(token.status).toBe(404);
  });
});
