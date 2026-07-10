import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { UserNotFoundError } from "./Errors.js";
import { Hooks } from "./Hooks.js";
import * as PlatformCrypto from "./PlatformCrypto.js";
import { SessionService } from "./session/SessionService.js";
import { SessionStore } from "./session/SessionStore.js";
import { UserStore } from "./session/UserStore.js";
import { hashToken } from "./TokenHash.js";
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
import { OrganizationStore, type Member, type SSOProvider } from "./index.js";
import { OAuthStateStore, OAuthUserStore, type OAuthState } from "./oauth/OAuth.js";
import { makeSSOService, SSOProviderStore, SSOError, SSOService } from "./SSO.js";
import type * as Types from "./Types.js";

/** Swap `globalThis.fetch` for a route handler while `thunk` runs. */
const withFetch = async <A>(
  routes: Record<string, unknown>,
  thunk: () => Promise<A>,
): Promise<A> => {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input.toString();
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    const body = key ? routes[key] : { error: "no route" };
    return Promise.resolve(
      new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } }),
    );
  }) as typeof fetch;
  try {
    return await thunk();
  } finally {
    globalThis.fetch = original;
  }
};

const makeStores = () => {
  const providers = new Map<string, SSOProvider>();
  const users = new Map<string, Types.User>();
  const usersByEmail = new Map<string, Types.User>();
  const states = new Map<string, OAuthState>();
  const members: Member[] = [];
  let userSeq = 0;

  const ssoStore: typeof SSOProviderStore.Service = {
    create: (p) => Effect.sync(() => (providers.set(p.id, p), p)),
    getById: (id) => Effect.succeed(providers.get(id) ?? null),
    getByDomain: (domain) =>
      Effect.succeed([...providers.values()].find((p) => p.domain === domain) ?? null),
    list: () => Effect.succeed([...providers.values()]),
  };

  const userStore = {
    getUser: (userId: string) => {
      const u = users.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    getUserByEmail: (email: string) => Effect.succeed(usersByEmail.get(email) ?? null),
    createUser: (input: { email: string; emailVerified: boolean; name?: string; image?: string }) =>
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

  const stateStore = {
    create: (s: OAuthState) => Effect.sync(() => (states.set(s.state, s), s)),
    get: (state: string) => Effect.succeed(states.get(state) ?? null),
    delete: (state: string) => Effect.sync(() => void states.delete(state)),
  };

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
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
    // Unused by SSO:
    createOrganization: () => Effect.die("unused") as never,
    getOrganizationById: () => Effect.die("unused") as never,
    getOrganizationBySlug: () => Effect.die("unused") as never,
    updateOrganization: () => Effect.die("unused") as never,
    deleteOrganization: () => Effect.die("unused") as never,
    updateMember: () => Effect.die("unused") as never,
    deleteMember: () => Effect.die("unused") as never,
    listMembersByOrganization: () => Effect.die("unused") as never,
    listMembersByUser: () => Effect.die("unused") as never,
    countMembersByOrganization: () => Effect.die("unused") as never,
    createInvitation: () => Effect.die("unused") as never,
    getInvitation: () => Effect.die("unused") as never,
    updateInvitation: () => Effect.die("unused") as never,
    listInvitationsByOrganization: () => Effect.die("unused") as never,
    listInvitationsByEmail: () => Effect.die("unused") as never,
  };

  const layer = Layer.mergeAll(
    Layer.succeed(SSOProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(userStore),
    Layer.succeed(SessionService)(sessionManager),
    Layer.succeed(OrganizationStore)(orgStore),
    Hooks.Default,
    PlatformCrypto.layer,
  );

  return { layer, providers, users, members };
};

const ACME = {
  issuer: "https://idp.acme.test",
  domain: "acme.test",
  clientId: "client-1",
  clientSecret: "secret-1",
  redirectUri: "https://app/api/auth/sso/callback",
  authorizationEndpoint: "https://idp.acme.test/authorize",
  tokenEndpoint: "https://idp.acme.test/token",
  userInfoEndpoint: "https://idp.acme.test/userinfo",
  organizationId: "org-1",
};

describe("SSOService", () => {
  it("registers a provider and routes sign-in by email domain", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(makeSSOService().pipe(Effect.provide(layer)));

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const provider = yield* sso.registerProvider("admin", ACME);
        const resolved = yield* sso.resolveProviderForEmail("worker@ACME.test");
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return { provider, resolved, start };
      }).pipe(Effect.provide(layer)),
    );

    expect(result.provider.domain).toBe("acme.test");
    expect(result.resolved?.id).toBe(result.provider.id);
    const url = new URL(result.start.url);
    expect(url.origin + url.pathname).toBe("https://idp.acme.test/authorize");
    expect(url.searchParams.get("client_id")).toBe("client-1");
    expect(url.searchParams.get("state")).toBe(result.start.state);
  });

  it("provisions a user + org membership on first login and reuses on the second", async () => {
    const { layer, users, members } = makeStores();
    const sso = await Effect.runPromise(
      makeSSOService({ defaultRole: "member" }).pipe(Effect.provide(layer)),
    );

    const idpRoutes = {
      "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
      "https://idp.acme.test/userinfo": {
        sub: "idp-user-9",
        email: "worker@acme.test",
        email_verified: true,
        name: "Worker Bee",
      },
    };

    const signInFlow = () =>
      Effect.gen(function* () {
        const start = yield* sso.signIn({ email: "worker@acme.test" });
        return yield* sso.handleCallback(start.state, "auth-code");
      }).pipe(Effect.provide(layer));

    // Register once.
    await Effect.runPromise(sso.registerProvider("admin", ACME).pipe(Effect.provide(layer)));

    // First login: creates the user and the org membership.
    const first = await withFetch(idpRoutes, () => Effect.runPromise(signInFlow()));
    expect(first.isNewUser).toBe(true);
    expect(first.user.email).toBe("worker@acme.test");
    expect(first.session.userId).toBe(first.user.id);
    expect(members).toEqual([
      { ...members[0], organizationId: "org-1", userId: first.user.id, role: "member" },
    ]);
    expect(users.size).toBe(1);

    // Second login: reuses the same user, no duplicate membership.
    const second = await withFetch(idpRoutes, () => Effect.runPromise(signInFlow()));
    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(users.size).toBe(1);
    expect(members.length).toBe(1);
  });

  it("populates endpoints from OIDC discovery", async () => {
    const { layer, providers } = makeStores();
    const sso = await Effect.runPromise(makeSSOService().pipe(Effect.provide(layer)));

    const discovered = await withFetch(
      {
        "https://idp.acme.test/.well-known/openid-configuration": {
          issuer: "https://idp.acme.test",
          authorization_endpoint: "https://idp.acme.test/auth",
          token_endpoint: "https://idp.acme.test/tok",
          userinfo_endpoint: "https://idp.acme.test/ui",
          jwks_uri: "https://idp.acme.test/jwks",
        },
      },
      () =>
        Effect.runPromise(
          sso
            .registerProvider("admin", {
              issuer: "https://idp.acme.test",
              domain: "acme.test",
              clientId: "c",
              clientSecret: "s",
              redirectUri: "https://app/cb",
              discover: true,
            })
            .pipe(Effect.provide(layer)),
        ),
    );

    expect(discovered.authorizationEndpoint).toBe("https://idp.acme.test/auth");
    expect(discovered.tokenEndpoint).toBe("https://idp.acme.test/tok");
    expect(discovered.userInfoEndpoint).toBe("https://idp.acme.test/ui");
    expect(providers.size).toBe(1);
  });

  it("fails sign-in for an unknown domain", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(makeSSOService().pipe(Effect.provide(layer)));
    const err = await Effect.runPromise(
      Effect.flip(sso.signIn({ email: "nobody@unknown.test" })).pipe(Effect.provide(layer)),
    );
    expect(err).toBeInstanceOf(SSOError);
  });

  it("rejects a callback whose profile email is unverified", async () => {
    const { layer } = makeStores();
    const sso = await Effect.runPromise(makeSSOService().pipe(Effect.provide(layer)));
    await Effect.runPromise(sso.registerProvider("admin", ACME).pipe(Effect.provide(layer)));

    const err = await withFetch(
      {
        "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
        "https://idp.acme.test/userinfo": {
          sub: "x",
          email: "worker@acme.test",
          email_verified: false,
        },
      },
      () =>
        Effect.runPromise(
          Effect.gen(function* () {
            const start = yield* sso.signIn({ email: "worker@acme.test" });
            return yield* Effect.flip(sso.handleCallback(start.state, "code"));
          }).pipe(Effect.provide(layer)),
        ),
    );
    expect(err).toBeInstanceOf(SSOError);
  });
});

// --- HTTP layer --------------------------------------------------------------

/** A web handler wired with the SSO endpoints over in-memory stores. */
const makeHttpFixture = () => {
  const usersById = new Map<string, Types.User>();
  const usersByEmail = new Map<string, Types.User>();
  const sessions = new Map<string, Types.Session>();
  const providers = new Map<string, SSOProvider>();
  const states = new Map<string, OAuthState>();
  const members: Member[] = [];
  let userSeq = 0;

  const seedUser = (email: string, attributes: Record<string, unknown> = {}): string => {
    const id = `u${++userSeq}`;
    const now = new Date();
    const user: Types.User = {
      id,
      email,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
      attributes,
    };
    usersById.set(id, user);
    usersByEmail.set(email, user);
    return id;
  };
  const makeSession = (userId: string): string => {
    const rawToken = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(12))).toString(
      "hex",
    );
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

  const userStore = {
    get: (userId: string) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId: string) => Effect.succeed(null),
  };
  const userServiceStore = {
    get: userStore.get,
    getByEmail: (email: string) => Effect.succeed(usersByEmail.get(email) ?? null),
    update: (user: Types.User) =>
      Effect.sync(() => (usersById.set(user.id, user), usersByEmail.set(user.email, user), user)),
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
  const oauthUserStore = {
    getUser: (userId: string) => {
      const u = usersById.get(userId);
      return u ? Effect.succeed(u) : Effect.fail(new UserNotFoundError({ message: "nf", userId }));
    },
    getUserByEmail: (email: string) => Effect.succeed(usersByEmail.get(email) ?? null),
    createUser: (input: { email: string; emailVerified: boolean; name?: string; image?: string }) =>
      Effect.sync(() => {
        const id = `u${++userSeq}`;
        const now = new Date();
        const user: Types.User = {
          id,
          email: input.email,
          emailVerified: input.emailVerified,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        usersById.set(id, user);
        usersByEmail.set(input.email, user);
        return user;
      }),
  };
  const ssoStore: typeof SSOProviderStore.Service = {
    create: (p) => Effect.sync(() => (providers.set(p.id, p), p)),
    getById: (id) => Effect.succeed(providers.get(id) ?? null),
    getByDomain: (domain) =>
      Effect.succeed([...providers.values()].find((p) => p.domain === domain) ?? null),
    list: () => Effect.succeed([...providers.values()]),
  };
  const stateStore = {
    create: (s: OAuthState) => Effect.sync(() => (states.set(s.state, s), s)),
    get: (state: string) => Effect.succeed(states.get(state) ?? null),
    delete: (state: string) => Effect.sync(() => void states.delete(state)),
  };
  // SSO only ever calls getMember/createMember; the rest are unused stubs.
  const orgStore = {
    createMember: (m: Member) => Effect.sync(() => (members.push(m), m)),
    getMember: (organizationId: string, userId: string) =>
      Effect.succeed(
        members.find((m) => m.organizationId === organizationId && m.userId === userId) ?? null,
      ),
  };

  const coreStoreLayer = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore as never),
    Layer.succeed(UserStore)(userStore),
  );

  const sessionServiceLayer = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(Layer.mergeAll(coreStoreLayer, Hooks.Default)));

  const base = Layer.mergeAll(
    sessionServiceLayer,
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

  // `SSOService` only needs `SSOProviderStore` to construct; `OAuthStateStore`/
  // `OAuthUserStore`/`SessionService`/`Crypto.Crypto` are required dynamically
  // by its `signIn`/`handleCallback` methods, and `OrganizationStore` is
  // resolved optionally at call time — all are provided here as ambient context.
  const ssoDeps = Layer.mergeAll(
    Layer.succeed(SSOProviderStore)(ssoStore),
    Layer.succeed(OAuthStateStore)(stateStore),
    Layer.succeed(OAuthUserStore)(oauthUserStore),
    Layer.succeed(OrganizationStore)(orgStore as never),
    PlatformCrypto.layer,
  );

  const ssoServiceLayer = SSOService.layer().pipe(Layer.provide(ssoDeps));

  const ssoLayer = Layer.mergeAll(ssoDeps, ssoServiceLayer);

  const withSSO = Layer.mergeAll(base, ssoLayer) as Layer.Layer<AuthServices>;
  const withoutSSO = base as Layer.Layer<AuthServices>;

  return {
    seedUser,
    makeSession,
    handler: makeAuthWebHandler({ services: withSSO, cookie: { secure: false } }).handler,
    handlerWithoutSSO: makeAuthWebHandler({ services: withoutSSO, cookie: { secure: false } })
      .handler,
    providers,
    usersByEmail,
  };
};

const post = (path: string, body: unknown, sessionId?: string): Request =>
  new Request(`http://test${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(sessionId !== undefined ? { cookie: `conduit_session=${sessionId}` } : {}),
    },
    body: JSON.stringify(body),
  });

const REGISTER_BODY = {
  issuer: "https://idp.acme.test",
  domain: "acme.test",
  clientId: "client-1",
  clientSecret: "secret-1",
  redirectUri: "https://app/api/auth/sso/callback",
  authorizationEndpoint: "https://idp.acme.test/authorize",
  tokenEndpoint: "https://idp.acme.test/token",
  userInfoEndpoint: "https://idp.acme.test/userinfo",
};

describe("HTTP SSO endpoints", () => {
  it("registers (admin only), signs in, and completes the callback", async () => {
    const fx = makeHttpFixture();
    const adminSid = fx.makeSession(fx.seedUser("admin@acme.test", { role: "admin" }));

    // Non-admin cannot register.
    const nonAdminSid = fx.makeSession(fx.seedUser("user@acme.test"));
    const denied = await fx.handler(post("/sso/register", REGISTER_BODY, nonAdminSid));
    expect(denied.status).toBe(403);

    // Admin registers the connection (secret is never echoed back).
    const registered = await fx.handler(post("/sso/register", REGISTER_BODY, adminSid));
    expect(registered.status).toBe(200);
    const provider = (await registered.json()) as Record<string, unknown>;
    expect(provider["domain"]).toBe("acme.test");
    expect(provider).not.toHaveProperty("clientSecret");

    // Anonymous sign-in resolves the IdP URL by email domain.
    const signIn = await fx.handler(post("/sign-in/sso", { email: "worker@acme.test" }));
    expect(signIn.status).toBe(200);
    const { url, state } = (await signIn.json()) as { url: string; state: string };
    expect(new URL(url).origin).toBe("https://idp.acme.test");

    // Callback provisions the user and sets a session cookie.
    const callback = await withFetch(
      {
        "https://idp.acme.test/token": { access_token: "at", token_type: "bearer" },
        "https://idp.acme.test/userinfo": {
          sub: "idp-1",
          email: "worker@acme.test",
          email_verified: true,
          name: "Worker",
        },
      },
      () => fx.handler(post("/sso/callback", { state, code: "auth-code" })),
    );
    expect(callback.status).toBe(200);
    expect(callback.headers.get("set-cookie")).toContain("conduit_session=");
    expect(((await callback.json()) as { user: { email: string } }).user.email).toBe(
      "worker@acme.test",
    );
  });

  it("returns 404 when SSO is not configured", async () => {
    const fx = makeHttpFixture();
    const res = await fx.handlerWithoutSSO(post("/sign-in/sso", { email: "a@b.test" }));
    expect(res.status).toBe(404);
  });
});
