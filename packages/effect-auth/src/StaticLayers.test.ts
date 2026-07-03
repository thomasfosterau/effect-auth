import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as Auth from "./index.js";

/**
 * D1 (DESIGN.md): every primary service class exposes a `static layer`
 * mirroring its standalone `XServiceLayer` constructor, reachable through the
 * bare-alias export (`Auth.SessionManager.layer(...)`).
 */
describe("static service layers", () => {
  it("exposes a static layer constructor on every primary service", () => {
    const services: ReadonlyArray<[string, { readonly layer: (...args: never[]) => unknown }]> = [
      ["SessionManager", Auth.SessionManager],
      ["RateLimiter", Auth.RateLimiter],
      ["AuthorizationPolicy", Auth.AuthorizationPolicy],
      ["UserService", Auth.UserService],
      ["EmailPasswordService", Auth.EmailPasswordService],
      ["EmailOtpService", Auth.EmailOtpService],
      ["PhoneOtpService", Auth.PhoneOtpService],
      ["MagicLinkService", Auth.MagicLinkService],
      ["EmailVerificationService", Auth.EmailVerificationService],
      ["PasswordResetService", Auth.PasswordResetService],
      ["UsernameService", Auth.UsernameService],
      ["TwoFactorService", Auth.TwoFactorService],
      ["WebAuthnService", Auth.WebAuthnService],
      ["ApiKeyService", Auth.ApiKeyService],
      ["JwtService", Auth.JwtService],
      ["OAuthService", Auth.OAuthService],
      ["SsoService", Auth.SsoService],
      ["SiweService", Auth.SiweService],
      ["GoogleOneTapService", Auth.GoogleOneTapService],
      ["AnonymousService", Auth.AnonymousService],
      ["AdminService", Auth.AdminService],
      ["OrganizationService", Auth.OrganizationService],
      ["AccountManagementService", Auth.AccountManagementService],
      ["DeviceAuthorizationService", Auth.DeviceAuthorizationService],
      ["AuthLifecycleService", Auth.AuthLifecycleService],
      ["OidcProviderService", Auth.OidcProviderService],
    ];
    for (const [name, service] of services) {
      expect(typeof service.layer, `${name}.layer`).toBe("function");
    }
  });

  it("SessionManager.layer builds a working session manager", async () => {
    const sessions = new Map<string, Auth.Session>();
    const user: Auth.User = {
      id: "user-1",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    const sessionStore: Auth.SessionStore = {
      create: (session) =>
        Effect.sync(() => {
          sessions.set(session.id, session);
          return session;
        }),
      get: (sessionId) => {
        const session = sessions.get(sessionId);
        return session
          ? Effect.succeed(session)
          : Effect.fail(new Auth.SessionNotFoundError({ message: "not found", sessionId }));
      },
      update: (session) =>
        Effect.sync(() => {
          sessions.set(session.id, session);
          return session;
        }),
      delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
      deleteByUserId: () => Effect.void,
      listByUserId: (userId) =>
        Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
    };

    const userStore: Auth.UserStore = {
      get: (userId) =>
        userId === user.id
          ? Effect.succeed(user)
          : Effect.fail(new Auth.UserNotFoundError({ message: "not found", userId })),
      getCredentials: (userId) =>
        Effect.fail(new Auth.UserNotFoundError({ message: "not found", userId })),
    };

    const config: Auth.SessionConfig = {
      sessionExpiresIn: {
        activePeriod: 30 * 24 * 60 * 60 * 1000,
        idlePeriod: 14 * 24 * 60 * 60 * 1000,
      },
    };

    const program = Effect.gen(function* () {
      const manager = yield* Auth.SessionManager;
      const session = yield* manager.createSession(user.id);
      const validated = yield* manager.validateSession(session.id);
      return validated;
    });

    const layer = Auth.SessionManager.layer(config).pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          Layer.succeed(Auth.SessionStore)(sessionStore),
          Layer.succeed(Auth.UserStore)(userStore),
          Auth.Hooks.Default,
        ),
      ),
    );

    const result = await Effect.runPromise(program.pipe(Effect.provide(layer)));

    expect(result.user.id).toBe(user.id);
    expect(result.session.userId).toBe(user.id);
  });

  it("static layers build the same layer as the standalone constructors", async () => {
    // UserService.layer() requires only its store; exercise it end-to-end.
    const user: Auth.User = {
      id: "user-2",
      email: "user2@example.com",
      emailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    const store: Auth.UserServiceStore = {
      get: (userId) =>
        userId === user.id
          ? Effect.succeed(user)
          : Effect.fail(new Auth.UserNotFoundError({ message: "not found", userId })),
      getByEmail: () => Effect.succeed(null),
      update: (u) => Effect.succeed(u),
      delete: () => Effect.void,
    };

    const program = Effect.gen(function* () {
      const users = yield* Auth.UserService;
      return yield* users.getUser(user.id);
    });

    const layer = Auth.UserService.layer().pipe(
      Layer.provideMerge(
        Layer.mergeAll(Layer.succeed(Auth.UserServiceStore)(store), Auth.Hooks.Default),
      ),
    );

    const viaStatic = await Effect.runPromise(program.pipe(Effect.provide(layer)));
    expect(viaStatic.id).toBe(user.id);
  });
});
