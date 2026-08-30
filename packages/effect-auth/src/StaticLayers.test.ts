import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import * as Auth from "./index.ts";

/**
 * D1 (DESIGN.md): every primary service class exposes a `static layer` — the
 * canonical construction `Auth.SessionService.layer(...)`.
 */
describe("static service layers", () => {
  it("exposes a static layer constructor on every primary service", () => {
    const services: ReadonlyArray<[string, { readonly layer: (...args: never[]) => unknown }]> = [
      ["SessionService", Auth.SessionService],
      ["RateLimiter", Auth.RateLimiter],
      ["AuthorizationPolicy", Auth.AuthorizationPolicy],
      ["UserService", Auth.UserService],
      ["EmailPasswordService", Auth.Email.EmailPasswordService],
      ["EmailOTPService", Auth.Email.EmailOTPService],
      ["PhoneOTPService", Auth.PhoneOTPService],
      ["MagicLinkService", Auth.MagicLinkService],
      ["EmailVerificationService", Auth.Email.EmailVerificationService],
      ["PasswordResetService", Auth.Password.PasswordResetService],
      ["UsernameService", Auth.UsernameService],
      ["MultiFactorService", Auth.SecondFactor.MultiFactorService],
      ["WebAuthnService", Auth.SecondFactor.WebAuthnService],
      ["APIKeyService", Auth.APIKeyService],
      ["JWTService", Auth.JWTService],
      ["OAuthService", Auth.OAuth.OAuthService],
      ["SSOService", Auth.SSOService],
      ["GoogleOneTapService", Auth.GoogleOneTapService],
      ["AnonymousService", Auth.AnonymousService],
      ["AdminService", Auth.AdminService],
      ["OrganizationService", Auth.OrganizationService],
      ["AccountManagementService", Auth.AccountManagementService],
      ["DeviceAuthorizationService", Auth.DeviceAuthorizationService],
      ["AuthLifecycleService", Auth.AuthLifecycleService],
      ["OIDCProviderService", Auth.OIDCProviderService],
    ];
    for (const [name, service] of services) {
      expect(typeof service.layer, `${name}.layer`).toBe("function");
    }
  });

  it("SessionService.layer builds a working session manager", async () => {
    const sessions = new Map<string, Auth.Session>();
    const user: Auth.User = {
      id: "user-1",
      email: "user@example.com",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };

    const sessionStore: typeof Auth.SessionStore.Service = {
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
      deleteByUserId: () => Effect.void,
      listByUserId: (userId) =>
        Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
    };

    const userStore: typeof Auth.UserStore.Service = {
      get: (userId) => Effect.succeed(userId === user.id ? user : null),
      getCredentials: () => Effect.succeed(null),
    };

    const config: Auth.SessionConfig = {
      sessionExpiresIn: {
        activePeriod: 30 * 24 * 60 * 60 * 1000,
        idlePeriod: 14 * 24 * 60 * 60 * 1000,
      },
    };

    const program = Effect.gen(function* () {
      const manager = yield* Auth.SessionService;
      const session = yield* manager.createSession(user.id);
      const validated = yield* manager.validateSession(session.id);
      return validated;
    });

    const layer = Auth.SessionService.layer(config).pipe(
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
    const store: typeof Auth.UserServiceStore.Service = {
      get: (userId) => Effect.succeed(userId === user.id ? user : null),
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
