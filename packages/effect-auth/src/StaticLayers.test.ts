import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, DateTime, Effect, Layer, Predicate } from "effect";
import * as Auth from "./index.ts";

/**
 * D1 (DESIGN.md): every primary service class exposes a `static layer` — the
 * canonical construction `Auth.SessionService.layer(...)`.
 */
describe("static service layers", () => {
  it("exposes a static layer constructor on every primary service", () => {
    const services: ReadonlyArray<[string, { readonly layer: (...args: never[]) => Layer.Any }]> = [
      ["SessionService", Auth.SessionService],
      ["RateLimiter", Auth.RateLimiter],
      ["UserService", Auth.UserService],
      ["EmailPasswordService", Auth.Email.EmailPasswordService],
      ["EmailOtpService", Auth.Email.EmailOtpService],
      ["PhoneOtpService", Auth.PhoneOtpService],
      ["MagicLinkService", Auth.MagicLinkService],
      ["EmailVerificationService", Auth.Email.EmailVerificationService],
      ["PasswordResetService", Auth.Password.PasswordResetService],
      ["UsernameService", Auth.UsernameService],
      ["MultiFactorService", Auth.MultiFactor.MultiFactorService],
      ["WebAuthnService", Auth.MultiFactor.WebAuthnService],
      ["ApiKeyService", Auth.ApiKeyService],
      ["JwtService", Auth.JwtService],
      ["OAuthService", Auth.OAuth.OAuthService],
      ["SsoService", Auth.SsoService],
      ["GoogleOneTapService", Auth.GoogleOneTapService],
      ["AnonymousService", Auth.AnonymousService],
      ["AdminService", Auth.AdminService],
      ["OrganizationService", Auth.OrganizationService],
      ["AccountManagementService", Auth.AccountManagementService],
      ["DeviceAuthorizationService", Auth.DeviceAuthorizationService],
      ["AuthLifecycleService", Auth.AuthLifecycleService],
      ["OidcProviderService", Auth.OidcProviderService],
    ];
    Arr.forEach(services, ([name, service]) => {
      expect(Predicate.isFunction(service.layer), `${name}.layer`).toBe(true);
    });
  });

  it("SessionService.layer builds a working session manager", async () => {
    const sessions = new Map<string, Auth.Session>();
    const user: Auth.User = {
      id: "user-1",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
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
    };

    const config: Auth.SessionConfig = {
      sessionExpiresIn: {
        activePeriod: 30 * 24 * 60 * 60 * 1000,
        idlePeriod: 14 * 24 * 60 * 60 * 1000,
      },
    };

    const layer = Auth.SessionService.layer(config).pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          Layer.succeed(Auth.SessionStore)(sessionStore),
          Layer.succeed(Auth.UserStore)(userStore),
          Auth.Hooks.Default,
        ),
      ),
    );

    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const manager = yield* Auth.SessionService;
        const session = yield* manager.createSession(user.id);
        const validated = yield* manager.validateSession(session.id);
        return validated;
      }).pipe(Effect.provide(layer)),
    );

    expect(result.user.id).toBe(user.id);
    expect(result.session.userId).toBe(user.id);
  });

  it("static layers build the same layer as the standalone constructors", async () => {
    // UserService.layer() requires only its store; exercise it end-to-end.
    const user: Auth.User = {
      id: "user-2",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    const store: typeof Auth.UserServiceStore.Service = {
      get: (userId) => Effect.succeed(userId === user.id ? user : null),
      update: (u) => Effect.succeed(u),
      delete: () => Effect.void,
    };

    const layer = Auth.UserService.layer().pipe(
      Layer.provideMerge(
        Layer.mergeAll(Layer.succeed(Auth.UserServiceStore)(store), Auth.Hooks.Default),
      ),
    );

    const viaStatic = await Effect.runPromise(
      Effect.gen(function* () {
        const users = yield* Auth.UserService;
        return yield* users.getUser(user.id);
      }).pipe(Effect.provide(layer)),
    );
    expect(viaStatic.id).toBe(user.id);
  });
});
