import { Context, Effect, FileSystem, Layer, Path } from "effect";
import { HttpApiBuilder } from "effect/unstable/httpapi";
import {
  Etag,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
} from "effect/unstable/http";
import { AuthApi } from "./HttpApi.js";
import * as S from "./HttpApiSchemas.js";
import { AuthLifecycleServiceTag } from "./AuthLifecycle.js";
import { Hooks } from "./Hooks.js";
import { SessionManagerTag } from "./Session.js";
import { EmailPasswordStoreTag, makeEmailPasswordService } from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import {
  PasswordResetServiceTag,
  PasswordResetStoreTag,
  PasswordResetUserStoreTag,
} from "./PasswordReset.js";
import { UserServiceStoreTag, UserServiceTag } from "./User.js";
import type * as Types from "./Types.js";

/**
 * The services the auth handlers require. Your `services` layer must provide
 * all of these (a superset is fine). They are the existing core services plus
 * the stores the orchestration services depend on, plus the `Hooks` service
 * (provide `Hooks.Default` for no-op hooks, or a `composePlugins([...])` stack).
 */
export type AuthServices =
  | AuthLifecycleServiceTag
  | SessionManagerTag
  | EmailPasswordStoreTag
  | PasswordHasherTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag
  | PasswordResetServiceTag
  | PasswordResetStoreTag
  | PasswordResetUserStoreTag
  | UserServiceTag
  | UserServiceStoreTag
  | Hooks;

/**
 * Server implementation for the auth HTTP contract.
 *
 * `makeAuthWebHandler` turns the contract + your service layer into a standard
 * Web `Request => Response` handler that any framework can mount. Handlers call
 * the existing Effect services; the session cookie and session resolution are
 * handled here so framework integrations no longer hand-roll them.
 */

// -----------------------------------------------------------------------------
// Cookie configuration
// -----------------------------------------------------------------------------

export interface CookieConfig {
  /** Cookie name. Default `conduit_session`. */
  readonly name?: string;
  /** Mark the cookie `Secure`. Default `true` (set `false` for local http). */
  readonly secure?: boolean;
  /** Cookie path. Default `/`. */
  readonly path?: string;
}

interface ResolvedCookieConfig {
  readonly name: string;
  readonly secure: boolean;
  readonly path: string;
}

const resolveCookieConfig = (config?: CookieConfig): ResolvedCookieConfig => ({
  name: config?.name ?? "conduit_session",
  secure: config?.secure ?? true,
  path: config?.path ?? "/",
});

const sessionCookieOptions = (cfg: ResolvedCookieConfig, expiresAt: Date) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    expires: expiresAt,
  }) as const;

const clearCookieOptions = (cfg: ResolvedCookieConfig) =>
  ({
    httpOnly: true,
    sameSite: "lax",
    secure: cfg.secure,
    path: cfg.path,
    maxAge: 0,
  }) as const;

// -----------------------------------------------------------------------------
// Session resolution (Authorization header, then cookie)
// -----------------------------------------------------------------------------

const sessionIdFromRequest = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): string | undefined => {
  const auth = request.headers["authorization"];
  if (auth) {
    const [scheme, value] = auth.split(" ");
    if ((scheme === "Token" || scheme === "Bearer") && value) return value;
  }
  return request.cookies[cfg.name];
};

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

const signUpInput = (payload: S.SignUpPayload) => ({
  email: payload.email,
  password: payload.password,
  ...(payload.name !== undefined && { name: payload.name }),
  ...(payload.attributes !== undefined && { attributes: payload.attributes }),
});

/** Layer implementing the `auth` group handlers. */
export const authGroupLayer = (config?: CookieConfig) => {
  const cfg = resolveCookieConfig(config);

  return HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
    handlers
      .handle("signUp", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle.signUp(signUpInput(payload)).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.Conflict({ message: e.message })),
              EmailNotVerifiedError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              EmailVerificationError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signIn", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle
            .signIn({ email: payload.email, password: payload.password })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.Unauthorized({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                EmailVerificationError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.Forbidden({ message: e.message })),
              }),
            );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("signOut", ({ request }) =>
        Effect.gen(function* () {
          const sessionId = sessionIdFromRequest(request, cfg);
          if (sessionId !== undefined) {
            const sessionManager = yield* SessionManagerTag;
            yield* Effect.ignore(sessionManager.invalidateSession(sessionId));
          }
          return yield* HttpServerResponse.setCookie(
            HttpServerResponse.empty({ status: 204 }),
            cfg.name,
            "",
            clearCookieOptions(cfg),
          ).pipe(Effect.orDie);
        }),
      )
      .handle("getSession", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          return S.encodeSessionWithUser(resolved);
        }),
      )
      .handle("sendVerificationEmail", ({ payload }) =>
        Effect.gen(function* () {
          const store = yield* EmailPasswordStoreTag;
          const verification = yield* EmailVerificationServiceTag;
          const email = payload.email.trim().toLowerCase();

          const user = yield* store
            .getUserByEmail(email)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));

          // Anti-enumeration: succeed uniformly whether or not the user exists
          // (or is already verified).
          if (user !== null && !user.emailVerified) {
            yield* verification.resendVerification(user.id, email).pipe(
              Effect.catchTags({
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
                EmailVerificationError: (e) =>
                  Effect.fail(new S.InternalServerError({ message: e.message })),
                RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              }),
            );
          }

          return { status: true };
        }),
      )
      .handle("verifyEmail", ({ payload }) =>
        Effect.gen(function* () {
          const lifecycle = yield* AuthLifecycleServiceTag;
          const result = yield* lifecycle.verifyEmail({ token: payload.token }).pipe(
            Effect.catchTags({
              EmailVerificationError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              UserNotFoundError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          const body: S.AuthSuccess = {
            user: S.encodeUser(result.user),
            needsEmailVerification: result.needsEmailVerification,
          };
          return yield* withSessionCookie(body, result.session, cfg);
        }),
      )
      .handle("requestPasswordReset", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetServiceTag;
          yield* passwordReset.requestPasswordReset(payload.email).pipe(
            Effect.catchTags({
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              PasswordResetError: (e) =>
                Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("resetPassword", ({ payload }) =>
        Effect.gen(function* () {
          const passwordReset = yield* PasswordResetServiceTag;
          yield* passwordReset.resetPassword(payload.token, payload.newPassword).pipe(
            Effect.catchTags({
              PasswordResetError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
              AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              RateLimitError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
            }),
          );
          return { status: true };
        }),
      )
      .handle("changePassword", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const emailPassword = yield* makeEmailPasswordService();
          yield* emailPassword
            .changePassword({
              userId: resolved.user.id,
              currentPassword: payload.currentPassword,
              newPassword: payload.newPassword,
              ...(payload.revokeOtherSessions !== undefined && {
                revokeOtherSessions: payload.revokeOtherSessions,
              }),
              currentSessionId: resolved.session.id,
            })
            .pipe(
              Effect.catchTags({
                InvalidCredentialsError: (e) =>
                  Effect.fail(new S.BadRequest({ message: e.message })),
                AuthError: (e) => Effect.fail(new S.BadRequest({ message: e.message })),
                HashingError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
        }),
      )
      .handle("updateUser", ({ payload, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const userService = yield* UserServiceTag;
          const updated = yield* userService
            .updateUser(resolved.user.id, {
              ...(payload.name !== undefined && { name: payload.name }),
              ...(payload.image !== undefined && { image: payload.image }),
            })
            .pipe(
              Effect.catchTags({
                UserNotFoundError: () =>
                  Effect.fail(new S.Unauthorized({ message: "Not authenticated" })),
                AuthError: (e) => Effect.fail(new S.InternalServerError({ message: e.message })),
              }),
            );
          return S.encodeUser(updated);
        }),
      )
      .handle("listSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;
          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
          return sessions.map(S.encodeSession);
        }),
      )
      .handle("revokeSession", ({ params, request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;

          const sessions = yield* sessionManager
            .listSessions(resolved.user.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));

          // Only the owner may revoke a session, and only their own sessions.
          const target = sessions.find((session) => session.id === params.sessionId);
          if (target === undefined) {
            return yield* new S.BadRequest({ message: "Session not found" });
          }

          yield* sessionManager
            .invalidateSession(target.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
        }),
      )
      .handle("revokeOtherSessions", ({ request }) =>
        Effect.gen(function* () {
          const resolved = yield* requireSession(request, cfg);
          const sessionManager = yield* SessionManagerTag;
          yield* sessionManager
            .revokeOtherSessions(resolved.user.id, resolved.session.id)
            .pipe(Effect.mapError((e) => new S.InternalServerError({ message: e.message })));
        }),
      ),
  );
};

/** Resolve and validate the request's session or fail with 401. */
const requireSession = (
  request: HttpServerRequest.HttpServerRequest,
  cfg: ResolvedCookieConfig,
): Effect.Effect<Types.SessionWithUser, S.Unauthorized, SessionManagerTag | Hooks> =>
  Effect.gen(function* () {
    const sessionId = sessionIdFromRequest(request, cfg);
    if (sessionId === undefined) {
      return yield* new S.Unauthorized({ message: "Not authenticated" });
    }
    const sessionManager = yield* SessionManagerTag;
    return yield* sessionManager
      .validateSession(sessionId)
      .pipe(Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })));
  });

/** Attach the session cookie to a JSON `AuthSuccess` response when a session is present. */
const withSessionCookie = (
  body: S.AuthSuccess,
  session: Types.Session | undefined,
  cfg: ResolvedCookieConfig,
) =>
  Effect.gen(function* () {
    const response = yield* HttpServerResponse.json(body);
    if (session === undefined) return response;
    return yield* HttpServerResponse.setCookie(
      response,
      cfg.name,
      session.id,
      sessionCookieOptions(cfg, session.expiresAt),
    );
  }).pipe(Effect.orDie);

// -----------------------------------------------------------------------------
// Web handler
// -----------------------------------------------------------------------------

/**
 * Runtime-agnostic platform services required by the HttpApi router. We never
 * serve files, so a no-op `FileSystem` suffices; it is both provided to
 * `HttpPlatform` and exposed in the output (the router requires `FileSystem`
 * directly too).
 */
const PlatformLayer = Layer.mergeAll(Etag.layer, Path.layer, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({})),
);

export interface AuthWebHandlerOptions {
  /** Your service layer (SessionManager, AuthLifecycle, stores, ...). */
  readonly services: Layer.Layer<AuthServices>;
  /** Cookie configuration. */
  readonly cookie?: CookieConfig;
  /**
   * Mount path prefix to strip before routing, e.g. `"/api/auth"`. When set, a
   * request to `/api/auth/sign-in` is routed to the `/sign-in` endpoint.
   */
  readonly prefix?: string;
  /**
   * Origins (e.g. `"https://app.example.com"`) allowed to make state-changing
   * (non-GET/HEAD/OPTIONS) requests, in addition to the request's own origin.
   *
   * Browsers attach an `Origin` header to cross-origin (and most same-origin)
   * mutating requests; when the header is present and matches neither the
   * request URL's origin nor this list, the request is rejected with `403`
   * before it reaches a handler (CSRF protection). Requests without an
   * `Origin` header (curl, server-to-server) are allowed through.
   */
  readonly trustedOrigins?: ReadonlyArray<string>;
}

/** CSRF check shared by the web handler. Returns `true` when allowed. */
const isTrustedRequest = (request: Request, trustedOrigins: ReadonlyArray<string>): boolean => {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;

  const origin = request.headers.get("origin");
  // No Origin header: non-browser client (curl, server-to-server) - allow.
  // An opaque "null" origin (sandboxed iframe, some redirects) is NOT trusted
  // unless explicitly listed.
  if (origin === null) return true;

  const requestOrigin = new URL(request.url).origin;
  return origin === requestOrigin || trustedOrigins.includes(origin);
};

/**
 * Build a standard Web `Request => Response` handler for the auth API.
 *
 * Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
 * `dispose` releases the handler's scope.
 */
export const makeAuthWebHandler = (
  options: AuthWebHandlerOptions,
): {
  readonly handler: (request: Request, context?: Context.Context<never>) => Promise<Response>;
  readonly dispose: () => Promise<void>;
} => {
  const apiLayer = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(authGroupLayer(options.cookie)),
    Layer.provide(PlatformLayer),
  );
  // The handlers' service requirements are tracked as phantom
  // `Request<"Requires", RIn>` types; providing `services` to the layer's OUTPUT
  // (provideMerge) both satisfies them at runtime and zeroes the web handler's
  // leftover context (HR), yielding a plain `(request) => Promise<Response>`.
  const appLayer = apiLayer.pipe(Layer.provideMerge(options.services));
  const web = HttpRouter.toWebHandler(appLayer);

  const trustedOrigins = options.trustedOrigins ?? [];
  const prefix = options.prefix;

  const handler = (request: Request, context?: Context.Context<never>): Promise<Response> => {
    if (!isTrustedRequest(request, trustedOrigins)) {
      return Promise.resolve(Response.json({ message: "Origin not allowed" }, { status: 403 }));
    }
    if (prefix === undefined || prefix === "") {
      return web.handler(request, context);
    }
    const url = new URL(request.url);
    if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) {
      url.pathname = url.pathname.slice(prefix.length) || "/";
      return web.handler(new Request(url, request), context);
    }
    return web.handler(request, context);
  };
  return { handler, dispose: web.dispose };
};
