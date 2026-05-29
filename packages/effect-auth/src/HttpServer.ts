import { Effect, FileSystem, Layer, Path } from "effect";
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
import { SessionManagerTag } from "./Session.js";
import { EmailPasswordStoreTag } from "./EmailPassword.js";
import { PasswordHasherTag } from "./Password.js";
import { EmailVerificationServiceTag, EmailVerificationStoreTag } from "./EmailVerification.js";
import type * as Types from "./Types.js";

/**
 * The services the auth handlers require. Your `services` layer must provide
 * all of these (a superset is fine). They are the existing core services plus
 * the stores the orchestration services depend on.
 */
export type AuthServices =
  | AuthLifecycleServiceTag
  | SessionManagerTag
  | EmailPasswordStoreTag
  | PasswordHasherTag
  | EmailVerificationServiceTag
  | EmailVerificationStoreTag;

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
          const sessionId = sessionIdFromRequest(request, cfg);
          if (sessionId === undefined) {
            return yield* new S.Unauthorized({ message: "Not authenticated" });
          }
          const sessionManager = yield* SessionManagerTag;
          const resolved = yield* sessionManager
            .validateSession(sessionId)
            .pipe(
              Effect.mapError(() => new S.Unauthorized({ message: "Invalid or expired session" })),
            );
          return S.encodeSessionWithUser(resolved);
        }),
      ),
  );
};

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
}

/**
 * Build a standard Web `Request => Response` handler for the auth API.
 *
 * Mount the returned `handler` in any framework (SvelteKit/Next/Hono/...).
 * `dispose` releases the handler's scope.
 */
export const makeAuthWebHandler = (options: AuthWebHandlerOptions) => {
  const apiLayer = HttpApiBuilder.layer(AuthApi).pipe(
    Layer.provide(authGroupLayer(options.cookie)),
    Layer.provide(PlatformLayer),
  );
  // The handlers' service requirements are tracked as phantom
  // `Request<"Requires", RIn>` types; providing `services` to the layer's OUTPUT
  // (provideMerge) both satisfies them at runtime and zeroes the web handler's
  // leftover context (HR), yielding a plain `(request) => Promise<Response>`.
  const appLayer = apiLayer.pipe(Layer.provideMerge(options.services));
  return HttpRouter.toWebHandler(appLayer);
};
