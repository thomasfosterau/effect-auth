import * as Auth from "effect-auth";
import { Layer } from "effect";
import { sessionStore, userStore } from "./adapters";
import { sessionConfig } from "./runtime";

/**
 * The effect-auth HTTP handler, mounted at /api/auth (see routes/api.auth.$.tsx).
 *
 * This app keeps its own email/password routes (RealWorld's /api/users), so
 * only the session endpoints are backed by real services here — enough for
 * `@effect-auth/client`'s session store (`GET /session`, `POST /sign-out`).
 * The remaining `AuthServices` are unused no-op stubs.
 */
const stores = Layer.mergeAll(
  Layer.succeed(Auth.SessionStore)(sessionStore),
  Layer.succeed(Auth.UserStore)(userStore),
);

const services: Layer.Layer<Auth.Http.AuthServices> = Layer.mergeAll(
  Auth.SessionManager.layer(sessionConfig).pipe(Layer.provide(stores)),
  Auth.Hooks.Default,
  Layer.succeed(Auth.AuthLifecycleService)(undefined as never),
  Layer.succeed(Auth.EmailPasswordStore)(undefined as never),
  Layer.succeed(Auth.PasswordHasher)(undefined as never),
  Layer.succeed(Auth.EmailVerificationService)(undefined as never),
  Layer.succeed(Auth.EmailVerificationStore)(undefined as never),
  Layer.succeed(Auth.PasswordResetService)(undefined as never),
  Layer.succeed(Auth.PasswordResetStore)(undefined as never),
  Layer.succeed(Auth.PasswordResetUserStore)(undefined as never),
  Layer.succeed(Auth.UserService)(undefined as never),
  Layer.succeed(Auth.UserServiceStore)(undefined as never),
);

export const authWebHandler = Auth.Http.makeAuthWebHandler({
  services,
  prefix: "/api/auth",
  cookie: { secure: process.env.NODE_ENV === "production" },
});
