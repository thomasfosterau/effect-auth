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
  Layer.succeed(Auth.SessionStoreTag)(sessionStore),
  Layer.succeed(Auth.UserStoreTag)(userStore),
);

const services: Layer.Layer<Auth.Http.AuthServices> = Layer.mergeAll(
  Auth.SessionManagerLayer(sessionConfig).pipe(Layer.provide(stores)),
  Auth.Hooks.Default,
  Layer.succeed(Auth.AuthLifecycleServiceTag)(undefined as never),
  Layer.succeed(Auth.EmailPasswordStoreTag)(undefined as never),
  Layer.succeed(Auth.PasswordHasherTag)(undefined as never),
  Layer.succeed(Auth.EmailVerificationServiceTag)(undefined as never),
  Layer.succeed(Auth.EmailVerificationStoreTag)(undefined as never),
  Layer.succeed(Auth.PasswordResetServiceTag)(undefined as never),
  Layer.succeed(Auth.PasswordResetStoreTag)(undefined as never),
  Layer.succeed(Auth.PasswordResetUserStoreTag)(undefined as never),
  Layer.succeed(Auth.UserServiceTag)(undefined as never),
  Layer.succeed(Auth.UserServiceStoreTag)(undefined as never),
);

export const authWebHandler = Auth.Http.makeAuthWebHandler({
  services,
  prefix: "/api/auth",
  cookie: { secure: process.env.NODE_ENV === "production" },
});
