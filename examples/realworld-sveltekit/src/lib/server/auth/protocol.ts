import * as Auth from "effect-auth";
import { Effect, Layer } from "effect";
import { eq } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { db, schema } from "../db/client.js";
import { sessionStore, userStore } from "./adapters.js";
import { sessionConfig } from "./runtime.js";

/**
 * Mounts the effect-auth HTTP protocol (`Auth.Http`) at `/api/auth`, backed by
 * the same SQLite database as the rest of the app.
 *
 * This is the protocol vertical slice: instead of hand-writing an auth runtime,
 * cookie helpers, session-resolution middleware and per-route handlers (see the
 * sibling `runtime.ts` / `cookies.ts` / `../api/auth.ts`), a single mounted
 * handler serves `POST /api/auth/sign-up|sign-in|sign-out` and
 * `GET /api/auth/session` with cookie handling built in.
 */

/** Email/password store backed by the existing `users` table. */
const emailPasswordStore: Auth.EmailPasswordStore = {
  getUserByEmail: (email) =>
    Effect.sync(() => {
      const row = db.select().from(schema.users).where(eq(schema.users.email, email)).get();
      return row
        ? ({
            id: row.id,
            attributes: {
              email: row.email,
              username: row.username,
              bio: row.bio,
              image: row.image,
            },
          } satisfies Auth.User)
        : null;
    }),
  createUser: (input) =>
    Effect.try({
      try: () => {
        const id = randomUUID();
        const attrUsername =
          typeof input.attributes?.username === "string" ? input.attributes.username : undefined;
        const username = attrUsername ?? input.name ?? input.email.split("@")[0];
        db.insert(schema.users)
          .values({ id, email: input.email, username, passwordHash: "" })
          .run();
        return { id, attributes: { email: input.email, username } } satisfies Auth.User;
      },
      catch: (cause) => new Auth.AuthError({ message: `Failed to create user: ${String(cause)}` }),
    }),
  getPasswordHash: (userId) =>
    Effect.sync(() => {
      const row = db
        .select({ passwordHash: schema.users.passwordHash })
        .from(schema.users)
        .where(eq(schema.users.id, userId))
        .get();
      return row?.passwordHash ?? null;
    }),
  setPasswordHash: (userId, hash) =>
    Effect.sync(() => {
      db.update(schema.users).set({ passwordHash: hash }).where(eq(schema.users.id, userId)).run();
    }),
};

/** Email verification is disabled here but the service + store must be present. */
const noopVerificationStore: Auth.EmailVerificationStore = {
  create: (verification) => Effect.succeed(verification),
  get: () => Effect.succeed(null),
  delete: () => Effect.void,
  deleteByUserId: () => Effect.void,
};

/** Stores consumed internally by SessionManager (not part of the auth surface). */
const InternalStores = Layer.mergeAll(
  Layer.succeed(Auth.SessionStore)(sessionStore),
  Layer.succeed(Auth.UserStore)(userStore),
);

/** Stores/services that are part of the auth service surface. */
const AuthStores = Layer.mergeAll(
  Layer.succeed(Auth.EmailPasswordStore)(emailPasswordStore),
  Layer.succeed(Auth.EmailVerificationStore)(noopVerificationStore),
  Layer.succeedContext(Auth.PasswordHasherLive),
);

const ServicesLayer: Layer.Layer<Auth.Http.AuthServices> = Layer.mergeAll(
  Auth.SessionManagerLayer(sessionConfig),
  Auth.AuthLifecycleServiceLayer({ requireEmailVerification: false }),
  Auth.EmailVerificationServiceLayer({ sendEmail: () => Effect.void }),
  // No-op hooks base; swap for a `composePlugins([...])` stack to install plugins.
  Auth.Hooks.Default,
).pipe(Layer.provide(InternalStores), Layer.provideMerge(AuthStores));

export const { handler: authHandler } = Auth.Http.makeAuthWebHandler({
  services: ServicesLayer,
  cookie: { name: "conduit_session", secure: process.env.NODE_ENV === "production" },
  prefix: "/api/auth",
});
