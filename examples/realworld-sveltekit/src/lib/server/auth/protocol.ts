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

const rowToUser = (row: typeof schema.users.$inferSelect): Auth.User => ({
  id: row.id,
  email: row.email,
  emailVerified: false,
  ...(row.image !== null && { image: row.image }),
  createdAt: row.createdAt,
  updatedAt: row.createdAt,
  attributes: {
    username: row.username,
    bio: row.bio,
    image: row.image,
  },
});

/** Email/password store backed by the existing `users` table. */
const emailPasswordStore: Auth.EmailPasswordStore = {
  getUserByEmail: (email) =>
    Effect.sync(() => {
      const row = db.select().from(schema.users).where(eq(schema.users.email, email)).get();
      return row ? rowToUser(row) : null;
    }),
  createUser: (input) =>
    Effect.try({
      try: () => {
        const id = randomUUID();
        const attrUsername =
          typeof input.attributes?.username === "string" ? input.attributes.username : undefined;
        const username = attrUsername ?? input.name ?? input.email.split("@")[0];
        db.insert(schema.users)
          .values({
            id,
            email: input.email,
            username,
            image: input.image ?? null,
            passwordHash: "",
          })
          .run();
        const now = new Date();
        return {
          id,
          email: input.email,
          emailVerified: false,
          ...(input.name !== undefined && { name: input.name }),
          ...(input.image !== undefined && { image: input.image }),
          createdAt: now,
          updatedAt: now,
          attributes: { username },
        } satisfies Auth.User;
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

/** Password-reset tokens kept in memory; the reset flow is unused by the app. */
const passwordResetTokens = new Map<string, Auth.PasswordResetToken>();

const passwordResetStore: Auth.PasswordResetStore = {
  create: (token) =>
    Effect.sync(() => {
      passwordResetTokens.set(token.token, token);
      return token;
    }),
  get: (token) => Effect.sync(() => passwordResetTokens.get(token) ?? null),
  delete: (token) =>
    Effect.sync(() => {
      passwordResetTokens.delete(token);
    }),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [key, token] of passwordResetTokens) {
        if (token.userId === userId) passwordResetTokens.delete(key);
      }
    }),
};

const passwordResetUserStore: Auth.PasswordResetUserStore = {
  getUserByEmail: (email) => emailPasswordStore.getUserByEmail(email),
  setPasswordHash: (userId, hash) => emailPasswordStore.setPasswordHash(userId, hash),
};

/** User profile store backed by the existing `users` table. */
const userServiceStore: Auth.UserServiceStore = {
  get: (userId) =>
    Effect.gen(function* () {
      const row = db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
      if (!row) {
        return yield* Effect.fail(
          new Auth.UserNotFoundError({ message: "User not found", userId }),
        );
      }
      return rowToUser(row);
    }),
  getByEmail: (email) => emailPasswordStore.getUserByEmail(email),
  update: (user) =>
    Effect.sync(() => {
      db.update(schema.users)
        .set({
          email: user.email,
          image: user.image ?? null,
          ...(typeof user.attributes["username"] === "string" && {
            username: user.attributes["username"],
          }),
          ...(typeof user.attributes["bio"] === "string" && {
            bio: user.attributes["bio"],
          }),
        })
        .where(eq(schema.users.id, user.id))
        .run();
      return user;
    }),
  delete: (userId) =>
    Effect.sync(() => {
      db.delete(schema.users).where(eq(schema.users.id, userId)).run();
    }),
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
  Layer.succeed(Auth.PasswordResetStoreTag)(passwordResetStore),
  Layer.succeed(Auth.PasswordResetUserStoreTag)(passwordResetUserStore),
  Layer.succeed(Auth.UserServiceStoreTag)(userServiceStore),
  Layer.succeedContext(Auth.PasswordHasherLive),
);

const ServicesLayer: Layer.Layer<Auth.Http.AuthServices> = Layer.mergeAll(
  Auth.SessionManagerLayer(sessionConfig),
  Auth.AuthLifecycleServiceLayer({ requireEmailVerification: false }),
  Auth.EmailVerificationServiceLayer({ sendEmail: () => Effect.void }),
  Auth.PasswordResetServiceLayer({ sendResetPassword: () => Effect.void }),
  Auth.UserServiceLayer(),
  // No-op hooks base; swap for a `composePlugins([...])` stack to install plugins.
  Auth.Hooks.Default,
).pipe(Layer.provide(InternalStores), Layer.provideMerge(AuthStores));

export const { handler: authHandler } = Auth.Http.makeAuthWebHandler({
  services: ServicesLayer,
  cookie: { name: "conduit_session", secure: process.env.NODE_ENV === "production" },
  prefix: "/api/auth",
});
