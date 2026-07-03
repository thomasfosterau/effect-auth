import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { composePlugins, Hooks } from "../Hooks.js";
import { makeLastLoginMethodPlugin } from "./LastLoginMethodPlugin.js";
import { makeEmailPasswordService } from "../EmailPassword.js";
import { EmailPasswordStoreTag, type EmailPasswordStore } from "../EmailPassword.js";
import { PasswordHasherTag, makeScryptHasher } from "../Password.js";
import {
  SessionManagerLayer,
  SessionManagerTag,
  SessionStoreTag,
  UserStoreTag,
  type SessionStore,
  type UserStore,
} from "../Session.js";
import type * as Types from "../Types.js";

const hasher = makeScryptHasher({ cost: 16384 });

const makeFixture = () => {
  const usersById = new Map<string, Types.User>();
  const userIdByEmail = new Map<string, string>();
  const passwordHashes = new Map<string, string>();
  const sessions = new Map<string, Types.Session>();
  let userSeq = 0;

  const emailPasswordStore: EmailPasswordStore = {
    getUserByEmail: (email) =>
      Effect.sync(() => {
        const id = userIdByEmail.get(email);
        return id === undefined ? null : (usersById.get(id) ?? null);
      }),
    createUser: (input) =>
      Effect.sync(() => {
        const now = new Date();
        const user: Types.User = {
          id: `user-${++userSeq}`,
          email: input.email,
          emailVerified: false,
          createdAt: now,
          updatedAt: now,
          attributes: {},
        };
        usersById.set(user.id, user);
        userIdByEmail.set(user.email, user.id);
        return user;
      }),
    getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
  };
  const sessionStore: SessionStore = {
    create: (s) => Effect.sync(() => (sessions.set(s.id, s), s)),
    get: (sessionId) => Effect.sync(() => sessions.get(sessionId) ?? null),
    update: (s) => Effect.sync(() => (sessions.set(s.id, s), s)),
    delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
    deleteByUserId: () => Effect.void,
    listByUserId: () => Effect.succeed([]),
  };
  const userStore: UserStore = {
    get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
    getCredentials: (_userId) => Effect.succeed(null),
  };

  const stores = Layer.mergeAll(
    Layer.succeed(SessionStoreTag)(sessionStore),
    Layer.succeed(UserStoreTag)(userStore),
    Layer.succeed(EmailPasswordStoreTag)(emailPasswordStore),
    Layer.succeed(PasswordHasherTag)(hasher),
  );
  const sessionManager = SessionManagerLayer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(stores));

  // Hooks stack: the last-login-method plugin over the no-op base.
  const hooks = composePlugins([makeLastLoginMethodPlugin()]).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(sessionManager),
  );

  return { layer: Layer.mergeAll(stores, sessionManager, hooks), sessions };
};

describe("LastLoginMethodPlugin", () => {
  it("records the method into session.attributes on sign-up and sign-in", async () => {
    const { layer, sessions } = makeFixture();
    const service = await Effect.runPromise(makeEmailPasswordService());

    const { signedUp, signedIn } = await Effect.runPromise(
      Effect.gen(function* () {
        const signedUp = yield* service.signUp({
          email: "alice@test.dev",
          password: "password-123",
        });
        const signedIn = yield* service.signIn({
          email: "alice@test.dev",
          password: "password-123",
        });
        return { signedUp, signedIn };
      }).pipe(Effect.provide(layer)),
    );

    // The hooks see the discriminator...
    expect(signedUp.method).toBe("email-password");
    expect(signedIn.method).toBe("email-password");
    // ...and the plugin persisted it onto both stored sessions.
    expect(sessions.get(signedUp.session!.id)?.attributes["method"]).toBe("email-password");
    expect(sessions.get(signedIn.session!.id)?.attributes["method"]).toBe("email-password");
  });

  it("does nothing when no session was issued", async () => {
    const { sessions } = makeFixture();
    const captured: Array<string | undefined> = [];

    // Drive the hook directly with a session-less result (e.g. a pending
    // second factor): the plugin must not attempt to record anything.
    const probe = Layer.mergeAll(
      composePlugins([makeLastLoginMethodPlugin()]).pipe(
        Layer.provide(Hooks.Default),
        Layer.provide(
          Layer.succeed(SessionManagerTag)({
            setSessionAttributes: (sessionId: string) =>
              Effect.sync(() => {
                captured.push(sessionId);
              }),
          } as never),
        ),
      ),
    );

    const now = new Date();
    const user: Types.User = {
      id: "u1",
      email: "a@b.c",
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
      attributes: {},
    };
    await Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        yield* hooks.afterSignIn({ user, method: "email-password" });
        yield* hooks.afterSignIn({
          user,
          session: {
            id: "s1",
            userId: "u1",
            expiresAt: now,
            createdAt: now,
            lastActivityAt: now,
            attributes: {},
          },
          // No method: nothing to record.
        });
      }).pipe(Effect.provide(probe)),
    );

    expect(captured).toEqual([]);
    expect(sessions.size).toBe(0);
  });
});
