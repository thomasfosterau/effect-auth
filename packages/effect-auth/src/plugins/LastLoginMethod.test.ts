import { assert, describe, it, expect } from "vite-plus/test";
import { DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Option from "effect/Option";
import { composePlugins, Hooks } from "../Hooks.ts";
import * as LastLoginMethod from "./LastLoginMethod.ts";
import * as EmailPassword from "../email/EmailPassword.ts";
import { EmailPasswordStore } from "../email/EmailPassword.ts";
import { IdentifierStore, memoryIdentifierStore, type Identifier } from "../Identifier.ts";
import { PasswordHasher } from "../password/Password.ts";
import * as Password from "../password/Password.ts";
import { SessionService } from "../SessionService.ts";
import { SessionStore } from "../SessionStore.ts";
import { UserStore } from "../UserStore.ts";
import { hashToken } from "../TokenHash.ts";
import type * as Types from "../Types.ts";

const hasher = Password.scryptHasher({ cost: 1024 });

const makeFixture = () => {
  const usersById = MutableHashMap.empty<string, Types.User>();
  const identifierRecords = MutableHashMap.empty<string, Identifier>();
  const passwordHashes = MutableHashMap.empty<string, string>();
  const sessions = MutableHashMap.empty<string, Types.Session>();
  let userSeq = 0;

  const emailPasswordStore: typeof EmailPasswordStore.Service = {
    createUser: (input) =>
      Effect.sync(() => {
        const now = DateTime.toDateUtc(DateTime.nowUnsafe());
        const user: Types.User = {
          id: `user-${++userSeq}`,
          ...(input.name !== undefined && { name: input.name }),
          createdAt: now,
          updatedAt: now,
          attributes: input.attributes ?? {},
        };
        MutableHashMap.set(usersById, user.id, user);
        return { user, created: true };
      }),
    getPasswordHash: (userId) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(passwordHashes, userId))),
    clearPasswordHash: (userId: string) =>
      Effect.sync(() => void MutableHashMap.remove(passwordHashes, userId)),
    setPasswordHash: (userId, hash) =>
      Effect.sync(() => void MutableHashMap.set(passwordHashes, userId, hash)),
  };
  const sessionStore: typeof SessionStore.Service = {
    create: (s) => Effect.sync(() => (MutableHashMap.set(sessions, s.id, s), s)),
    get: (sessionId) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
    update: (s) => Effect.sync(() => (MutableHashMap.set(sessions, s.id, s), s)),
    delete: (sessionId) => Effect.sync(() => void MutableHashMap.remove(sessions, sessionId)),
    deleteByUserId: () => Effect.void,
    listByUserId: () => Effect.succeed([]),
  };
  const userStore: typeof UserStore.Service = {
    get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(usersById, userId))),
  };

  const stores = Layer.mergeAll(
    Layer.succeed(SessionStore)(sessionStore),
    Layer.succeed(UserStore)(userStore),
    Layer.succeed(EmailPasswordStore)(emailPasswordStore),
    Layer.succeed(IdentifierStore)(memoryIdentifierStore(identifierRecords)),
    Layer.succeed(PasswordHasher)(hasher),
  );
  // SessionService.layer needs SessionStore | UserStore | Hooks at construction
  // time. It only ever calls before/afterCreateSession (untouched by the
  // last-login-method plugin, which taps afterSignIn/afterSignUp instead), so a
  // plain Hooks.Default is fine here — using the final plugin-composed `hooks`
  // would be circular, since that layer itself depends on `sessionManager`.
  const sessionManager = SessionService.layer({
    sessionExpiresIn: { activePeriod: 3600_000, idlePeriod: 3600_000 },
  }).pipe(Layer.provide(Layer.mergeAll(stores, Hooks.Default)));

  // Hooks stack: the last-login-method plugin over the no-op base.
  const hooks = composePlugins([LastLoginMethod.LastLoginMethodPlugin]).pipe(
    Layer.provide(Hooks.Default),
    Layer.provide(sessionManager),
  );

  return { layer: Layer.mergeAll(stores, sessionManager, hooks), sessions };
};

describe("LastLoginMethodPlugin", () => {
  it("records the method into session.attributes on sign-up and sign-in", async () => {
    const { layer, sessions } = makeFixture();
    const { signedUp, signedIn } = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* EmailPassword.make();
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
    assert(signedUp.session !== undefined && signedIn.session !== undefined, "both issue sessions");
    // The plugin addresses each session by its stored id, the token's digest.
    expect(signedIn.session.id).toBe(hashToken(signedIn.token ?? ""));
    expect(
      Option.getOrUndefined(MutableHashMap.get(sessions, signedUp.session.id))?.attributes[
        "method"
      ],
    ).toBe("email-password");
    expect(
      Option.getOrUndefined(MutableHashMap.get(sessions, signedIn.session.id))?.attributes[
        "method"
      ],
    ).toBe("email-password");
  });

  it("does nothing when no session was issued", async () => {
    const { sessions } = makeFixture();
    const captured: Array<string | undefined> = [];

    // Drive the hook directly with a session-less result (e.g. a pending
    // second factor): the plugin must not attempt to record anything.
    const probe = Layer.mergeAll(
      composePlugins([LastLoginMethod.LastLoginMethodPlugin]).pipe(
        Layer.provide(Hooks.Default),
        Layer.provide(
          // SAFETY: the plugin's hook reaches `SessionService` only through
          // `setSessionAttributes`, the one member this stand-in carries.
          Layer.succeed(SessionService)({
            setSessionAttributes: (sessionId: string) =>
              Effect.sync(() => {
                captured.push(sessionId);
              }),
          } as never),
        ),
      ),
    );

    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    const user: Types.User = {
      id: "u1",
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
    expect(MutableHashMap.size(sessions)).toBe(0);
  });
});
