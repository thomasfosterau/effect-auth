import { describe, it, expect } from "vite-plus/test";
import { Context, Effect, Layer } from "effect";
import { Hooks, composePlugins, makePlugin } from "./Hooks.js";
import * as Errors from "./Errors.js";
import type { AuthResult, SignInInput } from "./EmailPassword.js";
import { EmailPasswordStore } from "./EmailPassword.js";
import { makeEmailPasswordService } from "./EmailPassword.js";
import { PasswordHasher, makePBKDF2Hasher } from "./Password.js";
import { makeSessionManager, SessionStore, UserStore, SessionManager } from "./Session.js";
import { type RateLimitEntry, RateLimiter, RateLimitStore } from "./RateLimit.js";
import { RateLimitPlugin } from "./plugins/RateLimitPlugin.js";
import type { Session, SessionConfig, User } from "./Types.js";

const signIn = (email: string): SignInInput => ({ email, password: "secret" });
const authResult: AuthResult = {
  user: {
    id: "user-1",
    email: "user-1@example.com",
    emailVerified: false,
    createdAt: new Date(),
    updatedAt: new Date(),
    attributes: {},
  },
};

/** Run a program against a Hooks stack composed of the given plugin layers. */
const runWithPlugins = <A, E>(
  plugins: ReadonlyArray<Layer.Layer<Hooks, never, Hooks>>,
  program: Effect.Effect<A, E, Hooks>,
): Promise<A> =>
  Effect.runPromise(
    program.pipe(Effect.provide(composePlugins(plugins).pipe(Layer.provide(Hooks.Default)))),
  );

describe("Hooks - transform chaining", () => {
  const appendA = makePlugin({
    beforeSignIn: (input) => Effect.succeed({ ...input, email: `${input.email}-a` }),
  });
  const appendB = makePlugin({
    beforeSignIn: (input) => Effect.succeed({ ...input, email: `${input.email}-b` }),
  });

  it("threads the value through plugins in array order (A then B)", async () => {
    const result = await runWithPlugins(
      [appendA, appendB],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* hooks.beforeSignIn(signIn("x"));
      }),
    );

    expect(result.email).toBe("x-a-b");
  });

  it("swapping plugin order changes the outcome (B then A)", async () => {
    const result = await runWithPlugins(
      [appendB, appendA],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* hooks.beforeSignIn(signIn("x"));
      }),
    );

    expect(result.email).toBe("x-b-a");
  });
});

describe("Hooks - defaults", () => {
  it("leaves unspecified hooks as no-op identity defaults", async () => {
    // Plugin only specifies beforeSignIn; afterSignIn must fall through untouched.
    const onlyBeforeSignIn = makePlugin({
      beforeSignIn: (input) => Effect.succeed({ ...input, email: `${input.email}!` }),
    });

    const { transformed, observed } = await runWithPlugins(
      [onlyBeforeSignIn],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        const transformed = yield* hooks.beforeSignIn(signIn("x"));
        // afterSignIn was never provided -> identity, returns its input unchanged
        const observed = yield* hooks.afterSignIn(authResult);
        return { transformed, observed };
      }),
    );

    expect(transformed.email).toBe("x!");
    expect(observed).toBe(authResult);
  });

  it("an empty plugin stack behaves exactly like Hooks.Default", async () => {
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* hooks.beforeSignIn(signIn("untouched"));
      }).pipe(Effect.provide(composePlugins([]).pipe(Layer.provide(Hooks.Default)))),
    );

    expect(result.email).toBe("untouched");
  });
});

describe("Hooks - tap error handling", () => {
  it("with isolateTaps, every tap fires even when one fails", async () => {
    const calls: Array<string> = [];

    const failingTap = makePlugin(
      {
        afterSignIn: Hooks.tap(() =>
          Effect.sync(() => {
            calls.push("a");
          }).pipe(Effect.andThen(Effect.fail(new Errors.AuthError({ message: "boom" })))),
        ),
      },
      { isolateTaps: true },
    );

    const recordingTap = makePlugin(
      {
        afterSignIn: Hooks.tap(() =>
          Effect.sync(() => {
            calls.push("b");
          }),
        ),
      },
      { isolateTaps: true },
    );

    const result = await runWithPlugins(
      [failingTap, recordingTap],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* hooks.afterSignIn(authResult);
      }),
    );

    // Both taps ran in order despite the first failing (isolated),
    expect(calls).toEqual(["a", "b"]);
    // and the observed value was threaded through unchanged.
    expect(result).toBe(authResult);
  });

  it("without isolateTaps, a failing after* tap aborts the hook call", async () => {
    const strictTap = makePlugin({
      afterSignIn: Hooks.tap(() => Effect.fail(new Errors.AuthError({ message: "nope" }))),
    });

    const result = await runWithPlugins(
      [strictTap],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* Effect.result(hooks.afterSignIn(authResult));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("AuthError");
    }
  });
});

describe("Hooks - before* transform isolation: isolateTaps must not swallow denies", () => {
  it("before* deny propagates even when isolateTaps: true is set (primary bug fix)", async () => {
    // A plugin with isolateTaps:true that also defines a before* transform.
    // The before* failure must never be swallowed — doing so would silently
    // allow an operation that the plugin intended to deny (captcha / geo-block
    // / lockout semantics).
    const deny = makePlugin(
      {
        beforeSignIn: () =>
          Effect.fail(new Errors.RateLimitError({ message: "blocked", key: "k" })),
      },
      { isolateTaps: true },
    );

    const result = await runWithPlugins(
      [deny],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* Effect.result(hooks.beforeSignIn(signIn("x")));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("RateLimitError");
    }
  });

  it("before* deny under isolateTaps: true blocks later plugins too", async () => {
    let laterRan = false;

    const deny = makePlugin(
      {
        beforeSignIn: () =>
          Effect.fail(new Errors.RateLimitError({ message: "blocked", key: "k" })),
      },
      { isolateTaps: true },
    );
    const later = makePlugin({
      beforeSignIn: (input) =>
        Effect.sync(() => {
          laterRan = true;
          return input;
        }),
    });

    const result = await runWithPlugins(
      [deny, later],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* Effect.result(hooks.beforeSignIn(signIn("x")));
      }),
    );

    expect(result._tag).toBe("Failure");
    expect(laterRan).toBe(false);
  });
});

describe("Hooks - transform short-circuit", () => {
  it("propagates a transform failure as a typed error (deny)", async () => {
    const deny = makePlugin({
      beforeSignIn: () =>
        Effect.fail(new Errors.RateLimitError({ message: "rate limited", key: "k" })),
    });

    const result = await runWithPlugins(
      [deny],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* Effect.result(hooks.beforeSignIn(signIn("x")));
      }),
    );

    expect(result._tag).toBe("Failure");
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("RateLimitError");
    }
  });

  it("a failing earlier transform short-circuits before later ones run", async () => {
    let laterRan = false;

    const deny = makePlugin({
      beforeSignIn: () =>
        Effect.fail(new Errors.RateLimitError({ message: "rate limited", key: "k" })),
    });
    const later = makePlugin({
      beforeSignIn: (input) =>
        Effect.sync(() => {
          laterRan = true;
          return input;
        }),
    });

    // deny runs first; `later` must never run.
    const result = await runWithPlugins(
      [deny, later],
      Effect.gen(function* () {
        const hooks = yield* Hooks;
        return yield* Effect.result(hooks.beforeSignIn(signIn("x")));
      }),
    );

    expect(result._tag).toBe("Failure");
    expect(laterRan).toBe(false);
  });
});

describe("RateLimitPlugin - dependency composition + short-circuit", () => {
  const makeRateLimitStoreLayer = () => {
    const entries = new Map<string, RateLimitEntry>();
    return Layer.succeed(RateLimitStore, {
      get: (key: string) => Effect.succeed(entries.get(key) ?? null),
      set: (key: string, entry: RateLimitEntry) =>
        Effect.sync(() => {
          entries.set(key, entry);
        }),
      increment: (key: string) =>
        Effect.sync(() => {
          const existing = entries.get(key);
          const count = (existing?.count ?? 0) + 1;
          if (existing) {
            entries.set(key, { ...existing, count });
          }
          return count;
        }),
      delete: (key: string) =>
        Effect.sync(() => {
          entries.delete(key);
        }),
    });
  };

  it("allows attempts up to the limit, then fails with RateLimitError", async () => {
    // RateLimitPlugin declares its own deps: Layer<Hooks, never, Hooks | RateLimiter | RateLimitStore>.
    const layer = composePlugins([RateLimitPlugin]).pipe(
      Layer.provide(Hooks.Default),
      Layer.provide(RateLimiter.layer()),
      Layer.provide(makeRateLimitStoreLayer()),
    );

    const program = Effect.gen(function* () {
      const hooks = yield* Hooks;
      const outcomes: Array<string> = [];
      // login preset allows 5 requests per window.
      for (let i = 0; i < 6; i++) {
        const result = yield* Effect.result(hooks.beforeSignIn(signIn("rate@example.com")));
        outcomes.push(result._tag === "Success" ? "ok" : result.failure._tag);
      }
      return outcomes;
    });

    const outcomes = await Effect.runPromise(program.pipe(Effect.provide(layer)));

    expect(outcomes.slice(0, 5)).toEqual(["ok", "ok", "ok", "ok", "ok"]);
    expect(outcomes[5]).toBe("RateLimitError");
  });
});

describe("Hooks - integration with EmailPasswordService", () => {
  it("a beforeSignUp transform enriches the input the service consumes", async () => {
    const users = new Map<string, User>();
    const usersByEmail = new Map<string, string>();
    const passwordHashes = new Map<string, string>();
    const sessions = new Map<string, Session>();

    const sessionStore = {
      create: (session: Session) =>
        Effect.sync(() => {
          sessions.set(session.id, session);
          return session;
        }),
      get: (sessionId: string) => Effect.sync(() => sessions.get(sessionId) ?? null),
      update: (session: Session) =>
        Effect.sync(() => {
          sessions.set(session.id, session);
          return session;
        }),
      delete: (sessionId: string) =>
        Effect.sync(() => {
          sessions.delete(sessionId);
        }),
      deleteByUserId: (userId: string) =>
        Effect.sync(() => {
          for (const [id, session] of sessions.entries()) {
            if (session.userId === userId) sessions.delete(id);
          }
        }),
      listByUserId: (userId: string) =>
        Effect.sync(() =>
          Array.from(sessions.values()).filter((session) => session.userId === userId),
        ),
    };

    const userStore = {
      get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),
      getCredentials: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),
    };

    const emailPasswordStore = {
      getUserByEmail: (email: string) =>
        Effect.sync(() => {
          const id = usersByEmail.get(email);
          return id ? (users.get(id) ?? null) : null;
        }),
      createUser: ({
        email,
        attributes,
      }: {
        email: string;
        name?: string;
        attributes?: Record<string, unknown>;
      }) =>
        Effect.sync(() => {
          const id = `user-${users.size + 1}`;
          const user: User = {
            id,
            email,
            emailVerified: false,
            createdAt: new Date(),
            updatedAt: new Date(),
            attributes: attributes ?? {},
          };
          users.set(id, user);
          usersByEmail.set(email, id);
          return user;
        }),
      getPasswordHash: (userId: string) => Effect.sync(() => passwordHashes.get(userId) ?? null),
      setPasswordHash: (userId: string, hash: string) =>
        Effect.sync(() => {
          passwordHashes.set(userId, hash);
        }),
    };

    const sessionConfig: SessionConfig = {
      sessionExpiresIn: { activePeriod: 1000 * 60 * 60, idlePeriod: 1000 * 60 * 30 },
    };

    const sessionManager = await Effect.runPromise(
      Effect.provide(
        makeSessionManager(sessionConfig),
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
      ),
    );

    const testContext = Context.merge(
      Context.make(SessionManager, sessionManager),
      Context.merge(
        Context.make(EmailPasswordStore, emailPasswordStore),
        Context.make(PasswordHasher, makePBKDF2Hasher()),
      ),
    );

    // A transform plugin that stamps an attribute onto the sign-up input.
    const enrich = makePlugin({
      beforeSignUp: (input) =>
        Effect.succeed({
          ...input,
          attributes: { ...input.attributes, enrichedByPlugin: true },
        }),
    });

    const program = Effect.gen(function* () {
      const service = yield* makeEmailPasswordService();
      return yield* service.signUp({ email: "person@example.com", password: "strong-password" });
    });

    const result = await Effect.runPromise(
      program.pipe(
        Effect.provide(testContext),
        Effect.provide(composePlugins([enrich]).pipe(Layer.provide(Hooks.Default))),
      ),
    );

    // The attribute injected by the beforeSignUp hook reached the persisted user.
    expect(result.user.attributes.enrichedByPlugin).toBe(true);
  });
});
