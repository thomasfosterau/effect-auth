import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Layer } from "effect";
import {
  UsernameService,
  UsernameStore,
  UsernameError,
  type UsernameConfig,
} from "./Username.js";
import {
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
} from "./email/EmailPassword.js";
import { PasswordHasher, makeScryptHasher } from "./password/Password.js";
import { SessionService } from "./session/SessionService.js";
import { SessionStore } from "./session/SessionStore.js";
import { UserStore } from "./session/UserStore.js";
import { Hooks } from "./Hooks.js";
import type * as Types from "./Types.js";

const hasher = makeScryptHasher({ cost: 16384 });
const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60, idlePeriod: 1000 * 60 * 60 },
};

// Shared in-memory state, reset per test.
const usersById = new Map<string, Types.User>();
const userIdByEmail = new Map<string, string>();
const usernameToId = new Map<string, string>();
const passwordHashes = new Map<string, string>();
const sessions = new Map<string, Types.Session>();
let seq = 0;

const usernameStore: typeof UsernameStore.Service = {
  getUserByUsername: (username) =>
    Effect.sync(() => {
      const id = usernameToId.get(username);
      return id === undefined ? null : (usersById.get(id) ?? null);
    }),
  isUsernameTaken: (username) => Effect.sync(() => usernameToId.has(username)),
  setUsername: (userId, username) =>
    Effect.sync(() => {
      // Drop any previous username mapping for this user.
      for (const [name, id] of usernameToId) if (id === userId) usernameToId.delete(name);
      usernameToId.set(username, userId);
      const user = usersById.get(userId);
      if (user !== undefined) {
        usersById.set(userId, {
          ...user,
          attributes: { ...user.attributes, username },
        });
      }
    }),
};

const emailPasswordStore: typeof EmailPasswordStore.Service = {
  getUserByEmail: (email) =>
    Effect.sync(() => {
      const id = userIdByEmail.get(email);
      return id === undefined ? null : (usersById.get(id) ?? null);
    }),
  createUser: (input) =>
    Effect.sync(() => {
      const now = new Date();
      const user: Types.User = {
        id: `user-${++seq}`,
        email: input.email,
        emailVerified: false,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: now,
        updatedAt: now,
        attributes: input.attributes ?? {},
      };
      usersById.set(user.id, user);
      userIdByEmail.set(user.email, user.id);
      return user;
    }),
  getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  setPasswordHash: (userId, hash) => Effect.sync(() => void passwordHashes.set(userId, hash)),
};

const sessionStore: typeof SessionStore.Service = {
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
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, s] of sessions) if (s.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((s) => s.userId === userId)),
};

const userStore: typeof UserStore.Service = {
  get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
  getCredentials: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
};

const hasherLayer = Layer.succeed(PasswordHasher)(hasher);

const baseDeps = Layer.mergeAll(
  Layer.succeed(UsernameStore)(usernameStore),
  Layer.succeed(EmailPasswordStore)(emailPasswordStore),
  hasherLayer,
  SessionService.layer(sessionConfig).pipe(
    Layer.provide(
      Layer.mergeAll(
        Layer.succeed(SessionStore)(sessionStore),
        Layer.succeed(UserStore)(userStore),
      ),
    ),
  ),
  // EmailPasswordService.layer now requires PasswordHasher at construction (for the
  // decoy hash). Layer.mergeAll does not auto-wire, so pipe Layer.provide explicitly.
  EmailPasswordService.layer({}).pipe(Layer.provide(hasherLayer)),
  Hooks.Default,
);

const gate = (required: boolean): typeof SecondFactorGate.Service => ({
  required: () => Effect.succeed(required),
  begin: () => Effect.succeed({ token: "2fa-token", expiresAt: Date.now() + 60_000 }),
});

type UsernameDeps =
  | UsernameStore
  | EmailPasswordService
  | EmailPasswordStore
  | PasswordHasher
  | SessionService
  | Hooks;

const run = <A, E>(
  f: (svc: typeof UsernameService.Service) => Effect.Effect<A, E, UsernameDeps>,
  opts?: { config?: UsernameConfig; gate?: typeof SecondFactorGate.Service },
) => {
  // UsernameService.layer also requires PasswordHasher at construction time (decoy hash).
  const usernameLayer = UsernameService.layer(opts?.config).pipe(Layer.provide(hasherLayer));
  const layer = opts?.gate
    ? Layer.mergeAll(usernameLayer, baseDeps, Layer.succeed(SecondFactorGate)(opts.gate))
    : Layer.mergeAll(usernameLayer, baseDeps);
  return Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* UsernameService;
      return yield* f(svc);
    }).pipe(Effect.provide(layer)),
  );
};

describe("UsernameService", () => {
  beforeEach(() => {
    usersById.clear();
    userIdByEmail.clear();
    usernameToId.clear();
    passwordHashes.clear();
    sessions.clear();
    seq = 0;
  });

  it("signs up, normalizing and reserving the username", async () => {
    const result = await run((svc) =>
      svc.signUp({ username: "Alice_01", email: "alice@example.com", password: "password-123" }),
    );
    expect(result.user.attributes["username"]).toBe("alice_01");
    expect(usernameToId.get("alice_01")).toBe(result.user.id);
    expect(result.session).toBeDefined();
  });

  it("rejects a duplicate username (case-insensitive)", async () => {
    await run((svc) =>
      svc.signUp({ username: "bob", email: "bob@example.com", password: "password-123" }),
    );
    const err = await run((svc) =>
      Effect.flip(
        svc.signUp({ username: "BOB", email: "bob2@example.com", password: "password-123" }),
      ),
    );
    expect(err).toBeInstanceOf(UsernameError);
  });

  it("rejects an invalid username (charset / length)", async () => {
    const bad = await run((svc) =>
      Effect.flip(
        svc.signUp({ username: "a b!", email: "x@example.com", password: "password-123" }),
      ),
    );
    expect(bad).toBeInstanceOf(UsernameError);
    const short = await run((svc) =>
      Effect.flip(svc.signUp({ username: "ab", email: "y@example.com", password: "password-123" })),
    );
    expect(short).toBeInstanceOf(UsernameError);
  });

  it("signs in with the correct password", async () => {
    await run((svc) =>
      svc.signUp({ username: "carol", email: "carol@example.com", password: "password-123" }),
    );
    const result = await run((svc) => svc.signIn({ username: "Carol", password: "password-123" }));
    expect(result.session).toBeDefined();
    expect(result.user.attributes["username"]).toBe("carol");
  });

  it("returns a uniform error for a wrong password or unknown username", async () => {
    await run((svc) =>
      svc.signUp({ username: "dave", email: "dave@example.com", password: "password-123" }),
    );
    const wrong = await run((svc) =>
      Effect.flip(svc.signIn({ username: "dave", password: "nope" })),
    );
    const unknown = await run((svc) =>
      Effect.flip(svc.signIn({ username: "ghost", password: "password-123" })),
    );
    expect(wrong._tag).toBe("InvalidCredentialsError");
    expect(unknown._tag).toBe("InvalidCredentialsError");
  });

  it("honours the second-factor gate", async () => {
    await run((svc) =>
      svc.signUp({ username: "erin", email: "erin@example.com", password: "password-123" }),
    );
    const result = await run((svc) => svc.signIn({ username: "erin", password: "password-123" }), {
      gate: gate(true),
    });
    expect(result.secondFactor).toBeDefined();
    expect(result.session).toBeUndefined();
  });

  it("blocks sign-in when email is unverified and requireEmailVerification is enabled", async () => {
    await run((svc) =>
      svc.signUp({ username: "hector", email: "hector@example.com", password: "password-123" }),
    );
    const err = await run(
      (svc) => Effect.flip(svc.signIn({ username: "hector", password: "password-123" })),
      { config: { requireEmailVerification: true } },
    );
    expect(err._tag).toBe("EmailNotVerifiedError");

    // Once the email is marked verified the same credentials succeed.
    const userId = usernameToId.get("hector")!;
    usersById.set(userId, { ...usersById.get(userId)!, emailVerified: true });
    const result = await run(
      (svc) => svc.signIn({ username: "hector", password: "password-123" }),
      { config: { requireEmailVerification: true } },
    );
    expect(result.session).toBeDefined();
  });

  it("calls passwordHasher.verify even for an unknown username (constant-work)", async () => {
    let verifyCalls = 0;
    const realHasher = makeScryptHasher({ cost: 16384 });
    const spyHasher: typeof PasswordHasher.Service = {
      algorithm: realHasher.algorithm,
      hash: (password) => realHasher.hash(password),
      verify: (password, hash) => {
        verifyCalls++;
        return realHasher.verify(password, hash);
      },
    };

    const spyHasherLayer = Layer.succeed(PasswordHasher)(spyHasher);

    const spyDeps = Layer.mergeAll(
      Layer.succeed(UsernameStore)(usernameStore),
      Layer.succeed(EmailPasswordStore)(emailPasswordStore),
      spyHasherLayer,
      SessionService.layer(sessionConfig).pipe(
        Layer.provide(
          Layer.mergeAll(
            Layer.succeed(SessionStore)(sessionStore),
            Layer.succeed(UserStore)(userStore),
          ),
        ),
      ),
      EmailPasswordService.layer({}).pipe(Layer.provide(spyHasherLayer)),
      Hooks.Default,
    );

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* UsernameService;
        return yield* Effect.flip(svc.signIn({ username: "ghost", password: "any-password" }));
      }).pipe(
        Effect.provide(
          Layer.mergeAll(UsernameService.layer().pipe(Layer.provide(spyHasherLayer)), spyDeps),
        ),
      ),
    );

    expect(err._tag).toBe("InvalidCredentialsError");
    expect(verifyCalls).toBeGreaterThanOrEqual(1);
  });

  it("updates a username with uniqueness enforced", async () => {
    const a = await run((svc) =>
      svc.signUp({ username: "frank", email: "frank@example.com", password: "password-123" }),
    );
    await run((svc) =>
      svc.signUp({ username: "grace", email: "grace@example.com", password: "password-123" }),
    );

    // Taking another user's username fails.
    const clash = await run((svc) => Effect.flip(svc.updateUsername(a.user.id, "grace")));
    expect(clash).toBeInstanceOf(UsernameError);

    // Changing to a free username succeeds.
    await run((svc) => svc.updateUsername(a.user.id, "franklin"));
    expect(usernameToId.get("franklin")).toBe(a.user.id);
    expect(usernameToId.has("frank")).toBe(false);
  });
});
