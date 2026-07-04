import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Layer } from "effect";
import {
  UsernameService,
  UsernameStore,
  UsernameError,
  type UsernameConfig,
  type UsernameServiceShape,
  type UsernameStoreShape,
} from "./Username.js";
import {
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
  type EmailPasswordStoreShape,
  type SecondFactorGateShape,
} from "./EmailPassword.js";
import { PasswordHasher, makeScryptHasher } from "./Password.js";
import { SessionManager, SessionStore, UserStore } from "./Session.js";
import type { SessionStoreShape, UserStoreShape } from "./Session.js";
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

const usernameStore: UsernameStoreShape = {
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

const emailPasswordStore: EmailPasswordStoreShape = {
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

const sessionStore: SessionStoreShape = {
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

const userStore: UserStoreShape = {
  get: (userId) => Effect.sync(() => usersById.get(userId) ?? null),
  getCredentials: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
};

const baseDeps = Layer.mergeAll(
  Layer.succeed(UsernameStore)(usernameStore),
  Layer.succeed(EmailPasswordStore)(emailPasswordStore),
  Layer.succeed(PasswordHasher)(hasher),
  SessionManager.layer(sessionConfig).pipe(
    Layer.provide(
      Layer.mergeAll(
        Layer.succeed(SessionStore)(sessionStore),
        Layer.succeed(UserStore)(userStore),
      ),
    ),
  ),
  EmailPasswordService.layer({}),
  Hooks.Default,
);

const gate = (required: boolean): SecondFactorGateShape => ({
  required: () => Effect.succeed(required),
  begin: () => Effect.succeed({ token: "2fa-token", expiresAt: Date.now() + 60_000 }),
});

type UsernameDeps =
  | UsernameStore
  | EmailPasswordService
  | EmailPasswordStore
  | PasswordHasher
  | SessionManager
  | Hooks;

const run = <A, E>(
  f: (svc: UsernameServiceShape) => Effect.Effect<A, E, UsernameDeps>,
  opts?: { config?: UsernameConfig; gate?: SecondFactorGateShape },
) => {
  const layer = opts?.gate
    ? Layer.mergeAll(
        UsernameService.layer(opts.config),
        baseDeps,
        Layer.succeed(SecondFactorGate)(opts.gate),
      )
    : Layer.mergeAll(UsernameService.layer(opts?.config), baseDeps);
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
