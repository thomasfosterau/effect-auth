import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Effect, Layer } from "effect";
import { UsernameService, UsernameError, type UsernameConfig } from "./Username.ts";
import {
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
} from "./email/EmailPassword.ts";
import {
  IdentifierStore,
  memoryIdentifierStore,
  type Identifier,
  type IdentifierType,
} from "./Identifier.ts";
import { PasswordHasher } from "./password/Password.ts";
import * as Password from "./password/Password.ts";
import { SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { Hooks } from "./Hooks.ts";
import type * as Types from "./Types.ts";

const hasher = Password.scryptHasher({ cost: 1024 });
const sessionConfig: Types.SessionConfig = {
  sessionExpiresIn: { activePeriod: 1000 * 60 * 60, idlePeriod: 1000 * 60 * 60 },
};

// Shared in-memory state, reset per test. Login handles (emails, usernames)
// live in the identifier store now, not on the user record.
const usersById = new Map<string, Types.User>();
const identifierRecords = new Map<string, Identifier>();
const passwordHashes = new Map<string, string>();
const sessions = new Map<string, Types.Session>();
let seq = 0;

const identifierStore = memoryIdentifierStore(identifierRecords);

const findIdentifier = (type: IdentifierType, value: string): Identifier | null => {
  for (const record of identifierRecords.values()) {
    if (record.type === type && record.value === value) return record;
  }
  return null;
};

const emailPasswordStore: typeof EmailPasswordStore.Service = {
  createUser: (input) =>
    Effect.sync(() => {
      const now = new Date();
      const user: Types.User = {
        id: `user-${++seq}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: now,
        updatedAt: now,
        attributes: input.attributes ?? {},
      };
      usersById.set(user.id, user);
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
};

const hasherLayer = Layer.succeed(PasswordHasher)(hasher);

// Stage 0: raw stores + hasher + Hooks (no construction-time deps of their own).
const storesLayer = Layer.mergeAll(
  Layer.succeed(IdentifierStore)(identifierStore),
  Layer.succeed(EmailPasswordStore)(emailPasswordStore),
  Layer.succeed(SessionStore)(sessionStore),
  Layer.succeed(UserStore)(userStore),
  hasherLayer,
  Hooks.Default,
);

// Stage 1: SessionService.layer needs SessionStore | UserStore | Hooks.
const sessionServiceLayer = SessionService.layer(sessionConfig).pipe(Layer.provide(storesLayer));

const stage1 = Layer.mergeAll(storesLayer, sessionServiceLayer);

// Stage 2: EmailPasswordService.layer needs EmailPasswordStore | IdentifierStore |
// UserStore | PasswordHasher | SessionService | Hooks, all now available from stage1.
const emailPasswordServiceLayer = EmailPasswordService.layer({}).pipe(Layer.provide(stage1));

const baseDeps = Layer.mergeAll(stage1, emailPasswordServiceLayer);

const gate = (required: boolean): typeof SecondFactorGate.Service => ({
  required: () => Effect.succeed(required),
  begin: () => Effect.succeed({ token: "2fa-token", expiresAt: Date.now() + 60_000 }),
});

type UsernameDeps =
  | IdentifierStore
  | UserStore
  | EmailPasswordService
  | EmailPasswordStore
  | PasswordHasher
  | SessionService
  | Hooks;

const run = <A, E>(
  f: (svc: typeof UsernameService.Service) => Effect.Effect<A, E, UsernameDeps>,
  opts?: { config?: UsernameConfig; gate?: typeof SecondFactorGate.Service },
) => {
  // UsernameService.layer needs IdentifierStore | UserStore | EmailPasswordService |
  // EmailPasswordStore | PasswordHasher | SessionService | Hooks at construction time —
  // all satisfied by baseDeps.
  const usernameLayer = UsernameService.layer(opts?.config).pipe(Layer.provide(baseDeps));
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
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
    seq = 0;
  });

  it("signs up, normalizing and reserving the username", async () => {
    const result = await run((svc) =>
      svc.signUp({ username: "Alice_01", email: "alice@example.com", password: "password-123" }),
    );
    const identifier = findIdentifier("username", "alice_01");
    expect(identifier?.userId).toBe(result.user.id);
    // Usernames carry no external proof-of-ownership: created verified.
    expect(identifier?.verified).toBe(true);
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
    expect(result.identifier).toEqual({ type: "username", value: "carol" });
    expect(result.user.id).toBe(findIdentifier("username", "carol")?.userId);
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

    // Once the email identifier is marked verified the same credentials succeed.
    const emailIdentifier = findIdentifier("email", "hector@example.com")!;
    identifierRecords.set(emailIdentifier.id, {
      ...emailIdentifier,
      verified: true,
      verifiedAt: new Date(),
    });
    const result = await run(
      (svc) => svc.signIn({ username: "hector", password: "password-123" }),
      { config: { requireEmailVerification: true } },
    );
    expect(result.session).toBeDefined();
  });

  it("calls passwordHasher.verify even for an unknown username (constant-work)", async () => {
    let verifyCalls = 0;
    const realHasher = Password.scryptHasher({ cost: 1024 });
    const spyHasher: typeof PasswordHasher.Service = {
      algorithm: realHasher.algorithm,
      hash: (password) => realHasher.hash(password),
      verify: (password, hash) => {
        verifyCalls++;
        return realHasher.verify(password, hash);
      },
    };

    const spyHasherLayer = Layer.succeed(PasswordHasher)(spyHasher);

    const spyStoresLayer = Layer.mergeAll(
      Layer.succeed(IdentifierStore)(identifierStore),
      Layer.succeed(EmailPasswordStore)(emailPasswordStore),
      Layer.succeed(SessionStore)(sessionStore),
      Layer.succeed(UserStore)(userStore),
      spyHasherLayer,
      Hooks.Default,
    );

    const spySessionServiceLayer = SessionService.layer(sessionConfig).pipe(
      Layer.provide(spyStoresLayer),
    );

    const spyStage1 = Layer.mergeAll(spyStoresLayer, spySessionServiceLayer);

    const spyEmailPasswordServiceLayer = EmailPasswordService.layer({}).pipe(
      Layer.provide(spyStage1),
    );

    const spyDeps = Layer.mergeAll(spyStage1, spyEmailPasswordServiceLayer);

    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* UsernameService;
        return yield* Effect.flip(svc.signIn({ username: "ghost", password: "any-password" }));
      }).pipe(
        Effect.provide(
          Layer.mergeAll(UsernameService.layer().pipe(Layer.provide(spyDeps)), spyDeps),
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

    // Changing to a free username succeeds and drops the old identifier.
    await run((svc) => svc.updateUsername(a.user.id, "franklin"));
    expect(findIdentifier("username", "franklin")?.userId).toBe(a.user.id);
    expect(findIdentifier("username", "frank")).toBeNull();
  });
});
