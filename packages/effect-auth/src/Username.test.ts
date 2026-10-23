import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { Array as Arr, Effect, Layer, Option, Order } from "effect";
import { UsernameService, UsernameError, type UsernameConfig } from "./Username.ts";
import {
  type AuthResult,
  type EmailPasswordConfig,
  EmailPasswordService,
  EmailPasswordStore,
  SecondFactorGate,
} from "./email/EmailPassword.ts";
import {
  IdentifierStore,
  makeIdentifier,
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
  return Option.getOrNull(
    Arr.findFirst(
      identifierRecords.values(),
      (record) => record.type === type && record.value === value,
    ),
  );
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
      return { user, created: true };
    }),
  getPasswordHash: (userId) => Effect.sync(() => passwordHashes.get(userId) ?? null),
  clearPasswordHash: (userId: string) => Effect.sync(() => void passwordHashes.delete(userId)),
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
      sessions.forEach((s, id) => {
        if (s.userId === userId) sessions.delete(id);
      });
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
    const emailIdentifier = findIdentifier("email", "hector@example.com");
    assert(emailIdentifier !== null, "sign-up stored the email identifier");
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

describe("UsernameService under anti-enumeration (#414)", () => {
  beforeEach(() => {
    usersById.clear();
    identifierRecords.clear();
    passwordHashes.clear();
    sessions.clear();
    seq = 0;
  });

  const PASSWORD = "password-123";

  const claimEmail = (userId: string, email: string): void => {
    const identifier = makeIdentifier({ userId, type: "email", value: email, verified: false });
    identifierRecords.set(identifier.id, identifier);
  };

  /** A user who already holds `email`, created outside any sign-up. */
  const seedOwner = (email: string): Types.User => {
    const now = new Date();
    const owner: Types.User = {
      id: `owner-${++seq}`,
      createdAt: now,
      updatedAt: now,
      attributes: {},
    };
    usersById.set(owner.id, owner);
    claimEmail(owner.id, email);
    return owner;
  };

  /**
   * Run `f` against a `UsernameService` over an `EmailPasswordService` with
   * `antiEnumeration`, its store and hasher replaceable.
   */
  const runAntiEnumeration = <A, E>(
    f: (svc: typeof UsernameService.Service) => Effect.Effect<A, E, UsernameDeps>,
    opts: {
      readonly store?: typeof EmailPasswordStore.Service;
      readonly identifiers?: typeof IdentifierStore.Service;
      readonly hasher?: typeof PasswordHasher.Service;
      readonly emailPassword?: EmailPasswordConfig;
      readonly decorate?: (
        service: typeof EmailPasswordService.Service,
      ) => typeof EmailPasswordService.Service;
    } = {},
  ) => {
    const stores = Layer.mergeAll(
      Layer.succeed(IdentifierStore)(opts.identifiers ?? identifierStore),
      Layer.succeed(EmailPasswordStore)(opts.store ?? emailPasswordStore),
      Layer.succeed(SessionStore)(sessionStore),
      Layer.succeed(UserStore)(userStore),
      Layer.succeed(PasswordHasher)(opts.hasher ?? hasher),
      Hooks.Default,
    );
    const withSessions = Layer.mergeAll(
      stores,
      SessionService.layer(sessionConfig).pipe(Layer.provide(stores)),
    );
    const emailPassword = EmailPasswordService.layer(
      opts.emailPassword ?? { antiEnumeration: true },
    ).pipe(Layer.provide(withSessions));
    const decorate = opts.decorate;
    const deps = Layer.mergeAll(
      withSessions,
      decorate === undefined
        ? emailPassword
        : Layer.effect(
            EmailPasswordService,
            Effect.gen(function* () {
              return decorate(yield* EmailPasswordService);
            }),
          ).pipe(Layer.provide(emailPassword)),
    );
    return Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* UsernameService;
        return yield* f(svc);
      }).pipe(
        Effect.provide(Layer.mergeAll(UsernameService.layer().pipe(Layer.provide(deps)), deps)),
      ),
    );
  };

  // The ways sign-up finds the address held by another user. Each seeds the
  // owner for `victim@example.com` and returns the store sign-up runs with.
  const VICTIM = "victim@example.com";
  const takenAddress: ReadonlyArray<{
    readonly name: string;
    readonly arrange: () => {
      readonly owner: Types.User;
      readonly store: typeof EmailPasswordStore.Service;
    };
  }> = [
    {
      name: "the pre-check",
      arrange: () => ({ owner: seedOwner(VICTIM), store: emailPasswordStore }),
    },
    {
      name: "a concurrent sign-up winning the claim",
      arrange: () => {
        let owner: Types.User | undefined;
        return {
          get owner() {
            assert(owner !== undefined, "the store never ran");
            return owner;
          },
          store: {
            ...emailPasswordStore,
            createUser: (input) =>
              Effect.gen(function* () {
                if (input.identifier?.value === VICTIM) owner = seedOwner(VICTIM);
                return yield* emailPasswordStore.createUser(input);
              }),
          },
        };
      },
    },
    {
      name: "a store reporting created: false",
      arrange: () => {
        let owner: Types.User | undefined;
        return {
          get owner() {
            assert(owner !== undefined, "the store never ran");
            return owner;
          },
          store: {
            ...emailPasswordStore,
            createUser: (input) =>
              input.identifier?.value === VICTIM
                ? Effect.sync(() => {
                    owner = seedOwner(VICTIM);
                    return { user: owner, created: false };
                  })
                : emailPasswordStore.createUser(input),
          },
        };
      },
    },
  ];

  it.each(takenAddress)(
    "an address found taken by $name answers as a fresh sign-up does and claims no username",
    async ({ arrange }) => {
      const arranged = arrange();
      const fresh = await runAntiEnumeration(
        (svc) =>
          svc.signUp({ username: "fresh_one", email: "fresh@example.com", password: PASSWORD }),
        { store: arranged.store },
      );
      const taken = await runAntiEnumeration(
        (svc) => svc.signUp({ username: "squat_me", email: VICTIM, password: PASSWORD }),
        { store: arranged.store },
      );
      const owner = arranged.owner;

      // The same answer: same fields, no session, the submitted address.
      const shape = (result: AuthResult) => ({
        keys: Arr.sort(Object.keys(result), Order.String),
        userKeys: Arr.sort(Object.keys(result.user), Order.String),
        session: result.session,
        method: result.method,
      });
      expect(shape(taken)).toEqual(shape(fresh));
      expect(fresh.identifier).toEqual({ type: "email", value: "fresh@example.com" });
      expect(taken.identifier).toEqual({ type: "email", value: VICTIM });
      expect(taken.user.id).not.toBe(owner.id);

      // The fresh sign-up claims its username; the stand-in claims none, so
      // neither the owner nor a phantom user holds "squat_me".
      expect(findIdentifier("username", "fresh_one")?.userId).toBe(fresh.user.id);
      expect(findIdentifier("username", "squat_me")).toBeNull();
      expect(
        [...identifierRecords.values()].filter((identifier) => identifier.userId === owner.id),
      ).toEqual([expect.objectContaining({ type: "email", value: VICTIM })]);

      // The username stays free for a real sign-up.
      const later = await runAntiEnumeration((svc) =>
        svc.signUp({ username: "squat_me", email: "later@example.com", password: PASSWORD }),
      );
      expect(findIdentifier("username", "squat_me")?.userId).toBe(later.user.id);
    },
  );

  it("a decorated EmailPasswordService that copies the result still claims no username for the stand-in", async () => {
    // A wrapper (tracing, auditing, …) that hands back a copy of the result
    // rather than the object `signUp` built.
    const copying = (service: typeof EmailPasswordService.Service) => ({
      ...service,
      signUp: (input: Parameters<typeof service.signUp>[0]) =>
        service
          .signUp(input)
          .pipe(Effect.map((result) => ({ ...result, user: { ...result.user } }))),
    });
    const owner = seedOwner(VICTIM);
    const fresh = await runAntiEnumeration(
      (svc) =>
        svc.signUp({ username: "fresh_one", email: "fresh@example.com", password: PASSWORD }),
      { decorate: copying },
    );
    const taken = await runAntiEnumeration(
      (svc) => svc.signUp({ username: "squat_me", email: VICTIM, password: PASSWORD }),
      { decorate: copying },
    );

    expect(taken.user.id).not.toBe(owner.id);
    expect(findIdentifier("username", "fresh_one")?.userId).toBe(fresh.user.id);
    expect(findIdentifier("username", "squat_me")).toBeNull();
  });

  it("a stand-in whose address has no holder by the check claims no username", async () => {
    // The owner's address is released between the stand-in answer and the
    // username claim, so the store reports no holder: the stand-in's id is
    // never stored, so the user store does not know it either.
    const owner = seedOwner(VICTIM);
    const releasing = (service: typeof EmailPasswordService.Service) => ({
      ...service,
      signUp: (input: Parameters<typeof service.signUp>[0]) =>
        service.signUp(input).pipe(
          Effect.tap(() =>
            Effect.sync(() => {
              const held = findIdentifier("email", VICTIM);
              if (held !== null) identifierRecords.delete(held.id);
            }),
          ),
        ),
    });
    const taken = await runAntiEnumeration(
      (svc) => svc.signUp({ username: "squat_me", email: VICTIM, password: PASSWORD }),
      { decorate: releasing },
    );

    expect(taken.user.id).not.toBe(owner.id);
    expect(findIdentifier("email", VICTIM)).toBeNull();
    expect(findIdentifier("username", "squat_me")).toBeNull();
  });

  it("a fresh sign-up whose identifier store has not caught up still claims its username", async () => {
    // A store whose email reads lag its writes (a cache of negative lookups)
    // reports no holder for the address the sign-up has just claimed; the
    // user store, which does know the new user, settles it.
    const lagging: typeof IdentifierStore.Service = {
      ...identifierStore,
      getByValue: (type, value) =>
        type === "email" ? Effect.succeed(null) : identifierStore.getByValue(type, value),
    };
    const fresh = await runAntiEnumeration(
      (svc) =>
        svc.signUp({ username: "fresh_one", email: "fresh@example.com", password: PASSWORD }),
      { identifiers: lagging },
    );

    expect(findIdentifier("email", "fresh@example.com")?.userId).toBe(fresh.user.id);
    expect(findIdentifier("username", "fresh_one")?.userId).toBe(fresh.user.id);
  });

  it("a username taken before sign-up fails the same way for a fresh or a taken address", async () => {
    await runAntiEnumeration((svc) =>
      svc.signUp({ username: "taken", email: "first@example.com", password: PASSWORD }),
    );
    seedOwner(VICTIM);
    const fresh = await runAntiEnumeration((svc) =>
      Effect.flip(
        svc.signUp({ username: "Taken", email: "fresh@example.com", password: PASSWORD }),
      ),
    );
    const taken = await runAntiEnumeration((svc) =>
      Effect.flip(svc.signUp({ username: "Taken", email: VICTIM, password: PASSWORD })),
    );
    expect(fresh).toEqual(new UsernameError({ message: "Username is already taken" }));
    expect(taken).toEqual(fresh);
  });

  it("a username taken during sign-up fails the same way for a fresh or a taken address", async () => {
    // The hasher stands in for a concurrent sign-up: hashing runs after the
    // username check on both paths, and it hands the username to someone else.
    const rival = seedOwner("rival@example.com");
    const racingHasher: typeof PasswordHasher.Service = {
      ...hasher,
      hash: (password) =>
        Effect.sync(() => {
          if (findIdentifier("username", "contested") === null) {
            const identifier = makeIdentifier({
              userId: rival.id,
              type: "username",
              value: "contested",
              verified: true,
            });
            identifierRecords.set(identifier.id, identifier);
          }
        }).pipe(Effect.andThen(hasher.hash(password))),
    };
    seedOwner(VICTIM);
    const fresh = await runAntiEnumeration(
      (svc) =>
        Effect.flip(
          svc.signUp({ username: "contested", email: "fresh@example.com", password: PASSWORD }),
        ),
      { hasher: racingHasher },
    );
    const contested = findIdentifier("username", "contested");
    assert(contested !== null, "the racing sign-up claimed the username");
    identifierRecords.delete(contested.id);

    const taken = await runAntiEnumeration(
      (svc) =>
        Effect.flip(svc.signUp({ username: "contested", email: VICTIM, password: PASSWORD })),
      { hasher: racingHasher },
    );
    expect(fresh).toEqual(new UsernameError({ message: "Username is already taken" }));
    expect(taken).toEqual(fresh);
    expect(findIdentifier("username", "contested")?.userId).toBe(rival.id);
  });
});
