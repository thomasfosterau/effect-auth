import { assert, describe, it, expect, beforeEach } from "vite-plus/test";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { memoryEmailPasswordStore } from "./testing/MemoryStores.ts";
import { Context, DateTime, Duration, Effect, Layer, MutableHashMap, Order, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import * as P from "effect/Predicate";
import { SecureRandom } from "effect/crypto";
import { Hooks } from "./Hooks.ts";
import * as PlatformCrypto from "./PlatformCrypto.ts";
import {
  type MagicLinkCreateUserInput,
  type MagicLinkToken,
  MagicLinkStore,
  MagicLinkUserStore,
} from "./MagicLink.ts";
import * as MagicLink from "./MagicLink.ts";
import {
  type Identifier,
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
} from "./Identifier.ts";
import { make, SessionService } from "./SessionService.ts";
import { SessionStore } from "./SessionStore.ts";
import { UserStore } from "./UserStore.ts";
import { hashToken } from "./TokenHash.ts";
import type { Session, User, SessionConfig } from "./Types.ts";
import { observable } from "./testing/Passwordless.ts";
import { inlineDeliveryScheduler } from "./testing/Delivery.ts";
import { authenticateGate } from "./testing/AuthenticateGate.ts";
import { RateLimitError } from "./Errors.ts";
import type { AuthenticateAttempt } from "./Hooks.ts";
import { looseCollationIdentifierStore } from "./testing/LooseCollation.ts";

/** The no-op hooks, with the detached sends run in place so a test reads them on return. */
const TestHooks = Layer.merge(Hooks.Default, inlineDeliveryScheduler);

// The `index`th item a test double recorded; a missing one fails the test.
const recorded = <A>(items: ReadonlyArray<A>, index = 0): A => {
  const item = items[index];
  assert(item !== undefined, `expected a recorded item at index ${index}`);
  return item;
};

const users = MutableHashMap.empty<string, User>();
const identifierRecords = MutableHashMap.empty<string, Identifier>();
const magicLinkTokens = MutableHashMap.empty<string, MagicLinkToken>();
const sessions = MutableHashMap.empty<string, Session>();
const sentLinks: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

const sessionStore = {
  create: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  get: (sessionId: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),

  update: (session: Session) =>
    Effect.sync(() => {
      MutableHashMap.set(sessions, session.id, session);
      return session;
    }),

  delete: (sessionId: string) =>
    Effect.sync(() => {
      MutableHashMap.remove(sessions, sessionId);
    }),

  deleteByUserId: (userId: string) =>
    Effect.sync(() => {
      MutableHashMap.forEach(sessions, (session, id) => {
        if (session.userId === userId) {
          MutableHashMap.remove(sessions, id);
        }
      });
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() =>
      Array.from(MutableHashMap.values(sessions)).filter((session) => session.userId === userId),
    ),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, userId))),
};

const addUser = (user: User) => {
  MutableHashMap.set(users, user.id, user);
};

/** Seed an email identifier the way the store would persist it. */
const addEmailIdentifier = (userId: string, email: string, verified: boolean) => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    ...(verified ? { verifiedAt: DateTime.toDateUtc(DateTime.nowUnsafe()) } : {}),
    now: DateTime.toDateUtc(DateTime.nowUnsafe()),
  });
  MutableHashMap.set(identifierRecords, identifier.id, identifier);
};

const findEmailIdentifier = (email: string): Identifier | null =>
  Array.from(MutableHashMap.values(identifierRecords)).find(
    (identifier) => identifier.type === "email" && identifier.value === email,
  ) ?? null;

const magicLinkUserStore = {
  createUser: (input: MagicLinkCreateUserInput) =>
    Effect.sync(() => {
      createdWith.push(input.identifier);
      const user: User = {
        id: `user-${MutableHashMap.size(users) + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
        attributes: {},
      };
      addUser(user);
      return { user, created: true };
    }),
};

/** The `identifier` each `createUser` call was given. */
const createdWith: Array<MagicLinkCreateUserInput["identifier"]> = [];

/** The name of each `MagicLinkStore` call, in order. */
const storeOps: string[] = [];

const magicLinkStore = {
  create: (token: MagicLinkToken) =>
    Effect.sync(() => {
      storeOps.push("create");
      MutableHashMap.set(magicLinkTokens, token.token, token);
      return token;
    }),

  get: (token: string) =>
    Effect.sync(() => {
      storeOps.push("get");
      return Option.getOrNull(MutableHashMap.get(magicLinkTokens, token));
    }),

  getByEmail: (email: string) =>
    Effect.sync(() => {
      storeOps.push("getByEmail");
      return Option.getOrNull(
        Arr.findFirst(MutableHashMap.values(magicLinkTokens), (token) => token.email === email),
      );
    }),

  delete: (token: string) =>
    Effect.sync(() => {
      storeOps.push("delete");
      MutableHashMap.remove(magicLinkTokens, token);
    }),

  deleteByEmail: (email: string) =>
    Effect.sync(() => {
      storeOps.push("deleteByEmail");
      MutableHashMap.forEach(magicLinkTokens, (magicLink, token) => {
        if (magicLink.email === email) {
          MutableHashMap.remove(magicLinkTokens, token);
        }
      });
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

/** Password hashes, so a test can see a first proof clear one (#440). */
const passwordHashes = MutableHashMap.empty<string, string>();
const emailPasswordStore = memoryEmailPasswordStore({
  users: MutableHashMap.empty(),
  passwordHashes,
});

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(TestHooks)),
  );

  return Context.merge(
    Context.merge(
      Context.make(SessionService, sessionManager),
      Context.make(EmailPasswordStore, emailPasswordStore),
    ),
    Context.merge(
      Context.merge(
        Context.make(MagicLinkStore, magicLinkStore),
        Context.make(MagicLinkUserStore, magicLinkUserStore),
      ),
      Context.merge(
        Context.merge(
          Context.make(IdentifierStore, identifierStore),
          Context.make(UserStore, userStore),
        ),
        Context.make(SecureRandom.SecureRandom, PlatformCrypto.instance),
      ),
    ),
  );
};

const recordingSend = (email: string, token: string) =>
  Effect.sync(() => {
    sentLinks.push({ email, token });
  });

describe("MagicLinkService", () => {
  beforeEach(() => {
    MutableHashMap.clear(users);
    MutableHashMap.clear(identifierRecords);
    MutableHashMap.clear(magicLinkTokens);
    MutableHashMap.clear(sessions);
    MutableHashMap.clear(passwordHashes);
    sentLinks.splice(0, sentLinks.length);
    storeOps.length = 0;
    createdWith.length = 0;
  });

  it("should store a token and send a magic link for a new email", async () => {
    const testContext = await makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("new@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(1);
    expect(sentLinks[0]?.email).toBe("new@example.com");
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);

    // The store is keyed by hash; the sent token is the raw value.
    const stored = Option.getOrUndefined(
      MutableHashMap.get(magicLinkTokens, hashToken(recorded(sentLinks).token)),
    );
    expect(stored).toBeDefined();
    expect(stored?.email).toBe("new@example.com");
    expect(stored?.expiresAt).toBeGreaterThan(DateTime.toEpochMillis(DateTime.nowUnsafe()));
  });

  it("should normalize the email before sending", async () => {
    const testContext = await makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("  Person@Example.COM  ");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(1);
    expect(sentLinks[0]?.email).toBe("person@example.com");
  });

  it("should invalidate outstanding tokens when a new link is requested", async () => {
    const testContext = await makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("repeat@example.com");
          yield* service.send("repeat@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(2);
    // Only the latest token remains usable. Compare by hash (store key).
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
    expect(MutableHashMap.has(magicLinkTokens, hashToken(recorded(sentLinks, 1).token))).toBe(true);
    expect(MutableHashMap.has(magicLinkTokens, hashToken(recorded(sentLinks).token))).toBe(false);
  });

  it("should not send to unknown emails when sign-up is disabled, storing a marker token", async () => {
    const testContext = await makeTestContext();

    // Anti-enumeration: succeeds without sending, and stores an undelivered
    // marker token as it would a link's (#417).
    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            disableSignUp: true,
            sendMagicLink: recordingSend,
          });
          yield* service.send("stranger@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(0);
    expect(
      Arr.fromIterable(MutableHashMap.values(magicLinkTokens)).map((token) => token.email),
    ).toEqual(["stranger@example.com"]);
  });

  // #417: without a cooldown, the unknown branch must do the store work the
  // known branch does, or its timing reveals the account.
  it("does the same store work to send to a known and an unknown email without a cooldown", async () => {
    const testContext = await makeTestContext();
    addUser({
      id: "user-member",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-member", "member@example.com", true);

    const { knownOps, unknownOps } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            disableSignUp: true,
            sendMagicLink: recordingSend,
          });
          yield* service.send("member@example.com");
          const knownOps = storeOps.splice(0);
          yield* service.send("missing@example.com");
          return { knownOps, unknownOps: storeOps.splice(0) };
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(unknownOps).toEqual(knownOps);
    expect(knownOps).toEqual(["deleteByEmail", "create"]);
    expect(sentLinks.map((sent) => sent.email)).toEqual(["member@example.com"]);
  });

  it("should send to existing users when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-existing",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-existing", "member@example.com", true);

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            disableSignUp: true,
            sendMagicLink: recordingSend,
          });
          yield* service.send("member@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(1);
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
  });

  it("should verify a token, create a user with a verified email identifier and a session", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("fresh@example.com");
          return yield* service.verify(recorded(sentLinks).token, {
            sessionAttributes: { device: "test" },
          });
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    // Magic link proves email ownership, so the new user's email identifier
    // is created verified.
    const identifier = findEmailIdentifier("fresh@example.com");
    expect(identifier?.userId).toBe(result.user.id);
    expect(identifier?.verified).toBe(true);
    // The store was handed the address to create the user with (#380).
    expect(createdWith).toEqual([
      { type: "email", value: "fresh@example.com", verified: true, verifiedAt: expect.any(Date) },
    ]);
    expect(result.session.userId).toBe(result.user.id);
    expect(result.session.attributes).toEqual({ device: "test" });
    expect(MutableHashMap.size(sessions)).toBe(1);
    // One-time use: token consumed.
    expect(MutableHashMap.size(magicLinkTokens)).toBe(0);
  });

  it("should sign in an existing user without creating a new one", async () => {
    const testContext = await makeTestContext();

    const existing: User = {
      id: "user-known",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    };
    addUser(existing);
    addEmailIdentifier("user-known", "known@example.com", false);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("known@example.com");
          return yield* service.verify(recorded(sentLinks).token);
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result.user.id).toBe("user-known");
    expect(MutableHashMap.size(users)).toBe(1);
    expect(result.session.userId).toBe("user-known");
    // The verified link proves ownership: the previously unverified email
    // identifier is promoted to verified.
    expect(findEmailIdentifier("known@example.com")?.verified).toBe(true);
  });

  it("never signs a look-alike address into the account a loose store matches it to (#602)", async () => {
    const testContext = await makeTestContext();
    addUser({
      id: "user-bob",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-bob", "bob@example.com", true);

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          // The attacker holds `exämple.com`; a case- and accent-insensitive
          // store answers its lookups with Bob's record.
          yield* service.send("bob@exämple.com");
          return yield* service.verify(recorded(sentLinks).token);
        }).pipe(
          Effect.provideService(IdentifierStore, looseCollationIdentifierStore(identifierRecords)),
        ),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.map((sent) => sent.email)).toEqual(["bob@exämple.com"]);
    // The link signs in a new account for the look-alike, never Bob's.
    expect(result.user.id).not.toBe("user-bob");
    expect(findEmailIdentifier("bob@exämple.com")?.userId).toBe(result.user.id);
    expect(findEmailIdentifier("bob@example.com")?.userId).toBe("user-bob");
  });

  it("runs beforeAuthenticate with the resolved user before the link is spent (#592)", async () => {
    const testContext = await makeTestContext();
    addUser({
      id: "user-gated",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-gated", "gated@example.com", true);
    const seen: Array<AuthenticateAttempt> = [];

    const refused = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("gated@example.com");
          return yield* Effect.flip(service.verify(recorded(sentLinks).token));
        }),
        testContext,
      ).pipe(Effect.provide(authenticateGate(seen, true))),
    );

    expect(refused).toBeInstanceOf(RateLimitError);
    expect(seen).toEqual([
      {
        method: "magic-link",
        identifier: { type: "email", value: "gated@example.com" },
        userId: "user-gated",
      },
    ]);
    // Refused before the link was spent: it still works once the gate opens.
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("clears a squatter's password and sessions on the address's first proof (#440)", async () => {
    const testContext = await makeTestContext();

    // A squatter signed up with the address and a password they know, and
    // holds a session; the address was never verified.
    addUser({
      id: "user-squat",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-squat", "victim@example.com", false);
    MutableHashMap.set(passwordHashes, "user-squat", "squatter-hash");
    const now = DateTime.toDateUtc(DateTime.nowUnsafe());
    MutableHashMap.set(sessions, "squatter-session", {
      id: "squatter-session",
      userId: "user-squat",
      expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 3_600_000)),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("victim@example.com");
          return yield* service.verify(recorded(sentLinks).token);
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    // The holder of the address is signed in; the squatter's password and
    // session are gone, so only the session just issued remains.
    expect(result.user.id).toBe("user-squat");
    expect(MutableHashMap.has(passwordHashes, "user-squat")).toBe(false);
    expect(MutableHashMap.has(sessions, "squatter-session")).toBe(false);
    expect(
      Arr.fromIterable(MutableHashMap.values(sessions)).map((session) => session.userId),
    ).toEqual(["user-squat"]);
    expect(findEmailIdentifier("victim@example.com")?.verified).toBe(true);
  });

  it("keeps the password and sessions of an account whose address is already verified (#440)", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-owner",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-owner", "victim@example.com", true);
    MutableHashMap.set(passwordHashes, "user-owner", "owner-hash");

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("victim@example.com");
          return yield* service.verify(recorded(sentLinks).token);
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(Option.getOrUndefined(MutableHashMap.get(passwordHashes, "user-owner"))).toBe(
      "owner-hash",
    );
  });

  it("should reject expired tokens and delete them", async () => {
    const testContext = await makeTestContext();

    // Seed with the hash as key (the service looks up by hash).
    MutableHashMap.set(magicLinkTokens, hashToken("expired-token"), {
      token: hashToken("expired-token"),
      email: "late@example.com",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 10 * 60 * 1000,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 60 * 1000,
    });

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          return yield* Effect.result(service.verify("expired-token"));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    expect(MutableHashMap.size(magicLinkTokens)).toBe(0);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("should reject replayed tokens (one-time use)", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("once@example.com");
          const token = recorded(sentLinks).token;
          yield* service.verify(token);
          return yield* Effect.result(service.verify(token));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    // Only the first verification created a session.
    expect(MutableHashMap.size(sessions)).toBe(1);
  });

  it("should fail for unknown tokens", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          return yield* Effect.result(service.verify("missing-token"));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
  });

  it("should not create users at verification when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    MutableHashMap.set(magicLinkTokens, hashToken("orphan-token"), {
      token: hashToken("orphan-token"),
      email: "orphan@example.com",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()),
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 60 * 1000,
    });

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            disableSignUp: true,
            sendMagicLink: recordingSend,
          });
          return yield* Effect.result(service.verify("orphan-token"));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    expect(MutableHashMap.size(users)).toBe(0);
    expect(MutableHashMap.size(identifierRecords)).toBe(0);
    expect(MutableHashMap.size(sessions)).toBe(0);
  });

  it("should fail with ResendTooSoonError when a resend is within the cooldown window", async () => {
    const testContext = await makeTestContext();

    const result = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            sendMagicLink: recordingSend,
            resendCooldown: 60_000,
          });
          yield* service.send("user@example.com");
          return yield* Effect.result(service.send("user@example.com"));
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("ResendTooSoonError");
    assert(result.failure._tag === "ResendTooSoonError");
    expect(Duration.toMillis(result.failure.retryAfter)).toBeGreaterThan(0);
    expect(Duration.toMillis(result.failure.retryAfter)).toBeLessThanOrEqual(60_000);
    // The original token is preserved — no replacement was issued.
    expect(sentLinks.length).toBe(1);
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
  });

  it("should allow a resend after the cooldown window has elapsed", async () => {
    const testContext = await makeTestContext();

    // Seed a token whose createdAt is older than the 60 s cooldown.
    const oldToken = hashToken("old-magic-token");
    MutableHashMap.set(magicLinkTokens, oldToken, {
      token: oldToken,
      email: "user@example.com",
      createdAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 70_000,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) + 5 * 60 * 1000,
    });

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            sendMagicLink: recordingSend,
            resendCooldown: 60_000,
          });
          yield* service.send("user@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    // A fresh link was issued after the cooldown elapsed.
    expect(sentLinks.length).toBe(1);
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
    // The old token was replaced.
    expect(MutableHashMap.has(magicLinkTokens, oldToken)).toBe(false);
  });

  it("should not apply the cooldown when resendCooldown is not configured", async () => {
    const testContext = await makeTestContext();

    await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          // No resendCooldown: default behavior — immediate resend always succeeds.
          const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
          yield* service.send("repeat@example.com");
          yield* service.send("repeat@example.com");
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(sentLinks.length).toBe(2);
    expect(MutableHashMap.size(magicLinkTokens)).toBe(1);
  });

  // #415: with sign-up disabled, an unknown email must hit the cooldown exactly
  // as a known one does, or the second request's answer reveals the account.
  it("answers a known and an unknown email alike within the cooldown when sign-up is disabled", async () => {
    const testContext = await makeTestContext();
    addUser({
      id: "user-member",
      createdAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      updatedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      attributes: {},
    });
    addEmailIdentifier("user-member", "member@example.com", true);

    const { known, unknown } = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const service = yield* MagicLink.make({
            disableSignUp: true,
            resendCooldown: 60_000,
            sendMagicLink: recordingSend,
          });
          const twice = (email: string) =>
            Effect.all([Effect.result(service.send(email)), Effect.result(service.send(email))], {
              concurrency: 1,
            });
          return {
            known: yield* twice("member@example.com"),
            unknown: yield* twice("missing@example.com"),
          };
        }),
        testContext,
      ).pipe(Effect.provide(TestHooks)),
    );

    expect(unknown.map(observable)).toEqual(known.map(observable));
    expect(known.map(observable)).toEqual([
      { _tag: "Success" },
      {
        _tag: "Failure",
        error: "ResendTooSoonError",
        message: "Please wait before requesting another magic link",
      },
    ]);
    Arr.forEach([known[1], unknown[1]], (result) => {
      expect(result._tag).toBe("Failure");
      assert(Result.isFailure(result));
      assert(P.isTagged(result.failure, "ResendTooSoonError"));
      expect(Duration.toMillis(result.failure.retryAfter)).toBeGreaterThan(0);
      expect(Duration.toMillis(result.failure.retryAfter)).toBeLessThanOrEqual(60_000);
    });
    // Only the account holder is sent a link; the unknown email holds an
    // undelivered token as its cooldown marker.
    expect(sentLinks.map((link) => link.email)).toEqual(["member@example.com"]);
    expect(
      Arr.sort(
        Array.from(MutableHashMap.values(magicLinkTokens), (token) => token.email),
        Order.String,
      ),
    ).toEqual(["member@example.com", "missing@example.com"]);
    expect(MutableHashMap.size(users)).toBe(1);
  });
});
