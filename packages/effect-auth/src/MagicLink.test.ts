import { describe, it, expect, beforeEach } from "vite-plus/test";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { memoryEmailPasswordStore } from "./testing/MemoryStores.ts";
import { Array as Arr, Context, Crypto, Effect, Order, Predicate, Result } from "effect";
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

const users = new Map<string, User>();
const identifierRecords = new Map<string, Identifier>();
const magicLinkTokens = new Map<string, MagicLinkToken>();
const sessions = new Map<string, Session>();
const sentLinks: Array<{ email: string; token: string }> = [];

const identifierStore = memoryIdentifierStore(identifierRecords);

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
        if (session.userId === userId) {
          sessions.delete(id);
        }
      }
    }),

  listByUserId: (userId: string) =>
    Effect.sync(() => Array.from(sessions.values()).filter((session) => session.userId === userId)),
};

const userStore = {
  get: (userId: string) => Effect.sync(() => users.get(userId) ?? null),
};

const addUser = (user: User) => {
  users.set(user.id, user);
};

/** Seed an email identifier the way the store would persist it. */
const addEmailIdentifier = (userId: string, email: string, verified: boolean) => {
  const identifier = makeIdentifier({
    userId,
    type: "email",
    value: email,
    verified,
    ...(verified ? { verifiedAt: new Date() } : {}),
  });
  identifierRecords.set(identifier.id, identifier);
};

const findEmailIdentifier = (email: string): Identifier | null =>
  Array.from(identifierRecords.values()).find(
    (identifier) => identifier.type === "email" && identifier.value === email,
  ) ?? null;

const magicLinkUserStore = {
  createUser: (input: MagicLinkCreateUserInput) =>
    Effect.sync(() => {
      createdWith.push(input.identifier);
      const user: User = {
        id: `user-${users.size + 1}`,
        ...(input.name !== undefined && { name: input.name }),
        createdAt: new Date(),
        updatedAt: new Date(),
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
      magicLinkTokens.set(token.token, token);
      return token;
    }),

  get: (token: string) =>
    Effect.sync(() => {
      storeOps.push("get");
      return magicLinkTokens.get(token) ?? null;
    }),

  getByEmail: (email: string) =>
    Effect.sync(() => {
      storeOps.push("getByEmail");
      for (const token of magicLinkTokens.values()) {
        if (token.email === email) return token;
      }
      return null;
    }),

  delete: (token: string) =>
    Effect.sync(() => {
      storeOps.push("delete");
      magicLinkTokens.delete(token);
    }),

  deleteByEmail: (email: string) =>
    Effect.sync(() => {
      storeOps.push("deleteByEmail");
      for (const [token, magicLink] of magicLinkTokens.entries()) {
        if (magicLink.email === email) {
          magicLinkTokens.delete(token);
        }
      }
    }),
};

const sessionConfig: SessionConfig = {
  sessionExpiresIn: {
    activePeriod: 1000 * 60 * 60 * 24,
    idlePeriod: 1000 * 60 * 60 * 12,
  },
};

/** Password hashes, so a test can see a first proof clear one (#440). */
const passwordHashes = new Map<string, string>();
const emailPasswordStore = memoryEmailPasswordStore({ users: new Map(), passwordHashes });

const makeTestContext = async () => {
  const sessionManager = await Effect.runPromise(
    Effect.provide(
      make(sessionConfig),
      Context.merge(
        Context.merge(Context.make(SessionStore, sessionStore), Context.make(UserStore, userStore)),
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
      ),
    ).pipe(Effect.provide(Hooks.Default)),
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
        Context.make(Crypto.Crypto, PlatformCrypto.instance),
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
    users.clear();
    identifierRecords.clear();
    magicLinkTokens.clear();
    sessions.clear();
    passwordHashes.clear();
    sentLinks.splice(0, sentLinks.length);
    storeOps.length = 0;
    createdWith.length = 0;
  });

  it("should store a token and send a magic link for a new email", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("new@example.com");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(1);
    expect(sentLinks[0]?.email).toBe("new@example.com");
    expect(magicLinkTokens.size).toBe(1);

    // The store is keyed by hash; the sent token is the raw value.
    const stored = magicLinkTokens.get(hashToken(sentLinks[0]!.token));
    expect(stored).toBeDefined();
    expect(stored?.email).toBe("new@example.com");
    expect(stored?.expiresAt).toBeGreaterThan(Date.now());
  });

  it("should normalize the email before sending", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("  Person@Example.COM  ");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(1);
    expect(sentLinks[0]?.email).toBe("person@example.com");
  });

  it("should invalidate outstanding tokens when a new link is requested", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("repeat@example.com");
      yield* service.send("repeat@example.com");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(2);
    // Only the latest token remains usable. Compare by hash (store key).
    expect(magicLinkTokens.size).toBe(1);
    expect(magicLinkTokens.has(hashToken(sentLinks[1]!.token))).toBe(true);
    expect(magicLinkTokens.has(hashToken(sentLinks[0]!.token))).toBe(false);
  });

  it("should not send to unknown emails when sign-up is disabled, storing a marker token", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        disableSignUp: true,
        sendMagicLink: recordingSend,
      });
      yield* service.send("stranger@example.com");
    });

    // Anti-enumeration: succeeds without sending, and stores an undelivered
    // marker token as it would a link's (#417).
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(0);
    expect([...magicLinkTokens.values()].map((token) => token.email)).toEqual([
      "stranger@example.com",
    ]);
  });

  // #417: without a cooldown, the unknown branch must do the store work the
  // known branch does, or its timing reveals the account.
  it("does the same store work to send to a known and an unknown email without a cooldown", async () => {
    const testContext = await makeTestContext();
    addUser({ id: "user-member", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-member", "member@example.com", true);

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ disableSignUp: true, sendMagicLink: recordingSend });
      yield* service.send("member@example.com");
      const knownOps = storeOps.splice(0);
      yield* service.send("missing@example.com");
      return { knownOps, unknownOps: storeOps.splice(0) };
    });

    const { knownOps, unknownOps } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(unknownOps).toEqual(knownOps);
    expect(knownOps).toEqual(["deleteByEmail", "create"]);
    expect(sentLinks.map((sent) => sent.email)).toEqual(["member@example.com"]);
  });

  it("should send to existing users when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    addUser({
      id: "user-existing",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    });
    addEmailIdentifier("user-existing", "member@example.com", true);

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        disableSignUp: true,
        sendMagicLink: recordingSend,
      });
      yield* service.send("member@example.com");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(1);
    expect(magicLinkTokens.size).toBe(1);
  });

  it("should verify a token, create a user with a verified email identifier and a session", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("fresh@example.com");
      return yield* service.verify(sentLinks[0]!.token, {
        sessionAttributes: { device: "test" },
      });
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
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
    expect(sessions.size).toBe(1);
    // One-time use: token consumed.
    expect(magicLinkTokens.size).toBe(0);
  });

  it("should sign in an existing user without creating a new one", async () => {
    const testContext = await makeTestContext();

    const existing: User = {
      id: "user-known",
      createdAt: new Date(),
      updatedAt: new Date(),
      attributes: {},
    };
    addUser(existing);
    addEmailIdentifier("user-known", "known@example.com", false);

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("known@example.com");
      return yield* service.verify(sentLinks[0]!.token);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result.user.id).toBe("user-known");
    expect(users.size).toBe(1);
    expect(result.session.userId).toBe("user-known");
    // The verified link proves ownership: the previously unverified email
    // identifier is promoted to verified.
    expect(findEmailIdentifier("known@example.com")?.verified).toBe(true);
  });

  it("clears a squatter's password and sessions on the address's first proof (#440)", async () => {
    const testContext = await makeTestContext();

    // A squatter signed up with the address and a password they know, and
    // holds a session; the address was never verified.
    addUser({ id: "user-squat", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-squat", "victim@example.com", false);
    passwordHashes.set("user-squat", "squatter-hash");
    const now = new Date();
    sessions.set("squatter-session", {
      id: "squatter-session",
      userId: "user-squat",
      expiresAt: new Date(now.getTime() + 3_600_000),
      createdAt: now,
      lastActivityAt: now,
      attributes: {},
    });

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("victim@example.com");
      return yield* service.verify(sentLinks[0]!.token);
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // The holder of the address is signed in; the squatter's password and
    // session are gone, so only the session just issued remains.
    expect(result.user.id).toBe("user-squat");
    expect(passwordHashes.has("user-squat")).toBe(false);
    expect(sessions.has("squatter-session")).toBe(false);
    expect([...sessions.values()].map((session) => session.userId)).toEqual(["user-squat"]);
    expect(findEmailIdentifier("victim@example.com")?.verified).toBe(true);
  });

  it("keeps the password and sessions of an account whose address is already verified (#440)", async () => {
    const testContext = await makeTestContext();

    addUser({ id: "user-owner", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-owner", "victim@example.com", true);
    passwordHashes.set("user-owner", "owner-hash");

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("victim@example.com");
      return yield* service.verify(sentLinks[0]!.token);
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(passwordHashes.get("user-owner")).toBe("owner-hash");
  });

  it("should reject expired tokens and delete them", async () => {
    const testContext = await makeTestContext();

    // Seed with the hash as key (the service looks up by hash).
    magicLinkTokens.set(hashToken("expired-token"), {
      token: hashToken("expired-token"),
      email: "late@example.com",
      createdAt: Date.now() - 10 * 60 * 1000,
      expiresAt: Date.now() - 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      return yield* Effect.result(service.verify("expired-token"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    expect(magicLinkTokens.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should reject replayed tokens (one-time use)", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("once@example.com");
      const token = sentLinks[0]!.token;
      yield* service.verify(token);
      return yield* Effect.result(service.verify(token));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    // Only the first verification created a session.
    expect(sessions.size).toBe(1);
  });

  it("should fail for unknown tokens", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      return yield* Effect.result(service.verify("missing-token"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
  });

  it("should not create users at verification when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    magicLinkTokens.set(hashToken("orphan-token"), {
      token: hashToken("orphan-token"),
      email: "orphan@example.com",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        disableSignUp: true,
        sendMagicLink: recordingSend,
      });
      return yield* Effect.result(service.verify("orphan-token"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("MagicLinkError");
    expect(users.size).toBe(0);
    expect(identifierRecords.size).toBe(0);
    expect(sessions.size).toBe(0);
  });

  it("should fail with ResendTooSoonError when a resend is within the cooldown window", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        sendMagicLink: recordingSend,
        resendCooldown: 60_000,
      });
      yield* service.send("user@example.com");
      return yield* Effect.result(service.send("user@example.com"));
    });

    const result = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(result._tag).toBe("Failure");
    assert(Result.isFailure(result));
    expect(result.failure._tag).toBe("ResendTooSoonError");
    expect((result.failure as { retryAfter: number }).retryAfter).toBeGreaterThan(0);
    expect((result.failure as { retryAfter: number }).retryAfter).toBeLessThanOrEqual(60_000);
    // The original token is preserved — no replacement was issued.
    expect(sentLinks.length).toBe(1);
    expect(magicLinkTokens.size).toBe(1);
  });

  it("should allow a resend after the cooldown window has elapsed", async () => {
    const testContext = await makeTestContext();

    // Seed a token whose createdAt is older than the 60 s cooldown.
    const oldToken = hashToken("old-magic-token");
    magicLinkTokens.set(oldToken, {
      token: oldToken,
      email: "user@example.com",
      createdAt: Date.now() - 70_000,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        sendMagicLink: recordingSend,
        resendCooldown: 60_000,
      });
      yield* service.send("user@example.com");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    // A fresh link was issued after the cooldown elapsed.
    expect(sentLinks.length).toBe(1);
    expect(magicLinkTokens.size).toBe(1);
    // The old token was replaced.
    expect(magicLinkTokens.has(oldToken)).toBe(false);
  });

  it("should not apply the cooldown when resendCooldown is not configured", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      // No resendCooldown: default behavior — immediate resend always succeeds.
      const service = yield* MagicLink.make({ sendMagicLink: recordingSend });
      yield* service.send("repeat@example.com");
      yield* service.send("repeat@example.com");
    });

    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(2);
    expect(magicLinkTokens.size).toBe(1);
  });

  // #415: with sign-up disabled, an unknown email must hit the cooldown exactly
  // as a known one does, or the second request's answer reveals the account.
  it("answers a known and an unknown email alike within the cooldown when sign-up is disabled", async () => {
    const testContext = await makeTestContext();
    addUser({ id: "user-member", createdAt: new Date(), updatedAt: new Date(), attributes: {} });
    addEmailIdentifier("user-member", "member@example.com", true);

    const program = Effect.gen(function* () {
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
    });

    const { known, unknown } = await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
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
    for (const result of [known[1], unknown[1]]) {
      expect(result._tag).toBe("Failure");
      assert(Result.isFailure(result));
      assert(Predicate.isTagged(result.failure, "ResendTooSoonError"));
      expect(result.failure.retryAfter).toBeGreaterThan(0);
      expect(result.failure.retryAfter).toBeLessThanOrEqual(60_000);
    }
    // Only the account holder is sent a link; the unknown email holds an
    // undelivered token as its cooldown marker.
    expect(sentLinks.map((link) => link.email)).toEqual(["member@example.com"]);
    expect(
      Arr.sort(
        Array.from(magicLinkTokens.values(), (token) => token.email),
        Order.String,
      ),
    ).toEqual(["member@example.com", "missing@example.com"]);
    expect(users.size).toBe(1);
  });
});
