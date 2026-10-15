import { describe, it, expect, beforeEach } from "vite-plus/test";
import { Context, Crypto, Effect } from "effect";
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

const magicLinkStore = {
  create: (token: MagicLinkToken) =>
    Effect.sync(() => {
      magicLinkTokens.set(token.token, token);
      return token;
    }),

  get: (token: string) => Effect.sync(() => magicLinkTokens.get(token) ?? null),

  getByEmail: (email: string) =>
    Effect.sync(() => {
      for (const token of magicLinkTokens.values()) {
        if (token.email === email) return token;
      }
      return null;
    }),

  delete: (token: string) =>
    Effect.sync(() => {
      magicLinkTokens.delete(token);
    }),

  deleteByEmail: (email: string) =>
    Effect.sync(() => {
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
    Context.make(SessionService, sessionManager),
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
    sentLinks.splice(0, sentLinks.length);
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

  it("should not send or store anything for unknown emails when sign-up is disabled", async () => {
    const testContext = await makeTestContext();

    const program = Effect.gen(function* () {
      const service = yield* MagicLink.make({
        disableSignUp: true,
        sendMagicLink: recordingSend,
      });
      yield* service.send("stranger@example.com");
    });

    // Anti-enumeration: succeeds silently.
    await Effect.runPromise(
      Effect.provide(program, testContext).pipe(Effect.provide(Hooks.Default)),
    );

    expect(sentLinks.length).toBe(0);
    expect(magicLinkTokens.size).toBe(0);
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MagicLinkError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MagicLinkError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MagicLinkError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("MagicLinkError");
    }
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
    if (result._tag === "Failure") {
      expect(result.failure._tag).toBe("ResendTooSoonError");
      expect((result.failure as { retryAfter: number }).retryAfter).toBeGreaterThan(0);
      expect((result.failure as { retryAfter: number }).retryAfter).toBeLessThanOrEqual(60_000);
    }
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
});
