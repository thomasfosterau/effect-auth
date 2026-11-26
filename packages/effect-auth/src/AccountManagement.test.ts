import { sha256Hex } from "./testing/Sha256.ts";
import { assert, describe, it, expect } from "vite-plus/test";
import { DateTime, Effect, Layer, MutableHashMap, Order } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import {
  AccountManagementService,
  AccountManagementStore,
  AccountTokenError,
  type AccountToken,
} from "./AccountManagement.ts";
import {
  AuthError,
  EmailInUseError,
  InvalidCredentialsError,
  ReauthenticationRequiredError,
} from "./Errors.ts";
import { EmailPasswordStore } from "./email/EmailPassword.ts";
import { MultiAlgorithmVerifier, PasswordHasher, pbkdf2Hasher } from "./password/Password.ts";
import { scryptHasher } from "./password/Scrypt.ts";
import {
  IdentifierStore,
  makeIdentifier,
  memoryIdentifierStore,
  type Identifier,
} from "./Identifier.ts";
import { UserServiceStore } from "./User.ts";
import { SessionService } from "./SessionService.ts";
import type * as Types from "./Types.ts";

interface Harness {
  readonly layer: Layer.Layer<
    | AccountManagementService
    | AccountManagementStore
    | UserServiceStore
    | IdentifierStore
    | SessionService
  >;
  readonly users: MutableHashMap.MutableHashMap<string, Types.User>;
  readonly identifiers: MutableHashMap.MutableHashMap<string, Identifier>;
  readonly tokens: MutableHashMap.MutableHashMap<string, AccountToken>;
  readonly revoked: string[];
  readonly changeEmails: Array<{ newEmail: string; token: string }>;
  readonly deleteSends: Array<{ email: string | null; token: string }>;
  readonly beforeDeleteCalls: string[];
  readonly notifiedOld: Array<{ oldEmail: string | null; newEmail: string }>;
  readonly notices: Array<{ oldEmail: string; newEmail: string }>;
}

interface HarnessOptions {
  /** Password hashes by user id: provides an `EmailPasswordStore` and a `PasswordHasher`. */
  readonly passwordHashes?: Readonly<Record<string, string>>;
  /** Hashers a `MultiAlgorithmVerifier` accepts, beside the `PasswordHasher`. */
  readonly legacyHashers?: ReadonlyArray<typeof PasswordHasher.Service>;
  readonly sendEmailChangeNotice?: () => Effect.Effect<void, AuthError>;
}

/** A session of `userId` created `minutesAgo` minutes ago. */
const sessionFor = (userId: string, minutesAgo = 0, attributes = {}): Types.Session => {
  const createdAt = DateTime.subtract(DateTime.nowUnsafe(), { minutes: minutesAgo });
  return {
    id: `session-${userId}`,
    userId,
    createdAt: DateTime.toDateUtc(createdAt),
    lastActivityAt: DateTime.toDateUtc(createdAt),
    expiresAt: DateTime.toDateUtc(DateTime.add(createdAt, { days: 1 })),
    attributes,
  };
};

/** A passwordless account's proof: a session it signed in on just now. */
const signedIn = (userId: string) => ({ session: sessionFor(userId) });

const makeUser = (id: string): Types.User => {
  const now = DateTime.toDateUtc(DateTime.nowUnsafe());
  return {
    id,
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
};

const hasher = scryptHasher({ cost: 16384 });
const PASSWORD = "correct horse battery staple";
const hashOf = (password: string, with_ = hasher) =>
  Effect.runPromise(Effect.map(with_.hash(password), (result) => result.hash));

const passwordLayer = (options: HarnessOptions): Layer.Layer<never> => {
  const hashes = options.passwordHashes;
  if (hashes === undefined) return Layer.empty;
  const store: typeof EmailPasswordStore.Service = {
    createUser: () => Effect.die("unused"),
    getPasswordHash: (userId) => Effect.succeed(Option.fromNullishOr(hashes[userId] ?? null)),
    setPasswordHash: () => Effect.die("unused"),
    clearPasswordHash: () => Effect.die("unused"),
  };
  const verifier =
    options.legacyHashers === undefined
      ? Layer.empty
      : MultiAlgorithmVerifier.layer([...options.legacyHashers, hasher]);
  return Layer.mergeAll(
    Layer.succeed(EmailPasswordStore)(store),
    Layer.succeed(PasswordHasher)(hasher),
    verifier,
  );
};

/**
 * Wraps the identifier store for a test: `records` is the live map the store
 * writes to, so a wrapper can simulate a concurrent claim by writing to it.
 */
type WrapIdentifiers = (
  store: typeof IdentifierStore.Service,
  records: MutableHashMap.MutableHashMap<string, Identifier>,
) => typeof IdentifierStore.Service;

const makeHarness = (wrap?: WrapIdentifiers, options: HarnessOptions = {}): Harness => {
  const users = MutableHashMap.empty<string, Types.User>();
  const identifiers = MutableHashMap.empty<string, Identifier>();
  const tokens = MutableHashMap.empty<string, AccountToken>();
  const revoked: string[] = [];
  const changeEmails: Array<{ newEmail: string; token: string }> = [];
  const deleteSends: Array<{ email: string | null; token: string }> = [];
  const beforeDeleteCalls: string[] = [];
  const notifiedOld: Array<{ oldEmail: string | null; newEmail: string }> = [];
  const notices: Array<{ oldEmail: string; newEmail: string }> = [];

  const addUser = (user: Types.User, email: string) => {
    MutableHashMap.set(users, user.id, user);
    const identifier = makeIdentifier({
      userId: user.id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: DateTime.toDateUtc(DateTime.nowUnsafe()),
      now: DateTime.toDateUtc(DateTime.nowUnsafe()),
    });
    MutableHashMap.set(identifiers, identifier.id, identifier);
  };
  addUser(makeUser("user-1"), "alice@example.com");
  addUser(makeUser("user-2"), "bob@example.com");

  const userStore: typeof UserServiceStore.Service = {
    get: (userId) => Effect.sync(() => MutableHashMap.get(users, userId)),
    update: (user) =>
      Effect.sync(() => {
        MutableHashMap.set(users, user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void MutableHashMap.remove(users, userId)),
  };

  const tokenStore: typeof AccountManagementStore.Service = {
    create: (token) =>
      Effect.sync(() => {
        MutableHashMap.set(tokens, token.token, token);
        return token;
      }),
    get: (token) => Effect.sync(() => MutableHashMap.get(tokens, token)),
    delete: (token) => Effect.sync(() => void MutableHashMap.remove(tokens, token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        MutableHashMap.forEach(tokens, (rec, t) => {
          if (rec.userId === userId) MutableHashMap.remove(tokens, t);
        });
      }),
  };

  // Minimal SessionService: only `invalidateUserSessions` is exercised.
  const sessionManager: typeof SessionService.Service = {
    createSession: () => Effect.die("unused"),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: (userId) => Effect.sync(() => void revoked.push(userId)),
    listSessions: () => Effect.succeed([]),
    revokeSessionById: () => Effect.succeed(false),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const layer = AccountManagementService.layer({
    sendChangeEmailVerification: ({ newEmail, token }) =>
      Effect.sync(() => void changeEmails.push({ newEmail, token })),
    sendEmailChangeNotice: ({ oldEmail, newEmail }) =>
      (options.sendEmailChangeNotice?.() ?? Effect.void).pipe(
        Effect.tap(() => Effect.sync(() => void notices.push({ oldEmail, newEmail }))),
      ),
    sendDeleteAccountVerification: ({ email, token }) =>
      Effect.sync(() => void deleteSends.push({ email, token })),
    beforeDelete: (user) => Effect.sync(() => void beforeDeleteCalls.push(user.id)),
    notifyEmailChanged: ({ oldEmail, newEmail }) =>
      Effect.sync(() => void notifiedOld.push({ oldEmail, newEmail })),
  }).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        Layer.succeed(UserServiceStore)(userStore),
        Layer.succeed(IdentifierStore)(
          wrap === undefined
            ? memoryIdentifierStore(identifiers)
            : wrap(memoryIdentifierStore(identifiers), identifiers),
        ),
        Layer.succeed(AccountManagementStore)(tokenStore),
        Layer.succeed(SessionService)(sessionManager),
        passwordLayer(options),
      ),
    ),
  );

  return {
    layer,
    users,
    identifiers,
    tokens,
    revoked,
    changeEmails,
    deleteSends,
    beforeDeleteCalls,
    notifiedOld,
    notices,
  };
};

const run = <A, E>(
  h: Harness,
  f: (
    svc: typeof AccountManagementService.Service,
  ) => Effect.Effect<
    A,
    E,
    AccountManagementStore | UserServiceStore | IdentifierStore | SessionService
  >,
) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* AccountManagementService;
      return yield* f(svc);
    }).pipe(Effect.provide(h.layer)),
  );

describe("AccountManagement — change email", () => {
  it("swaps the email and marks it verified on confirm (happy path)", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", "ALICE-NEW@example.com", signedIn("user-1")),
    );
    expect(h.changeEmails).toHaveLength(1);
    expect(h.changeEmails[0]?.newEmail).toBe("alice-new@example.com");

    const { user } = await run(h, (svc) => svc.confirmEmailChange(token));
    expect(user.id).toBe("user-1");
    // The old email identifier is gone; the new one belongs to the user and is verified.
    const userEmails = Arr.fromIterable(MutableHashMap.values(h.identifiers)).filter(
      (identifier) => identifier.userId === "user-1" && identifier.type === "email",
    );
    expect(userEmails).toHaveLength(1);
    expect(userEmails[0]?.value).toBe("alice-new@example.com");
    expect(userEmails[0]?.verified).toBe(true);
    expect(
      Arr.fromIterable(MutableHashMap.values(h.identifiers)).some(
        (identifier) => identifier.value === "alice@example.com",
      ),
    ).toBe(false);
    // Sessions revoked on email change (default).
    expect(h.revoked).toContain("user-1");
    // Old address notified.
    expect(h.notifiedOld).toEqual([
      { oldEmail: "alice@example.com", newEmail: "alice-new@example.com" },
    ]);
  });

  it("rejects a target email already in use by another account", async () => {
    const h = makeHarness();
    const err = await run(h, (svc) =>
      Effect.flip(svc.requestEmailChange("user-1", "bob@example.com", signedIn("user-1"))),
    );
    expect(err).toBeInstanceOf(EmailInUseError);
    expect(h.changeEmails).toHaveLength(0);
    expect(MutableHashMap.size(h.tokens)).toBe(0);
  });

  it("consumes the token on first confirm (single use)", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", "alice2@example.com", signedIn("user-1")),
    );
    await run(h, (svc) => svc.confirmEmailChange(token));
    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
  });

  it("stores the token's digest, never the token", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", "alice4@example.com", signedIn("user-1")),
    );
    expect(MutableHashMap.has(h.tokens, token)).toBe(false);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
  });

  it("rejects an expired token", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", "alice3@example.com", signedIn("user-1")),
    );
    // Force expiry.
    const rec = Option.getOrUndefined(MutableHashMap.get(h.tokens, sha256Hex(token)));
    assert(rec !== undefined, "the change-email token is stored");

    MutableHashMap.set(h.tokens, sha256Hex(token), {
      ...rec,
      expiresAt: DateTime.toEpochMillis(DateTime.nowUnsafe()) - 1,
    });
    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
  });
});

describe("AccountManagement — change email: re-authentication", () => {
  const withPassword = async (extra: Partial<HarnessOptions> = {}) =>
    makeHarness(undefined, {
      passwordHashes: { "user-1": await hashOf(PASSWORD) },
      ...extra,
    });
  const nothingSent = (h: Harness) => {
    expect(h.notices).toEqual([]);
    expect(h.changeEmails).toEqual([]);
    expect(MutableHashMap.size(h.tokens)).toBe(0);
  };

  it("an account with a password must give it, even on a fresh session", async () => {
    const h = await withPassword();
    const err = await run(h, (svc) =>
      Effect.flip(svc.requestEmailChange("user-1", "new@example.com", signedIn("user-1"))),
    );
    expect(err).toBeInstanceOf(ReauthenticationRequiredError);
    expect(err.code).toBe("REAUTHENTICATION_REQUIRED");
    nothingSent(h);
  });

  it("a wrong password is refused and sends nothing", async () => {
    const h = await withPassword();
    const err = await run(h, (svc) =>
      Effect.flip(
        svc.requestEmailChange("user-1", "new@example.com", { currentPassword: "wrong password" }),
      ),
    );
    expect(err).toBeInstanceOf(InvalidCredentialsError);
    nothingSent(h);
  });

  it("the right password starts the change, whatever the session's age", async () => {
    const h = await withPassword();
    await run(h, (svc) =>
      svc.requestEmailChange("user-1", "new@example.com", {
        currentPassword: PASSWORD,
        session: sessionFor("user-1", 600),
      }),
    );
    expect(h.changeEmails.map((sent) => sent.newEmail)).toEqual(["new@example.com"]);
  });

  it("a password hashed by a previous hasher verifies through MultiAlgorithmVerifier", async () => {
    const legacy = pbkdf2Hasher({ iterations: 1000 });
    const h = makeHarness(undefined, {
      passwordHashes: { "user-1": await hashOf(PASSWORD, legacy) },
      legacyHashers: [legacy],
    });
    await run(h, (svc) =>
      svc.requestEmailChange("user-1", "new@example.com", { currentPassword: PASSWORD }),
    );
    expect(h.changeEmails).toHaveLength(1);
  });

  it.each([
    ["no session", {}],
    ["a session older than five minutes", { session: sessionFor("user-1", 6) }],
    ["another user's session", { session: sessionFor("user-2") }],
    [
      "an impersonation session",
      { session: sessionFor("user-1", 0, { impersonatedBy: "admin-1" }) },
    ],
    ["a password, when the account has none", { currentPassword: PASSWORD }],
  ])("a passwordless account is refused with %s", async (_label, proof) => {
    const h = makeHarness();
    const err = await run(h, (svc) =>
      Effect.flip(svc.requestEmailChange("user-1", "new@example.com", proof)),
    );
    expect(err).toBeInstanceOf(ReauthenticationRequiredError);
    nothingSent(h);
  });

  it("a passwordless account's session counts as recent within reauthenticationMaxAge", async () => {
    const h = makeHarness();
    await run(h, (svc) =>
      svc.requestEmailChange("user-1", "new@example.com", {
        session: sessionFor("user-1", 4),
      }),
    );
    expect(h.changeEmails).toHaveLength(1);
  });
});

describe("AccountManagement — change email: the old address is told at request time", () => {
  it("notifies the current address, naming the new one, before the confirmation is sent", async () => {
    const h = makeHarness();
    await run(h, (svc) => svc.requestEmailChange("user-1", "new@example.com", signedIn("user-1")));
    expect(h.notices).toEqual([{ oldEmail: "alice@example.com", newEmail: "new@example.com" }]);
    // Nothing is confirmed yet, so the after-change notice has not gone.
    expect(h.notifiedOld).toEqual([]);
  });

  it("notifies the current address even when the new one is taken", async () => {
    const h = makeHarness();
    const err = await run(h, (svc) =>
      Effect.flip(svc.requestEmailChange("user-1", "bob@example.com", signedIn("user-1"))),
    );
    expect(err).toBeInstanceOf(EmailInUseError);
    expect(h.notices).toEqual([{ oldEmail: "alice@example.com", newEmail: "bob@example.com" }]);
  });

  it("a failed notice fails the request and issues no token", async () => {
    const h = makeHarness(undefined, {
      sendEmailChangeNotice: () => Effect.fail(new AuthError({ message: "provider down" })),
    });
    const err = await run(h, (svc) =>
      Effect.flip(svc.requestEmailChange("user-1", "new@example.com", signedIn("user-1"))),
    );
    expect(err).toBeInstanceOf(AuthError);
    expect(h.changeEmails).toEqual([]);
    expect(MutableHashMap.size(h.tokens)).toBe(0);
  });
});

describe("AccountManagement — change email: failed claims keep the previous address", () => {
  const NEW_EMAIL = "alice-new@example.com";
  const userEmails = (h: Harness, userId: string) =>
    Arr.fromIterable(MutableHashMap.values(h.identifiers))
      .filter((identifier) => identifier.userId === userId && identifier.type === "email")
      .map((identifier) => ({ value: identifier.value, verified: identifier.verified }));

  it("a claim taken by another account mid-confirm leaves the previous address in place and verified", async () => {
    // Another account claims the new address after the confirm-time check and
    // before this account's replace, so the store's unique index refuses it.
    const h = makeHarness((store, records) => ({
      ...store,
      replace: (from, to) =>
        Effect.suspend(() => {
          MutableHashMap.set(
            records,
            "rival",
            makeIdentifier({
              userId: "user-2",
              type: "email",
              value: NEW_EMAIL,
              verified: true,
              now: DateTime.toDateUtc(DateTime.nowUnsafe()),
            }),
          );
          return store.replace(from, to);
        }),
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toBe("Email already in use");
    expect(userEmails(h, "user-1")).toEqual([{ value: "alice@example.com", verified: true }]);
    expect(
      Arr.fromIterable(MutableHashMap.values(h.identifiers)).find((i) => i.value === NEW_EMAIL)
        ?.userId,
    ).toBe("user-2");
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });

  it("a store failure on the replace leaves the previous address in place and verified; a retry completes the change", async () => {
    let failReplace = true;
    const h = makeHarness((store) => ({
      ...store,
      replace: (from, to) => {
        if (failReplace) {
          failReplace = false;
          return Effect.fail(new AuthError({ message: "store unavailable" }));
        }
        return store.replace(from, to);
      },
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AuthError);
    expect(userEmails(h, "user-1")).toEqual([{ value: "alice@example.com", verified: true }]);

    // The token was not consumed, so the same confirm now succeeds.
    const { user } = await run(h, (svc) => svc.confirmEmailChange(token));
    expect(user.id).toBe("user-1");
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(h.notifiedOld).toEqual([{ oldEmail: "alice@example.com", newEmail: NEW_EMAIL }]);
  });

  it("a store without transactions that fails between its claim and its release converges on retry", async () => {
    // A claim-then-release store whose release fails: the user holds both.
    let failRelease = true;
    const h = makeHarness((store) => ({
      ...store,
      replace: (from, to) => {
        if (failRelease) {
          failRelease = false;
          return store.create(to).pipe(
            // The memory store holds every identifier type; it never refuses.
            Effect.catchTag("IdentifierRefusedError", Effect.die),
            Effect.andThen(Effect.fail(new AuthError({ message: "store unavailable" }))),
          );
        }
        return store.replace(from, to);
      },
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AuthError);
    expect(userEmails(h, "user-1")).toEqual([
      { value: "alice@example.com", verified: true },
      { value: NEW_EMAIL, verified: true },
    ]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);

    // The retry sees the new address as this user's own and releases the old one.
    await run(h, (svc) => svc.confirmEmailChange(token));
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
  });

  it("releases every other address the user held, and retries a failed release to completion", async () => {
    let failRelease = true;
    const h = makeHarness((store, records) => ({
      ...store,
      delete: (id) => {
        if (
          failRelease &&
          Option.getOrUndefined(MutableHashMap.get(records, id))?.value === "alice@work.example.com"
        ) {
          failRelease = false;
          return Effect.fail(new AuthError({ message: "store unavailable" }));
        }
        return store.delete(id);
      },
    }));
    const second = makeIdentifier({
      userId: "user-1",
      type: "email",
      value: "alice@work.example.com",
      now: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 1000 })),
    });
    MutableHashMap.set(h.identifiers, second.id, second);
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AuthError);
    // The email of record was replaced; the second address is still to release.
    expect(
      Arr.sort(
        userEmails(h, "user-1").map((email) => email.value),
        Order.String,
      ),
    ).toEqual([NEW_EMAIL, "alice@work.example.com"]);

    await run(h, (svc) => svc.confirmEmailChange(token));
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
  });

  it("an email of record released during the confirmation fails with AccountTokenError and keeps the token", async () => {
    // The address is released between the read and the replace, and the user
    // does not hold the new one: nothing to converge on.
    const h = makeHarness((store) => ({
      ...store,
      replace: (from, to) => store.delete(from.id).pipe(Effect.andThen(store.replace(from, to))),
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toContain("changed during the confirmation");
    expect(userEmails(h, "user-1")).toEqual([]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });

  // A double submit: a second confirmation of the same token completes the
  // replace between this request's read and its own replace. `verified` is
  // the state the concurrent write leaves the new address in.
  const doubleSubmit =
    (rejectTakenFirst: boolean, verified = true) =>
    (store: typeof IdentifierStore.Service): typeof IdentifierStore.Service => ({
      ...store,
      replace: (from, to) =>
        Effect.gen(function* () {
          yield* store.replace(
            from,
            makeIdentifier({
              userId: to.userId,
              type: "email",
              value: to.value,
              verified,
              now: DateTime.toDateUtc(DateTime.nowUnsafe()),
            }),
          );
          // A store that claims `to` before it looks at `from` (effect-auth/sql's
          // INSERT first) refuses the now-held value instead of resolving to null.
          if (rejectTakenFirst && Option.isSome(yield* store.getByValue(to.type, to.value))) {
            return yield* new AuthError({ message: "unique index violation" });
          }
          return yield* store.replace(from, to);
        }),
    });

  Arr.forEach(
    [
      ["resolves to null", false],
      ["refuses the held value", true],
    ] as const,
    ([label, rejectTakenFirst]) => {
      it(`a double-submitted confirmation converges to success when the store ${label}`, async () => {
        const h = makeHarness(doubleSubmit(rejectTakenFirst));
        const { token } = await run(h, (svc) =>
          svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
        );

        const { user } = await run(h, (svc) => svc.confirmEmailChange(token));

        expect(user.id).toBe("user-1");
        expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
        expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
        expect(h.revoked).toEqual(["user-1"]);
        expect(h.notifiedOld).toEqual([{ oldEmail: "alice@example.com", newEmail: NEW_EMAIL }]);
      });

      it(`a converged confirmation leaves the new address verified when the concurrent write left it unverified and the store ${label}`, async () => {
        const h = makeHarness(doubleSubmit(rejectTakenFirst, false));
        const { token } = await run(h, (svc) =>
          svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
        );

        await run(h, (svc) => svc.confirmEmailChange(token));

        expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
        expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
      });
    },
  );

  it("a store that reports a row already holding the new address, unverified, ends with it verified", async () => {
    // The single-table store resolves a stale `from` to the row when the row
    // already holds `to`'s address, as the row stands: here, unverified.
    const h = makeHarness((store) => ({
      ...store,
      replace: (from, to) =>
        Effect.gen(function* () {
          yield* store.replace(
            from,
            makeIdentifier({
              userId: to.userId,
              type: "email",
              value: to.value,
              now: DateTime.toDateUtc(DateTime.nowUnsafe()),
            }),
          );
          return yield* store.getByValue(to.type, to.value);
        }),
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    await run(h, (svc) => svc.confirmEmailChange(token));

    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
  });

  it("a user who already holds the new address, unverified, ends with it verified and the previous address released", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );
    const held = makeIdentifier({
      userId: "user-1",
      type: "email",
      value: NEW_EMAIL,
      now: DateTime.toDateUtc(DateTime.add(DateTime.nowUnsafe(), { milliseconds: 1000 })),
    });
    MutableHashMap.set(h.identifiers, held.id, held);

    await run(h, (svc) => svc.confirmEmailChange(token));

    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
  });

  it("a failed verification of a converged address fails and keeps the token; a retry completes the change verified", async () => {
    let failSetVerified = true;
    const h = makeHarness((store) => ({
      ...doubleSubmit(false, false)(store),
      setVerified: (id, verifiedAt) => {
        if (failSetVerified) {
          failSetVerified = false;
          return Effect.fail(new AuthError({ message: "store unavailable" }));
        }
        return store.setVerified(id, verifiedAt);
      },
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AuthError);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
    expect(h.revoked).toEqual([]);

    await run(h, (svc) => svc.confirmEmailChange(token));
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
  });

  it("an address deleted before its verification fails with AccountTokenError and keeps the token", async () => {
    // A concurrent delete removes the converged identifier, so `setVerified`
    // resolves to null.
    const h = makeHarness((store) => ({
      ...doubleSubmit(false, false)(store),
      setVerified: (id, verifiedAt) =>
        store.delete(id).pipe(Effect.andThen(store.setVerified(id, verifiedAt))),
    }));
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toBe("The account's email changed during the confirmation; try again");
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });

  it("a user with no email claims the new address", async () => {
    const h = makeHarness();
    MutableHashMap.forEach(h.identifiers, (identifier, id) => {
      if (identifier.userId === "user-1") MutableHashMap.remove(h.identifiers, id);
    });
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );
    // No current address to tell.
    expect(h.notices).toEqual([]);

    await run(h, (svc) => svc.confirmEmailChange(token));

    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(h.notifiedOld).toEqual([{ oldEmail: null, newEmail: NEW_EMAIL }]);
  });

  // A user with no email; `owner` claims the new address, unverified, after
  // the confirm-time check and before this request's own claim.
  const claimedMidConfirm = (owner: string): Harness => {
    const h = makeHarness((store, records) => ({
      ...store,
      create: (identifier) =>
        Effect.suspend(() => {
          const concurrent = makeIdentifier({
            userId: owner,
            type: "email",
            value: identifier.value,
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          });
          MutableHashMap.set(records, concurrent.id, concurrent);
          return store.create(identifier);
        }),
    }));
    MutableHashMap.forEach(h.identifiers, (identifier, id) => {
      if (identifier.userId === "user-1") MutableHashMap.remove(h.identifiers, id);
    });
    return h;
  };

  it("a double-submitted confirmation by a user with no email converges to success, with the address verified", async () => {
    const h = claimedMidConfirm("user-1");
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const { user } = await run(h, (svc) => svc.confirmEmailChange(token));

    expect(user.id).toBe("user-1");
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(false);
    expect(h.revoked).toEqual(["user-1"]);
    expect(h.notifiedOld).toEqual([{ oldEmail: null, newEmail: NEW_EMAIL }]);
  });

  it("a user with no email whose claim another account wins mid-confirm fails with Email already in use and keeps the token", async () => {
    const h = claimedMidConfirm("user-2");
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", NEW_EMAIL, signedIn("user-1")),
    );

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toBe("Email already in use");
    expect(userEmails(h, "user-1")).toEqual([]);
    expect(
      Arr.fromIterable(MutableHashMap.values(h.identifiers)).find((i) => i.value === NEW_EMAIL)
        ?.userId,
    ).toBe("user-2");
    expect(MutableHashMap.has(h.tokens, sha256Hex(token))).toBe(true);
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });
});

describe("AccountManagement — delete user", () => {
  it("runs cleanup, revokes sessions, and deletes the user on confirm", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) => svc.requestAccountDeletion("user-2"));
    expect(h.deleteSends).toEqual([{ email: "bob@example.com", token }]);

    const { userId } = await run(h, (svc) => svc.confirmAccountDeletion(token));
    expect(userId).toBe("user-2");
    expect(h.beforeDeleteCalls).toEqual(["user-2"]);
    expect(h.revoked).toContain("user-2");
    expect(MutableHashMap.has(h.users, "user-2")).toBe(false);
    // The user's identifiers are removed too.
    expect(
      Arr.fromIterable(MutableHashMap.values(h.identifiers)).some(
        (identifier) => identifier.userId === "user-2",
      ),
    ).toBe(false);
  });

  it("rejects a change-email token at the deletion confirm endpoint (wrong purpose)", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) =>
      svc.requestEmailChange("user-1", "alice9@example.com", signedIn("user-1")),
    );
    const err = await run(h, (svc) => Effect.flip(svc.confirmAccountDeletion(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
    // The user still exists.
    expect(MutableHashMap.has(h.users, "user-1")).toBe(true);
  });
});
