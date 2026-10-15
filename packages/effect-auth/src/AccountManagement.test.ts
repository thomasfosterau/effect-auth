import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import {
  AccountManagementService,
  AccountManagementStore,
  AccountTokenError,
  type AccountToken,
} from "./AccountManagement.ts";
import { AuthError, EmailInUseError } from "./Errors.ts";
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
  readonly users: Map<string, Types.User>;
  readonly identifiers: Map<string, Identifier>;
  readonly tokens: Map<string, AccountToken>;
  readonly revoked: string[];
  readonly changeEmails: Array<{ newEmail: string; token: string }>;
  readonly deleteSends: Array<{ email: string | null; token: string }>;
  readonly beforeDeleteCalls: string[];
  readonly notifiedOld: Array<{ oldEmail: string | null; newEmail: string }>;
}

const makeUser = (id: string): Types.User => {
  const now = new Date();
  return {
    id,
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
};

/**
 * Wraps the identifier store for a test: `records` is the live map the store
 * writes to, so a wrapper can simulate a concurrent claim by writing to it.
 */
type WrapIdentifiers = (
  store: typeof IdentifierStore.Service,
  records: Map<string, Identifier>,
) => typeof IdentifierStore.Service;

const makeHarness = (wrap?: WrapIdentifiers): Harness => {
  const users = new Map<string, Types.User>();
  const identifiers = new Map<string, Identifier>();
  const tokens = new Map<string, AccountToken>();
  const revoked: string[] = [];
  const changeEmails: Array<{ newEmail: string; token: string }> = [];
  const deleteSends: Array<{ email: string | null; token: string }> = [];
  const beforeDeleteCalls: string[] = [];
  const notifiedOld: Array<{ oldEmail: string | null; newEmail: string }> = [];

  const addUser = (user: Types.User, email: string) => {
    users.set(user.id, user);
    const identifier = makeIdentifier({
      userId: user.id,
      type: "email",
      value: email,
      verified: true,
      verifiedAt: new Date(),
    });
    identifiers.set(identifier.id, identifier);
  };
  addUser(makeUser("user-1"), "alice@example.com");
  addUser(makeUser("user-2"), "bob@example.com");

  const userStore: typeof UserServiceStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
    update: (user) =>
      Effect.sync(() => {
        users.set(user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void users.delete(userId)),
  };

  const tokenStore: typeof AccountManagementStore.Service = {
    create: (token) =>
      Effect.sync(() => {
        tokens.set(token.token, token);
        return token;
      }),
    get: (token) => Effect.sync(() => tokens.get(token) ?? null),
    delete: (token) => Effect.sync(() => void tokens.delete(token)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        for (const [t, rec] of tokens) if (rec.userId === userId) tokens.delete(t);
      }),
  };

  // Minimal SessionService: only `invalidateUserSessions` is exercised.
  const sessionManager: typeof SessionService.Service = {
    createSession: () => Effect.die("unused"),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: (userId) => Effect.sync(() => void revoked.push(userId)),
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const layer = AccountManagementService.layer({
    sendChangeEmailVerification: ({ newEmail, token }) =>
      Effect.sync(() => void changeEmails.push({ newEmail, token })),
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
      svc.requestEmailChange("user-1", "ALICE-NEW@example.com"),
    );
    expect(h.changeEmails).toHaveLength(1);
    expect(h.changeEmails[0]!.newEmail).toBe("alice-new@example.com");

    const { user } = await run(h, (svc) => svc.confirmEmailChange(token));
    expect(user.id).toBe("user-1");
    // The old email identifier is gone; the new one belongs to the user and is verified.
    const userEmails = [...h.identifiers.values()].filter(
      (identifier) => identifier.userId === "user-1" && identifier.type === "email",
    );
    expect(userEmails).toHaveLength(1);
    expect(userEmails[0]!.value).toBe("alice-new@example.com");
    expect(userEmails[0]!.verified).toBe(true);
    expect(
      [...h.identifiers.values()].some((identifier) => identifier.value === "alice@example.com"),
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
      Effect.flip(svc.requestEmailChange("user-1", "bob@example.com")),
    );
    expect(err).toBeInstanceOf(EmailInUseError);
    expect(h.changeEmails).toHaveLength(0);
    expect(h.tokens.size).toBe(0);
  });

  it("consumes the token on first confirm (single use)", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", "alice2@example.com"));
    await run(h, (svc) => svc.confirmEmailChange(token));
    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
  });

  it("rejects an expired token", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", "alice3@example.com"));
    // Force expiry.
    const rec = h.tokens.get(token)!;
    h.tokens.set(token, { ...rec, expiresAt: Date.now() - 1 });
    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
  });
});

describe("AccountManagement — change email: failed claims keep the previous address", () => {
  const NEW_EMAIL = "alice-new@example.com";
  const userEmails = (h: Harness, userId: string) =>
    [...h.identifiers.values()]
      .filter((identifier) => identifier.userId === userId && identifier.type === "email")
      .map((identifier) => ({ value: identifier.value, verified: identifier.verified }));

  it("a claim taken by another account mid-confirm leaves the previous address in place and verified", async () => {
    // Another account claims the new address after the confirm-time check and
    // before this account's replace, so the store's unique index refuses it.
    const h = makeHarness((store, records) => ({
      ...store,
      replace: (from, to) =>
        Effect.suspend(() => {
          records.set(
            "rival",
            makeIdentifier({ userId: "user-2", type: "email", value: NEW_EMAIL, verified: true }),
          );
          return store.replace(from, to);
        }),
    }));
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toBe("Email already in use");
    expect(userEmails(h, "user-1")).toEqual([{ value: "alice@example.com", verified: true }]);
    expect([...h.identifiers.values()].find((i) => i.value === NEW_EMAIL)?.userId).toBe("user-2");
    expect(h.tokens.has(token)).toBe(true);
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
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

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
          return store
            .create(to)
            .pipe(Effect.andThen(Effect.fail(new AuthError({ message: "store unavailable" }))));
        }
        return store.replace(from, to);
      },
    }));
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AuthError);
    expect(userEmails(h, "user-1")).toEqual([
      { value: "alice@example.com", verified: true },
      { value: NEW_EMAIL, verified: true },
    ]);
    expect(h.tokens.has(token)).toBe(true);

    // The retry sees the new address as this user's own and releases the old one.
    await run(h, (svc) => svc.confirmEmailChange(token));
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
  });

  it("releases every other address the user held, and retries a failed release to completion", async () => {
    let failRelease = true;
    const h = makeHarness((store, records) => ({
      ...store,
      delete: (id) => {
        if (failRelease && records.get(id)?.value === "alice@work.example.com") {
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
      now: new Date(Date.now() + 1000),
    });
    h.identifiers.set(second.id, second);
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AuthError);
    // The email of record was replaced; the second address is still to release.
    expect(
      userEmails(h, "user-1")
        .map((email) => email.value)
        .sort(),
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
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toContain("changed during the confirmation");
    expect(userEmails(h, "user-1")).toEqual([]);
    expect(h.tokens.has(token)).toBe(true);
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });

  // A double submit: a second confirmation of the same token completes the
  // replace between this request's read and its own replace.
  const doubleSubmit =
    (rejectTakenFirst: boolean) =>
    (store: typeof IdentifierStore.Service): typeof IdentifierStore.Service => ({
      ...store,
      replace: (from, to) =>
        Effect.gen(function* () {
          yield* store.replace(
            from,
            makeIdentifier({ userId: to.userId, type: "email", value: to.value, verified: true }),
          );
          // A store that claims `to` before it looks at `from` (effect-auth-sql's
          // INSERT first) refuses the now-held value instead of resolving to null.
          if (rejectTakenFirst && (yield* store.getByValue(to.type, to.value)) !== null) {
            return yield* new AuthError({ message: "unique index violation" });
          }
          return yield* store.replace(from, to);
        }),
    });

  for (const [label, rejectTakenFirst] of [
    ["resolves to null", false],
    ["refuses the held value", true],
  ] as const) {
    it(`a double-submitted confirmation converges to success when the store ${label}`, async () => {
      const h = makeHarness(doubleSubmit(rejectTakenFirst));
      const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

      const { user } = await run(h, (svc) => svc.confirmEmailChange(token));

      expect(user.id).toBe("user-1");
      expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
      expect(h.tokens.has(token)).toBe(false);
      expect(h.revoked).toEqual(["user-1"]);
      expect(h.notifiedOld).toEqual([{ oldEmail: "alice@example.com", newEmail: NEW_EMAIL }]);
    });
  }

  it("a user with no email claims the new address", async () => {
    const h = makeHarness();
    for (const [id, identifier] of h.identifiers) {
      if (identifier.userId === "user-1") h.identifiers.delete(id);
    }
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    await run(h, (svc) => svc.confirmEmailChange(token));

    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
    expect(h.notifiedOld).toEqual([{ oldEmail: null, newEmail: NEW_EMAIL }]);
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
    expect(h.users.has("user-2")).toBe(false);
    // The user's identifiers are removed too.
    expect([...h.identifiers.values()].some((identifier) => identifier.userId === "user-2")).toBe(
      false,
    );
  });

  it("rejects a change-email token at the deletion confirm endpoint (wrong purpose)", async () => {
    const h = makeHarness();
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", "alice9@example.com"));
    const err = await run(h, (svc) => Effect.flip(svc.confirmAccountDeletion(token)));
    expect(err).toBeInstanceOf(AccountTokenError);
    // The user still exists.
    expect(h.users.has("user-1")).toBe(true);
  });
});
