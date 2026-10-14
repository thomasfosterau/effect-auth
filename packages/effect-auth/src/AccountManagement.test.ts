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
    // before this account's create, so the store's unique index rejects the claim.
    const h = makeHarness((store, records) => ({
      ...store,
      create: (identifier) => {
        if (identifier.value !== NEW_EMAIL) return store.create(identifier);
        return Effect.suspend(() => {
          records.set(
            "rival",
            makeIdentifier({ userId: "user-2", type: "email", value: NEW_EMAIL, verified: true }),
          );
          return store.create(identifier);
        });
      },
    }));
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(AccountTokenError);
    expect(err.message).toBe("Email already in use");
    expect(userEmails(h, "user-1")).toEqual([{ value: "alice@example.com", verified: true }]);
    expect([...h.identifiers.values()].find((i) => i.value === NEW_EMAIL)?.userId).toBe("user-2");
    expect(h.revoked).toEqual([]);
    expect(h.notifiedOld).toEqual([]);
  });

  it("a store failure on the claim leaves the previous address in place and verified; a retry completes the change", async () => {
    let failClaim = true;
    const h = makeHarness((store) => ({
      ...store,
      create: (identifier) => {
        if (identifier.value === NEW_EMAIL && failClaim) {
          failClaim = false;
          return Effect.fail(new AuthError({ message: "store unavailable" }));
        }
        return store.create(identifier);
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

  it("a failure releasing the previous address after the claim is retried to completion", async () => {
    let failRelease = true;
    const h = makeHarness((store, records) => ({
      ...store,
      delete: (id) => {
        if (failRelease && records.get(id)?.value === "alice@example.com") {
          failRelease = false;
          return Effect.fail(new AuthError({ message: "store unavailable" }));
        }
        return store.delete(id);
      },
    }));
    const { token } = await run(h, (svc) => svc.requestEmailChange("user-1", NEW_EMAIL));

    const err = await run(h, (svc) => Effect.flip(svc.confirmEmailChange(token)));
    expect(err).toBeInstanceOf(AuthError);
    // The new address is claimed; the previous one is still there to be released.
    expect(userEmails(h, "user-1")).toEqual([
      { value: "alice@example.com", verified: true },
      { value: NEW_EMAIL, verified: true },
    ]);

    // The retry sees the new address as this user's own and releases the old one.
    await run(h, (svc) => svc.confirmEmailChange(token));
    expect(userEmails(h, "user-1")).toEqual([{ value: NEW_EMAIL, verified: true }]);
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
