import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer } from "effect";
import {
  AccountManagementService,
  AccountManagementStore,
  AccountTokenError,
  type AccountToken,
} from "./AccountManagement.js";
import { EmailInUseError } from "./Errors.js";
import { UserServiceStore } from "./User.js";
import { SessionService } from "./session/SessionService.js";
import type * as Types from "./Types.js";

interface Harness {
  readonly layer: Layer.Layer<
    AccountManagementService | AccountManagementStore | UserServiceStore | SessionService
  >;
  readonly users: Map<string, Types.User>;
  readonly tokens: Map<string, AccountToken>;
  readonly revoked: string[];
  readonly changeEmails: Array<{ newEmail: string; token: string }>;
  readonly deleteSends: Array<{ email: string; token: string }>;
  readonly beforeDeleteCalls: string[];
  readonly notifiedOld: Array<{ oldEmail: string; newEmail: string }>;
}

const makeUser = (id: string, email: string): Types.User => {
  const now = new Date();
  return {
    id,
    email,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
    attributes: {},
  };
};

const makeHarness = (): Harness => {
  const users = new Map<string, Types.User>();
  const emailToId = new Map<string, string>();
  const tokens = new Map<string, AccountToken>();
  const revoked: string[] = [];
  const changeEmails: Array<{ newEmail: string; token: string }> = [];
  const deleteSends: Array<{ email: string; token: string }> = [];
  const beforeDeleteCalls: string[] = [];
  const notifiedOld: Array<{ oldEmail: string; newEmail: string }> = [];

  const addUser = (user: Types.User) => {
    users.set(user.id, user);
    emailToId.set(user.email, user.id);
  };
  addUser(makeUser("user-1", "alice@example.com"));
  addUser(makeUser("user-2", "bob@example.com"));

  const userStore: typeof UserServiceStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
    getByEmail: (email) =>
      Effect.sync(() => {
        const id = emailToId.get(email);
        return id === undefined ? null : (users.get(id) ?? null);
      }),
    update: (user) =>
      Effect.sync(() => {
        // Keep the email index consistent (email may have changed).
        for (const [mail, id] of emailToId) if (id === user.id) emailToId.delete(mail);
        users.set(user.id, user);
        emailToId.set(user.email, user.id);
        return user;
      }),
    delete: (userId) =>
      Effect.sync(() => {
        const user = users.get(userId);
        if (user !== undefined) {
          emailToId.delete(user.email);
          users.delete(userId);
        }
      }),
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
    sendDeleteAccountVerification: ({ user, token }) =>
      Effect.sync(() => void deleteSends.push({ email: user.email, token })),
    beforeDelete: (user) => Effect.sync(() => void beforeDeleteCalls.push(user.id)),
    notifyEmailChanged: ({ oldEmail, newEmail }) =>
      Effect.sync(() => void notifiedOld.push({ oldEmail, newEmail })),
  }).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        Layer.succeed(UserServiceStore)(userStore),
        Layer.succeed(AccountManagementStore)(tokenStore),
        Layer.succeed(SessionService)(sessionManager),
      ),
    ),
  );

  return {
    layer,
    users,
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
    svc: AccountManagementServiceShape,
  ) => Effect.Effect<A, E, AccountManagementStore | UserServiceStore | SessionService>,
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
    expect(user.email).toBe("alice-new@example.com");
    expect(user.emailVerified).toBe(true);
    expect(h.users.get("user-1")!.email).toBe("alice-new@example.com");
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
