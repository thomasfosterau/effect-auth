/**
 * Email change and account deletion through `AccountManagementService` over the
 * single-table `IdentifierStore` (PGlite), on a nullable `email` column and on a
 * NOT NULL one.
 *
 * The store holds one email per user, so core's confirm goes through
 * `IdentifierStore.replace`, which rewrites the row's address in one `UPDATE`:
 * the change completes on both shapes, and a NOT NULL row is never left `NULL`.
 * When the new address is taken, by a claim the confirm-time check saw or by
 * one that lands between that check and the write, the change fails, the
 * previous address stays in place and verified, and only the first case
 * consumes the token.
 *
 * Account deletion is the other flow the NOT NULL shape has to get right: the
 * store leaves the address to the user row, and the application's user writer
 * hard-deletes that row, which takes the address with it.
 */

import type { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import {
  defineUsers,
  layer as singleTableLayer,
  type SingleTableUsers,
} from "./SingleTableIdentifierStore.ts";
import { USER, USER_CREATED_AT } from "./testing/IdentifierStoreContract.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

const appUsers = pgTable("app_users_email_change", {
  userId: uuid("id").primaryKey(),
  email: text("email").unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

/** The same users table with `email` NOT NULL. */
const strictUsers = pgTable("app_users_email_change_strict", {
  userId: uuid("id").primaryKey(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

const mapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

const strictMapping = defineUsers({
  table: strictUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

const OLD = "ada@example.com";
const NEW = "ada-new@example.com";
const GRACE = "grace@example.com";

let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(`
    CREATE TABLE IF NOT EXISTS app_users_email_change (
      id uuid PRIMARY KEY,
      email text UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL
    );
    CREATE TABLE IF NOT EXISTS app_users_email_change_strict (
      id uuid PRIMARY KEY,
      email text NOT NULL UNIQUE,
      email_verified boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL
    );
  `);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users_email_change", "app_users_email_change_strict"]);
});

const readRow = async (userId: string) => {
  const rows = await drizzle(client)
    .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
    .from(appUsers)
    .where(eq(appUsers.userId, userId))
    .limit(1);
  return rows[0] ?? null;
};

const readStrictRow = async (userId: string) => {
  const rows = await drizzle(client)
    .select({ email: strictUsers.email, emailVerified: strictUsers.emailVerified })
    .from(strictUsers)
    .where(eq(strictUsers.userId, userId))
    .limit(1);
  return rows[0] ?? null;
};

const deleteStrictRow = async (userId: string) => {
  await drizzle(client).delete(strictUsers).where(eq(strictUsers.userId, userId));
};

const makeUser = (id: string): Auth.User => {
  const now = new Date(USER_CREATED_AT);
  return { id, createdAt: now, updatedAt: now, attributes: {} };
};

/**
 * An `AccountManagementService` over the single-table store on this file's
 * database. `deleteRow` is what the application's user writer does when it
 * deletes a user, which `UserServiceStore.delete` stands for here. `wrap`, when
 * given, wraps the identifier store, to stage a concurrent write.
 */
const makeHarness = (
  users: SingleTableUsers,
  deleteRow: (userId: string) => Promise<void>,
  wrap?: (store: typeof Auth.IdentifierStore.Service) => typeof Auth.IdentifierStore.Service,
) => {
  const userMap = new Map<string, Auth.User>([
    [USER.ada, makeUser(USER.ada)],
    [USER.grace, makeUser(USER.grace)],
  ]);
  const tokens = new Map<string, Auth.AccountToken>();

  const userStore: typeof Auth.UserServiceStore.Service = {
    get: (userId) => Effect.sync(() => userMap.get(userId) ?? null),
    update: (user) =>
      Effect.sync(() => {
        userMap.set(user.id, user);
        return user;
      }),
    delete: (userId) =>
      Effect.promise(async () => {
        userMap.delete(userId);
        await deleteRow(userId);
      }),
  };

  const tokenStore: typeof Auth.AccountManagementStore.Service = {
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

  // Minimal SessionService: only `invalidateUserSessions` is reached.
  const sessions: typeof Auth.SessionService.Service = {
    createSession: () => Effect.die("unused"),
    validateSession: () => Effect.die("unused"),
    invalidateSession: () => Effect.die("unused"),
    invalidateUserSessions: () => Effect.void,
    listSessions: () => Effect.succeed([]),
    revokeOtherSessions: () => Effect.void,
    setSessionAttributes: () => Effect.die("unused"),
  };

  const layer = Auth.AccountManagementService.layer({
    sendChangeEmailVerification: () => Effect.void,
    sendDeleteAccountVerification: () => Effect.void,
  }).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        Layer.succeed(Auth.UserServiceStore)(userStore),
        Layer.succeed(Auth.AccountManagementStore)(tokenStore),
        Layer.succeed(Auth.SessionService)(sessions),
        Layer.effect(
          Auth.IdentifierStore,
          Effect.gen(function* () {
            const store = yield* Auth.IdentifierStore;
            return wrap === undefined ? store : wrap(store);
          }),
        ).pipe(
          Layer.provide(
            singleTableLayer(users).pipe(Layer.provide(databaseLayer(drizzle(client)))),
          ),
        ),
      ),
    ),
  );

  return {
    run: <A, E>(
      f: (svc: typeof Auth.AccountManagementService.Service) => Effect.Effect<A, E>,
    ): Promise<A> =>
      Effect.runPromise(
        Effect.gen(function* () {
          const svc = yield* Auth.AccountManagementService;
          return yield* f(svc);
        }).pipe(Effect.provide(layer)) as Effect.Effect<A, E>,
      ),
    tokens,
  };
};

describe("single-table IdentifierStore: email change", () => {
  describe("nullable email", () => {
    beforeEach(async () => {
      await drizzle(client)
        .insert(appUsers)
        .values([
          { userId: USER.ada, email: OLD, emailVerified: true, createdAt: USER_CREATED_AT },
          { userId: USER.grace, createdAt: USER_CREATED_AT },
        ]);
    });

    it("changes the address in place: the row holds the new address, verified, and the token is consumed", async () => {
      const h = makeHarness(mapping, async () => {});
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const { user } = await h.run((svc) => svc.confirmEmailChange(token));

      expect(user.id).toBe(USER.ada);
      expect(await readRow(USER.ada)).toEqual({ email: NEW, emailVerified: true });
      expect(await readRow(USER.grace)).toEqual({ email: null, emailVerified: false });
      expect(h.tokens.has(token)).toBe(false);
    });

    it("an address another user claims between the confirm-time check and the write fails with AccountTokenError; the previous address and the token stay", async () => {
      // Grace takes the new address just before the store writes it, so only the
      // unique index can refuse it.
      const h = makeHarness(
        mapping,
        async () => {},
        (store) => ({
          ...store,
          replace: (from, to) =>
            Effect.promise(() =>
              drizzle(client)
                .update(appUsers)
                .set({ email: NEW, emailVerified: true })
                .where(eq(appUsers.userId, USER.grace)),
            ).pipe(Effect.andThen(store.replace(from, to))),
        }),
      );
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const err = await h.run((svc) => Effect.flip(svc.confirmEmailChange(token)));

      expect(err).toBeInstanceOf(Auth.AccountTokenError);
      expect(err.message).toBe("Email already in use");
      expect(await readRow(USER.ada)).toEqual({ email: OLD, emailVerified: true });
      expect(await readRow(USER.grace)).toEqual({ email: NEW, emailVerified: true });
      expect(h.tokens.has(token)).toBe(true);
    });

    it("a row a concurrent write already moved to the new address, unverified, ends verified, and the token is consumed", async () => {
      // A concurrent writer moves Ada's row to the new address, unverified, just
      // before the store writes: the guarded UPDATE matches nothing, and the
      // store reports the row as it stands.
      const h = makeHarness(
        mapping,
        async () => {},
        (store) => ({
          ...store,
          replace: (from, to) =>
            Effect.promise(() =>
              drizzle(client)
                .update(appUsers)
                .set({ email: NEW, emailVerified: false })
                .where(eq(appUsers.userId, USER.ada)),
            ).pipe(Effect.andThen(store.replace(from, to))),
        }),
      );
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const { user } = await h.run((svc) => svc.confirmEmailChange(token));

      expect(user.id).toBe(USER.ada);
      expect(await readRow(USER.ada)).toEqual({ email: NEW, emailVerified: true });
      expect(h.tokens.has(token)).toBe(false);
    });

    it("an address another user claims after the change is requested fails with AccountTokenError and the previous address stays", async () => {
      const h = makeHarness(mapping, async () => {});
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));
      await drizzle(client)
        .update(appUsers)
        .set({ email: NEW, emailVerified: true })
        .where(eq(appUsers.userId, USER.grace));

      const err = await h.run((svc) => Effect.flip(svc.confirmEmailChange(token)));

      expect(err).toBeInstanceOf(Auth.AccountTokenError);
      expect(err.message).toBe("Email already in use");
      expect(await readRow(USER.ada)).toEqual({ email: OLD, emailVerified: true });
    });
  });

  describe("NOT NULL email", () => {
    beforeEach(async () => {
      await drizzle(client)
        .insert(strictUsers)
        .values([
          { userId: USER.ada, email: OLD, emailVerified: true, createdAt: USER_CREATED_AT },
          { userId: USER.grace, email: GRACE, createdAt: USER_CREATED_AT },
        ]);
    });

    it("changes the address in place without ever writing NULL, and consumes the token", async () => {
      const h = makeHarness(strictMapping, deleteStrictRow);
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const { user } = await h.run((svc) => svc.confirmEmailChange(token));

      expect(user.id).toBe(USER.ada);
      expect(await readStrictRow(USER.ada)).toEqual({ email: NEW, emailVerified: true });
      expect(await readStrictRow(USER.grace)).toEqual({ email: GRACE, emailVerified: false });
      expect(h.tokens.has(token)).toBe(false);
    });

    it("an address another user claims between the confirm-time check and the write fails with AccountTokenError; the previous address and the token stay", async () => {
      const h = makeHarness(strictMapping, deleteStrictRow, (store) => ({
        ...store,
        replace: (from, to) =>
          Effect.promise(() =>
            drizzle(client)
              .update(strictUsers)
              .set({ email: NEW })
              .where(eq(strictUsers.userId, USER.grace)),
          ).pipe(Effect.andThen(store.replace(from, to))),
      }));
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const err = await h.run((svc) => Effect.flip(svc.confirmEmailChange(token)));

      expect(err).toBeInstanceOf(Auth.AccountTokenError);
      expect(err.message).toBe("Email already in use");
      expect(await readStrictRow(USER.ada)).toEqual({ email: OLD, emailVerified: true });
      expect(h.tokens.has(token)).toBe(true);
    });

    it("a row a concurrent write already moved to the new address, unverified, ends verified, and the token is consumed", async () => {
      // A concurrent writer moves Ada's row to the new address, unverified, just
      // before the store writes: the guarded UPDATE matches nothing, and the
      // store reports the row as it stands.
      const h = makeHarness(strictMapping, deleteStrictRow, (store) => ({
        ...store,
        replace: (from, to) =>
          Effect.promise(() =>
            drizzle(client)
              .update(strictUsers)
              .set({ email: NEW, emailVerified: false })
              .where(eq(strictUsers.userId, USER.ada)),
          ).pipe(Effect.andThen(store.replace(from, to))),
      }));
      const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

      const { user } = await h.run((svc) => svc.confirmEmailChange(token));

      expect(user.id).toBe(USER.ada);
      expect(await readStrictRow(USER.ada)).toEqual({ email: NEW, emailVerified: true });
      expect(h.tokens.has(token)).toBe(false);
    });

    it("account deletion completes: the user row and its address go, the token is consumed, and the other user is untouched", async () => {
      const h = makeHarness(strictMapping, deleteStrictRow);
      const { token } = await h.run((svc) => svc.requestAccountDeletion(USER.ada));

      const deleted = await h.run((svc) => svc.confirmAccountDeletion(token));

      expect(deleted).toEqual({ userId: USER.ada });
      expect(await readStrictRow(USER.ada)).toBeNull();
      expect(await readStrictRow(USER.grace)).toEqual({ email: GRACE, emailVerified: false });
      expect(h.tokens.has(token)).toBe(false);
    });
  });
});
