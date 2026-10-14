/**
 * Email change through `AccountManagementService` over the single-table
 * `IdentifierStore` (PGlite).
 *
 * The store holds one email per user and refuses a second, so core's
 * claim-first confirm is refused while the user still holds the current
 * address: the change fails with an `AuthError` before anything is released,
 * and the previous address stays in place and verified. The token is not
 * consumed.
 */

import type { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { boolean, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { defineUsers, layer as singleTableLayer } from "./SingleTableIdentifierStore.ts";
import { USER, USER_CREATED_AT } from "./testing/IdentifierStoreContract.ts";
import { migratedPglite, truncate } from "./testing/PgliteTemplate.ts";

const appUsers = pgTable("app_users_email_change", {
  userId: uuid("id").primaryKey(),
  email: text("email").unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  createdAt: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
});

const mapping = defineUsers({
  table: appUsers,
  columns: { id: "userId", email: "email", emailVerified: "emailVerified", createdAt: "createdAt" },
});

const OLD = "ada@example.com";
const NEW = "ada-new@example.com";

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
  `);
});

afterAll(async () => {
  await client?.close();
});

beforeEach(async () => {
  await truncate(client, ["app_users_email_change"]);
  await drizzle(client)
    .insert(appUsers)
    .values([
      { userId: USER.ada, email: OLD, emailVerified: true, createdAt: USER_CREATED_AT },
      { userId: USER.grace, createdAt: USER_CREATED_AT },
    ]);
});

const readRow = async (userId: string) => {
  const rows = await drizzle(client)
    .select({ email: appUsers.email, emailVerified: appUsers.emailVerified })
    .from(appUsers)
    .where(eq(appUsers.userId, userId))
    .limit(1);
  return rows[0] ?? null;
};

const makeUser = (id: string): Auth.User => {
  const now = new Date(USER_CREATED_AT);
  return { id, createdAt: now, updatedAt: now, attributes: {} };
};

/** An `AccountManagementService` over the single-table store on this file's database. */
const makeHarness = () => {
  const users = new Map<string, Auth.User>([
    [USER.ada, makeUser(USER.ada)],
    [USER.grace, makeUser(USER.grace)],
  ]);
  const tokens = new Map<string, Auth.AccountToken>();

  const userStore: typeof Auth.UserServiceStore.Service = {
    get: (userId) => Effect.sync(() => users.get(userId) ?? null),
    update: (user) =>
      Effect.sync(() => {
        users.set(user.id, user);
        return user;
      }),
    delete: (userId) => Effect.sync(() => void users.delete(userId)),
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
        singleTableLayer(mapping).pipe(Layer.provide(databaseLayer(drizzle(client)))),
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
  it("refuses the claim while the user holds the current address: the change fails and the previous address stays verified", async () => {
    const h = makeHarness();
    const { token } = await h.run((svc) => svc.requestEmailChange(USER.ada, NEW));

    const err = await h.run((svc) => Effect.flip(svc.confirmEmailChange(token)));

    expect(err).toBeInstanceOf(Auth.AuthError);
    expect(err.message).toContain("allows one email identifier per user");
    expect(await readRow(USER.ada)).toEqual({ email: OLD, emailVerified: true });
    expect(h.tokens.has(token)).toBe(true);
  });

  it("an address another user claims after the change is requested fails with AccountTokenError and the previous address stays", async () => {
    const h = makeHarness();
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
