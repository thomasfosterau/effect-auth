/**
 * `EmailPasswordStore`, `ApiKeyStore`, `RateLimitStore` and the token stores on
 * PostgreSQL (PGlite, in-process), twice: through drizzle's Promise driver
 * (`drizzle-orm/pglite`) and through its Effect driver (`effect-pglite`, the
 * 1.0 line's `drizzle-orm/effect-*` family that `drizzle-orm/effect-postgres`
 * belongs to), so the upsert's `RETURNING` and the unique key-hash index run
 * on a real engine on both seams (#675).
 *
 * Then `EmailPasswordStore` over an application's own users table through
 * `defineSchema`: `password_hash` mapped, and a promoted `role` that takes the
 * column's default when sign-up names none; and `UserServiceStore` over the
 * same table, writing to renamed and promoted columns (#728).
 */

import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import { drizzle } from "drizzle-orm/pglite";
import { pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import * as EffectPglite from "drizzle-orm-effect/effect-pglite";
import { Cause, Effect, Exit, Layer } from "effect";
import { afterAll, assert, beforeAll, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { defineSchema } from "./Columns.ts";
import { databaseLayer, effectDatabaseLayer } from "./Database.ts";
import * as EmailPasswordStore from "./EmailPasswordStore.ts";
import { tables } from "./PgSchema.ts";
import * as UserServiceStore from "./UserServiceStore.ts";
import * as UserStore from "./UserStore.ts";
import { authStoresContract, authStoresLayer } from "./testing/AuthStoresContract.ts";
import { migratedPglite } from "./testing/PgliteTemplate.ts";

/**
 * The file's one in-memory Postgres, opened from the run's migrated template
 * (#291). Every case mints its own ids, so nothing is truncated between them.
 */
let client: PGlite;

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec(`
    CREATE TABLE app_users (
      id uuid PRIMARY KEY,
      display_name text,
      avatar_url text,
      role text NOT NULL DEFAULT 'member',
      plan text,
      password_hash text,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    );
  `);
});

afterAll(async () => {
  await client?.close();
});

authStoresContract("PostgreSQL, Promise driver", (effect) =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(
        authStoresLayer(tables).pipe(Layer.provide(databaseLayer(drizzle({ client })))),
      ),
    ),
  ),
);

authStoresContract("PostgreSQL, Effect driver", (effect) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const db = yield* EffectPglite.make();
      return yield* effect.pipe(
        Effect.provide(authStoresLayer(tables).pipe(Layer.provide(effectDatabaseLayer(db)))),
      );
    }).pipe(
      Effect.provide(
        Layer.mergeAll(EffectPglite.DefaultServices, PgliteClient.layer({ liveClient: client })),
      ),
    ),
  ),
);

/** An application's own users table: uuid key, its own names, a promoted role, no bag. */
const appUsers = pgTable("app_users", {
  userId: uuid("id").primaryKey(),
  displayName: text("display_name"),
  avatarUrl: text("avatar_url"),
  role: text("role").notNull().default("member"),
  plan: text("plan"),
  passwordHash: text("password_hash"),
  created: timestamp("created_at", { mode: "date", withTimezone: true }).notNull(),
  updated: timestamp("updated_at", { mode: "date", withTimezone: true }).notNull(),
});

const adopted = (passwordHash: "passwordHash" | undefined) =>
  defineSchema({
    sessions: {
      table: tables.sessions,
      columns: {
        id: "id",
        userId: "userId",
        expiresAt: "expiresAt",
        createdAt: "createdAt",
        lastActivityAt: "lastActivityAt",
        attributes: "attributes",
      },
    },
    users: {
      table: appUsers,
      columns: {
        id: "userId",
        name: "displayName",
        image: "avatarUrl",
        createdAt: "created",
        updatedAt: "updated",
        ...(passwordHash === undefined ? {} : { passwordHash }),
      },
      promoted: { role: "role", plan: "plan" },
    },
    identifiers: {
      table: tables.identifiers,
      columns: {
        id: "id",
        userId: "userId",
        type: "type",
        value: "value",
        verified: "verified",
        verifiedAt: "verifiedAt",
        createdAt: "createdAt",
      },
    },
  });

const runAdopted = <A, E>(
  effect: Effect.Effect<
    A,
    E,
    Auth.Email.EmailPasswordStore | Auth.UserStore | Auth.UserServiceStore
  >,
  passwordHash: "passwordHash" | undefined = "passwordHash",
): Promise<A> =>
  Effect.runPromise(
    effect.pipe(
      Effect.provide(
        Layer.mergeAll(
          EmailPasswordStore.layer(adopted(passwordHash)),
          UserStore.layer(adopted(passwordHash)),
          UserServiceStore.layer(adopted(passwordHash)),
        ).pipe(Layer.provide(databaseLayer(drizzle({ client })))),
      ),
    ),
  );

describe("EmailPasswordStore on an application's own users table", () => {
  it("writes a promoted attribute to its column, and reads back the column's default", async () => {
    const result = await runAdopted(
      Effect.gen(function* () {
        const store = yield* Auth.Email.EmailPasswordStore;
        const users = yield* Auth.UserStore;
        const member = yield* store.createUser({ name: "Ada" });
        const admin = yield* store.createUser({ name: "Grace", attributes: { role: "admin" } });
        yield* store.setPasswordHash(admin.user.id, "hash");
        return {
          member: member.user,
          admin: yield* users.get(admin.user.id),
          hash: yield* store.getPasswordHash(admin.user.id),
        };
      }),
    );
    expect(result.member.attributes).toEqual({ role: "member" });
    expect(result.admin?.attributes).toEqual({ role: "admin" });
    expect(result.hash).toBe("hash");
  });

  it("refuses attributes a table with no bag cannot hold", async () => {
    const error = await runAdopted(
      Effect.flip(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailPasswordStore;
          return yield* store.createUser({ attributes: { team: "core" } });
        }),
      ),
    );
    expect(error).toBeInstanceOf(Auth.AuthError);
    expect(error.message).toContain("no attribute bag for team");
  });

  it("dies at layer construction when passwordHash is unmapped", async () => {
    const exit = await Effect.runPromiseExit(
      Effect.provide(
        Effect.void,
        EmailPasswordStore.layer(adopted(undefined)).pipe(
          Layer.provide(databaseLayer(drizzle({ client }))),
        ),
      ),
    );
    assert(Exit.isFailure(exit));
    expect(Cause.pretty(exit.cause)).toContain("map `passwordHash` in defineSchema");
  });
});

describe("UserServiceStore on an application's own users table", () => {
  it("writes name and image to their renamed columns and promoted attributes to theirs", async () => {
    const result = await runAdopted(
      Effect.gen(function* () {
        const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
          store.createUser({ name: "Ada" }),
        );
        const store = yield* Auth.UserServiceStore;
        yield* store.update({
          ...user,
          name: "Grace",
          image: "g.png",
          attributes: { role: "admin", plan: "pro" },
        });
        const promoted = yield* store.get(user.id);
        // A promoted attribute the user no longer has clears its column.
        yield* store.update({ ...user, attributes: { role: "member" } });
        return { id: user.id, promoted, cleared: yield* store.get(user.id) };
      }),
    );
    const row = await client.query("SELECT role, plan FROM app_users WHERE id = $1", [result.id]);
    expect(result.promoted?.name).toBe("Grace");
    expect(result.promoted?.image).toBe("g.png");
    expect(result.promoted?.attributes).toEqual({ role: "admin", plan: "pro" });
    expect(result.cleared?.name).toBe("Ada");
    expect(result.cleared?.image).toBeUndefined();
    expect(result.cleared?.attributes).toEqual({ role: "member" });
    expect(row.rows).toEqual([{ role: "member", plan: null }]);
  });

  it("refuses attributes a table with no bag cannot hold, writing nothing", async () => {
    const result = await runAdopted(
      Effect.gen(function* () {
        const { user } = yield* Auth.Email.EmailPasswordStore.use((store) =>
          store.createUser({ name: "Ada" }),
        );
        const store = yield* Auth.UserServiceStore;
        const error = yield* Effect.flip(
          store.update({ ...user, name: "Grace", attributes: { role: "admin", team: "core" } }),
        );
        return { error, read: yield* store.get(user.id) };
      }),
    );
    expect(result.error).toBeInstanceOf(Auth.AuthError);
    expect(result.error.message).toContain("drizzle userService.update failed");
    expect(result.error.message).toContain("no attribute bag for team");
    expect(result.read?.name).toBe("Ada");
    expect(result.read?.attributes).toEqual({ role: "member" });
  });

  it("deletes the row, which then reads null", async () => {
    const result = await runAdopted(
      Effect.gen(function* () {
        const { user } = yield* Auth.Email.EmailPasswordStore.use((store) => store.createUser({}));
        const store = yield* Auth.UserServiceStore;
        yield* store.delete(user.id);
        return yield* store.get(user.id);
      }),
    );
    expect(result).toBeNull();
  });
});
