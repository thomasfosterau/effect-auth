/**
 * The drizzle stores exercised against a real PostgreSQL engine.
 *
 * `@electric-sql/pglite` is Postgres compiled to WASM: it runs in-process with
 * no server, so `jsonb`, `timestamptz`, `RETURNING` and unique-index
 * violations behave exactly as they do in production — the very things a mock
 * would paper over.
 */

import { PGlite } from "@electric-sql/pglite";
import { getTableName } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer, type DrizzlePgDatabase } from "./Database.ts";
import {
  defineTables,
  identifiersTable,
  migrationSql,
  migrationStatements,
  sessionsTable,
  type TableNames,
  type Tables,
  tables as defaultTables,
  usersTable,
} from "./Schema.ts";
import { layer } from "./Stores.ts";

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

/**
 * Spin up a fresh in-memory Postgres, apply the exported DDL, run `build`'s
 * program against all three stores, then tear the database down.
 */
const runFresh = async <A, E>(
  build: (db: DrizzlePgDatabase, tables: Tables) => Effect.Effect<A, E, StoreServices>,
  names?: Partial<TableNames>,
): Promise<A> => {
  const client = await PGlite.create();
  try {
    for (const statement of migrationStatements(names)) {
      await client.exec(statement);
    }
    const db = drizzle(client);
    const tables = names === undefined ? defaultTables : defineTables(names);
    return await Effect.runPromise(
      build(db, tables).pipe(
        Effect.provide(layer(tables).pipe(Layer.provide(databaseLayer(db)))),
      ) as Effect.Effect<A, E>,
    );
  } finally {
    await client.close();
  }
};

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

const makeSession = (overrides: Partial<Auth.Session> = {}): Auth.Session => ({
  id: "session-1",
  userId: "user-1",
  expiresAt: at(60_000),
  createdAt: at(0),
  lastActivityAt: at(0),
  attributes: {},
  ...overrides,
});

/** Insert a user row directly — `UserStore` is read-only by contract. */
const seedUser = (
  db: DrizzlePgDatabase,
  tables: Tables,
  row: Partial<Tables["users"]["$inferInsert"]> = {},
): Effect.Effect<string> =>
  Effect.promise(async () => {
    const id = row.id ?? "user-1";
    await db
      .insert(tables.users)
      .values({
        id,
        name: null,
        image: null,
        passwordHash: null,
        attributes: {},
        createdAt: at(0),
        updatedAt: at(0),
        ...row,
      })
      .execute();
    return id;
  });

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

describe("SessionStore", () => {
  it("round-trips a session through create/get/update/delete", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const session = makeSession({ attributes: { device: "laptop" } });

        const created = yield* store.create(session);
        const loaded = yield* store.get(session.id);
        const updated = yield* store.update({
          ...session,
          expiresAt: at(120_000),
          lastActivityAt: at(30_000),
          attributes: { device: "phone" },
        });
        const reloaded = yield* store.get(session.id);
        yield* store.delete(session.id);
        const afterDelete = yield* store.get(session.id);

        return { created, loaded, updated, reloaded, afterDelete };
      }),
    );

    expect(result.created).toEqual(makeSession({ attributes: { device: "laptop" } }));
    expect(result.loaded?.id).toBe("session-1");
    expect(result.loaded?.userId).toBe("user-1");
    expect(result.loaded?.createdAt).toEqual(at(0));
    expect(result.loaded?.expiresAt).toEqual(at(60_000));
    expect(result.loaded?.attributes).toEqual({ device: "laptop" });
    expect(result.updated.attributes).toEqual({ device: "phone" });
    expect(result.reloaded?.expiresAt).toEqual(at(120_000));
    expect(result.reloaded?.lastActivityAt).toEqual(at(30_000));
    expect(result.reloaded?.attributes).toEqual({ device: "phone" });
    expect(result.afterDelete).toBeNull();
  });

  it("returns null on a miss and no-ops on deletes of absent rows", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const missing = yield* store.get("nope");
        yield* store.delete("nope");
        yield* store.deleteByUserId("nobody");
        const listed = yield* store.listByUserId("nobody");
        return { missing, listed };
      }),
    );

    expect(result.missing).toBeNull();
    expect(result.listed).toEqual([]);
  });

  it("stores expiry as timestamptz without interpreting it", async () => {
    // Expiry is the service layer's decision; the store persists and returns
    // whatever instant it was given, including one already in the past.
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const expired = makeSession({ id: "expired", expiresAt: at(-60_000) });
        const future = makeSession({ id: "future", expiresAt: at(86_400_000) });
        yield* store.create(expired);
        yield* store.create(future);
        return {
          expired: yield* store.get("expired"),
          future: yield* store.get("future"),
        };
      }),
    );

    expect(result.expired?.expiresAt).toEqual(at(-60_000));
    expect(result.expired?.expiresAt.getTime()).toBeLessThan(result.future!.expiresAt.getTime());
    expect(result.future?.expiresAt).toEqual(at(86_400_000));
  });

  it("round-trips nested attribute bags through jsonb", async () => {
    const attributes = {
      device: "laptop",
      count: 42,
      ratio: 0.5,
      active: true,
      missing: null,
      roles: ["admin", "editor"],
      nested: { ip: "10.0.0.1", tags: [1, 2, 3] },
    };

    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(makeSession({ attributes }));
        const empty = makeSession({ id: "session-2", attributes: {} });
        yield* store.create(empty);
        return {
          rich: yield* store.get("session-1"),
          empty: yield* store.get("session-2"),
        };
      }),
    );

    expect(result.rich?.attributes).toEqual(attributes);
    expect(result.empty?.attributes).toEqual({});
  });

  it("lists a user's sessions by createdAt and scopes deleteByUserId", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(makeSession({ id: "b", createdAt: at(2000) }));
        yield* store.create(makeSession({ id: "a", createdAt: at(1000) }));
        yield* store.create(makeSession({ id: "c", createdAt: at(3000) }));
        yield* store.create(makeSession({ id: "other", userId: "user-2" }));

        const listed = yield* store.listByUserId("user-1");
        yield* store.deleteByUserId("user-1");
        return {
          listed,
          afterDelete: yield* store.listByUserId("user-1"),
          untouched: yield* store.listByUserId("user-2"),
        };
      }),
    );

    expect(result.listed.map((session) => session.id)).toEqual(["a", "b", "c"]);
    expect(result.afterDelete).toEqual([]);
    expect(result.untouched.map((session) => session.id)).toEqual(["other"]);
  });
});

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

describe("UserStore", () => {
  it("maps rows to users, omitting absent optional fields", async () => {
    const result = await runFresh((db, tables) =>
      Effect.gen(function* () {
        yield* seedUser(db, tables, {
          id: "full",
          name: "Ada",
          image: "https://example.com/a.png",
          attributes: { plan: "pro", flags: { beta: true } },
          createdAt: at(0),
          updatedAt: at(5000),
        });
        yield* seedUser(db, tables, { id: "bare" });

        const store = yield* Auth.UserStore;
        return {
          full: yield* store.get("full"),
          bare: yield* store.get("bare"),
          missing: yield* store.get("ghost"),
        };
      }),
    );

    expect(result.full).toEqual({
      id: "full",
      name: "Ada",
      image: "https://example.com/a.png",
      createdAt: at(0),
      updatedAt: at(5000),
      attributes: { plan: "pro", flags: { beta: true } },
    });
    expect(result.bare).toEqual({
      id: "bare",
      createdAt: at(0),
      updatedAt: at(0),
      attributes: {},
    });
    expect(result.bare && "name" in result.bare).toBe(false);
    expect(result.bare && "image" in result.bare).toBe(false);
    expect(result.missing).toBeNull();
  });

  it("reads getCredentials from password_hash", async () => {
    const result = await runFresh((db, tables) =>
      Effect.gen(function* () {
        yield* seedUser(db, tables, { id: "with-password", passwordHash: "argon2id$hash" });
        yield* seedUser(db, tables, { id: "no-password" });

        const store = yield* Auth.UserStore;
        return {
          withPassword: yield* store.getCredentials("with-password"),
          withoutPassword: yield* store.getCredentials("no-password"),
          missingUser: yield* store.getCredentials("ghost"),
        };
      }),
    );

    expect(result.withPassword).toBe("argon2id$hash");
    expect(result.withoutPassword).toBeNull();
    expect(result.missingUser).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// IdentifierStore
// ---------------------------------------------------------------------------

const identifier = (overrides: Partial<Auth.Identifier> = {}): Auth.Identifier => ({
  id: "identifier-1",
  userId: "user-1",
  type: "email",
  value: "ada@example.com",
  verified: false,
  createdAt: at(0),
  ...overrides,
});

describe("IdentifierStore", () => {
  it("creates and resolves identifiers by (type, value)", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        const created = yield* store.create(identifier());
        yield* store.create(
          identifier({ id: "identifier-2", type: "username", value: "ada", createdAt: at(1000) }),
        );

        return {
          created,
          byEmail: yield* store.getByValue("email", "ada@example.com"),
          byUsername: yield* store.getByValue("username", "ada"),
          // Same value, different type — the unique key is the pair.
          crossType: yield* store.getByValue("phone", "ada@example.com"),
          missing: yield* store.getByValue("email", "nobody@example.com"),
        };
      }),
    );

    expect(result.created).toEqual(identifier());
    expect(result.byEmail).toEqual(identifier());
    expect(result.byEmail && "verifiedAt" in result.byEmail).toBe(false);
    expect(result.byUsername?.id).toBe("identifier-2");
    expect(result.crossType).toBeNull();
    expect(result.missing).toBeNull();
  });

  it("rejects a duplicate (type, value) with AuthError, which claimIdentifier reads as taken", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(identifier());

        // The unique index rejects the losing INSERT; the store surfaces it as
        // an AuthError carrying the driver error as `cause`.
        const duplicate = yield* Effect.flip(
          store.create(identifier({ id: "identifier-2", userId: "user-2" })),
        );
        // claimIdentifier re-reads the pair and reports a conflict instead.
        const claim = yield* Effect.flip(
          Auth.claimIdentifier(store, identifier({ id: "identifier-3", userId: "user-2" })),
        );
        // A free pair still claims cleanly after the rejection.
        const free = yield* Auth.claimIdentifier(
          store,
          identifier({ id: "identifier-4", userId: "user-2", value: "grace@example.com" }),
        );

        return {
          duplicate,
          claim,
          free,
          owner: yield* store.getByValue("email", "ada@example.com"),
        };
      }),
    );

    expect(result.duplicate._tag).toBe("AuthError");
    expect(result.duplicate.message).toBe("drizzle identifier.create failed");
    expect(result.duplicate.cause).toBeDefined();

    expect(result.claim._tag).toBe("IdentifierTakenError");
    expect((result.claim as Auth.IdentifierTakenError).identifierType).toBe("email");

    expect(result.free.id).toBe("identifier-4");
    // The loser never overwrote the original owner.
    expect(result.owner?.userId).toBe("user-1");
  });

  it("lists a user's identifiers by createdAt ascending", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(
          identifier({ id: "third", value: "c@example.com", createdAt: at(3000) }),
        );
        yield* store.create(
          identifier({ id: "first", value: "a@example.com", createdAt: at(1000) }),
        );
        yield* store.create(
          identifier({ id: "second", value: "b@example.com", createdAt: at(2000) }),
        );
        yield* store.create(identifier({ id: "other", userId: "user-2", value: "z@example.com" }));

        return {
          listed: yield* store.listByUser("user-1"),
          none: yield* store.listByUser("ghost"),
        };
      }),
    );

    expect(result.listed.map((row) => row.id)).toEqual(["first", "second", "third"]);
    expect(result.none).toEqual([]);
  });

  it("setVerified stamps the timestamp and returns null for an unknown id", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(identifier());
        const verified = yield* store.setVerified("identifier-1", at(9000));
        return {
          verified,
          reloaded: yield* store.getByValue("email", "ada@example.com"),
          unknown: yield* store.setVerified("ghost", at(9000)),
        };
      }),
    );

    expect(result.verified?.verified).toBe(true);
    expect(result.verified?.verifiedAt).toEqual(at(9000));
    expect(result.reloaded?.verified).toBe(true);
    expect(result.reloaded?.verifiedAt).toEqual(at(9000));
    expect(result.unknown).toBeNull();
  });

  it("deletes one identifier or every identifier of a user, no-op when absent", async () => {
    const result = await runFresh(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(identifier({ id: "email-1" }));
        yield* store.create(identifier({ id: "user-name", type: "username", value: "ada" }));
        yield* store.create(identifier({ id: "kept", userId: "user-2", value: "z@example.com" }));

        yield* store.delete("email-1");
        yield* store.delete("never-existed");
        const afterSingle = yield* store.listByUser("user-1");

        yield* store.deleteByUser("user-1");
        yield* store.deleteByUser("ghost");

        return {
          afterSingle,
          afterBulk: yield* store.listByUser("user-1"),
          kept: yield* store.listByUser("user-2"),
        };
      }),
    );

    expect(result.afterSingle.map((row) => row.id)).toEqual(["user-name"]);
    expect(result.afterBulk).toEqual([]);
    expect(result.kept.map((row) => row.id)).toEqual(["kept"]);
  });
});

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

describe("Schema", () => {
  it("drives every store from custom table names", async () => {
    const names: TableNames = {
      sessions: "app_sessions",
      users: "app_users",
      identifiers: "app_identifiers",
    };

    const result = await runFresh(
      (db, tables) =>
        Effect.gen(function* () {
          yield* seedUser(db, tables, { id: "user-1", passwordHash: "hash" });

          const sessions = yield* Auth.SessionStore;
          const users = yield* Auth.UserStore;
          const identifiers = yield* Auth.IdentifierStore;

          yield* sessions.create(makeSession({ attributes: { via: "custom" } }));
          yield* identifiers.create(identifier());

          const present = yield* Effect.promise(async () => {
            const rows = await db.execute(
              `SELECT table_name FROM information_schema.tables
                 WHERE table_schema = 'public' ORDER BY table_name`,
            );
            const list = Array.isArray(rows) ? rows : (rows as { rows: unknown[] }).rows;
            return list.map((row) => (row as { table_name: string }).table_name);
          });

          return {
            present,
            session: yield* sessions.get("session-1"),
            credentials: yield* users.getCredentials("user-1"),
            identifier: yield* identifiers.getByValue("email", "ada@example.com"),
          };
        }),
      names,
    );

    expect(result.present).toEqual(["app_identifiers", "app_sessions", "app_users"]);
    expect(result.session?.attributes).toEqual({ via: "custom" });
    expect(result.credentials).toBe("hash");
    expect(result.identifier?.id).toBe("identifier-1");
  });

  it("emits DDL matching the requested table names", () => {
    const statements = migrationStatements();
    expect(statements).toHaveLength(6);
    expect(statements[0]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_users");
    expect(statements[1]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_sessions");
    expect(statements[3]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_identifiers");
    expect(statements[4]).toContain(
      "CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_identifiers_type_value_key",
    );
    // No email columns on users: handles live in the identifiers table.
    expect(statements[0]).not.toContain("email");

    const custom = migrationSql({ users: "app_users" });
    expect(custom).toContain("CREATE TABLE IF NOT EXISTS app_users");
    expect(custom).toContain("CREATE TABLE IF NOT EXISTS effect_auth_sessions");
    expect(custom.endsWith(";\n")).toBe(true);
  });

  it("names the exported tables effect_auth_* and honours per-table overrides", () => {
    expect([
      getTableName(sessionsTable),
      getTableName(usersTable),
      getTableName(identifiersTable),
    ]).toEqual(["effect_auth_sessions", "effect_auth_users", "effect_auth_identifiers"]);
    expect(sessionsTable).toBe(defaultTables.sessions);

    const custom = defineTables({ sessions: "app_sessions" });
    expect(getTableName(custom.sessions)).toBe("app_sessions");
    // Unspecified names keep their defaults.
    expect(getTableName(custom.users)).toBe("effect_auth_users");
  });
});
