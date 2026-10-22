/**
 * The whole package exercised a second time, against a real SQLite engine.
 *
 * `better-sqlite3` is the reference synchronous driver: it runs in-process with
 * no server, and — unlike the PostgreSQL suites — it puts the *sync* result kind
 * through the seam, which is the case most likely to break a `.execute()`-based
 * abstraction. The store code under test is byte-for-byte the code the PGlite
 * suites run; only `Sqlite.tables` and the handle differ.
 *
 * The assertions deliberately mirror the PostgreSQL suites, because that is the
 * claim being made: epoch-millisecond integers behave like `timestamptz`,
 * JSON-mode `text` behaves like `jsonb`, `0`/`1` behaves like `boolean`, and the
 * `(type, value)` unique index still drives `Auth.claimIdentifier`.
 */

import Database from "better-sqlite3";
import type { Logger } from "drizzle-orm";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { Effect, Layer } from "effect";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { layer } from "./Layers.ts";
import {
  getIdentifierByValue,
  getSession,
  getUser,
  layer as requestsLayer,
  listIdentifiersByUser,
  type AuthRequests,
} from "./Requests.ts";
import { defineTables, migrationStatements, tables, type Tables } from "./SqliteSchema.ts";
import { identifierStoreContract } from "./testing/IdentifierStoreContract.ts";
import { conformance } from "./testing/Conformance.ts";
import * as Testing from "@thomasfosterau/effect-auth/testing";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type StoreServices = Auth.SessionStore | Auth.UserStore | Auth.IdentifierStore;

interface QueryLog {
  readonly logger: Logger;
  readonly reset: () => void;
  /** Every `SELECT` this program sent to `table`. */
  readonly selectsOn: (table: string) => ReadonlyArray<string>;
}

const makeQueryLog = (): QueryLog => {
  let queries: Array<string> = [];
  return {
    logger: {
      logQuery: (query) => {
        queries.push(query);
      },
    },
    reset: () => {
      queries = [];
    },
    selectsOn: (table) =>
      queries.filter((query) => query.startsWith("select") && query.includes(`"${table}"`)),
  };
};

/**
 * Fresh in-memory SQLite + the exported DDL + a query-counting drizzle handle,
 * closed afterwards.
 */
const withDatabase = async <A>(
  use: (
    db: BetterSQLite3Database,
    log: QueryLog,
    activeTables: Tables,
    client: Database.Database,
  ) => Promise<A>,
  names?: Parameters<typeof defineTables>[0],
): Promise<A> => {
  const client = new Database(":memory:");
  const migrateAndUse = async (): Promise<A> => {
    for (const statement of migrationStatements(names)) {
      client.exec(statement);
    }
    const log = makeQueryLog();
    return await use(
      drizzle(client, { logger: log.logger }),
      log,
      names === undefined ? tables : defineTables(names),
      client,
    );
  };
  return await migrateAndUse().finally(() => client.close());
};

/** Run a program against all three stores on a fresh SQLite database. */
const runStores = <A, E>(
  build: (
    db: BetterSQLite3Database,
    activeTables: Tables,
    client: Database.Database,
  ) => Effect.Effect<A, E, StoreServices>,
  names?: Parameters<typeof defineTables>[0],
): Promise<A> =>
  withDatabase(
    (db, _log, activeTables, client) =>
      Effect.runPromise(
        build(db, activeTables, client).pipe(
          Effect.provide(layer(activeTables).pipe(Layer.provide(databaseLayer(db)))),
        ) as Effect.Effect<A, E>,
      ),
    names,
  );

/**
 * Run a program against a single {@link requestsLayer} build — one build, so
 * one set of resolvers, which is what makes batching possible at all.
 */
const runRequests = <A, E>(
  db: BetterSQLite3Database,
  activeTables: Tables,
  program: Effect.Effect<A, E, AuthRequests>,
): Promise<A> =>
  Effect.runPromise(
    program.pipe(
      Effect.provide(requestsLayer(activeTables).pipe(Layer.provide(databaseLayer(db)))),
    ) as Effect.Effect<A, E>,
  );

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

const identifier = (overrides: Partial<Auth.Identifier> = {}): Auth.Identifier => ({
  id: "identifier-1",
  userId: "user-1",
  type: "email",
  value: "ada@example.com",
  verified: false,
  createdAt: at(0),
  ...overrides,
});

/** Insert a user row directly — `UserStore` is read-only by contract. */
const seedUser = (
  db: BetterSQLite3Database,
  activeTables: Tables,
  row: Partial<Tables["users"]["$inferInsert"]> = {},
): Effect.Effect<string> =>
  Effect.orDie(
    Effect.tryPromise(async () => {
      const id = row.id ?? "user-1";
      await db
        .insert(activeTables.users)
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
    }),
  );

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

describe("SQLite / SessionStore", () => {
  it("round-trips a session through create/get/update/delete", async () => {
    const result = await runStores(() =>
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
    // Epoch-millisecond integers come back as the exact `Date` that went in.
    expect(result.loaded?.createdAt).toEqual(at(0));
    expect(result.loaded?.expiresAt).toEqual(at(60_000));
    expect(result.loaded?.attributes).toEqual({ device: "laptop" });
    expect(result.updated.attributes).toEqual({ device: "phone" });
    expect(result.reloaded?.expiresAt).toEqual(at(120_000));
    expect(result.reloaded?.lastActivityAt).toEqual(at(30_000));
    expect(result.reloaded?.attributes).toEqual({ device: "phone" });
    expect(result.afterDelete).toBeNull();
  });

  it("round-trips nested attribute bags through JSON-mode text", async () => {
    const attributes = {
      device: "laptop",
      count: 42,
      ratio: 0.5,
      active: true,
      missing: null,
      roles: ["admin", "editor"],
      nested: { ip: "10.0.0.1", tags: [1, 2, 3] },
    };

    const result = await runStores(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        yield* store.create(makeSession({ attributes }));
        yield* store.create(makeSession({ id: "session-2", attributes: {} }));
        return {
          rich: yield* store.get("session-1"),
          empty: yield* store.get("session-2"),
        };
      }),
    );

    expect(result.rich?.attributes).toEqual(attributes);
    expect(result.empty?.attributes).toEqual({});
  });

  it("returns null on a miss, no-ops absent deletes, and scopes deleteByUserId", async () => {
    const result = await runStores(() =>
      Effect.gen(function* () {
        const store = yield* Auth.SessionStore;
        const missing = yield* store.get("nope");
        yield* store.delete("nope");
        yield* store.deleteByUserId("nobody");

        yield* store.create(makeSession({ id: "b", createdAt: at(2000) }));
        yield* store.create(makeSession({ id: "a", createdAt: at(1000) }));
        yield* store.create(makeSession({ id: "c", createdAt: at(3000) }));
        yield* store.create(makeSession({ id: "other", userId: "user-2" }));

        const listed = yield* store.listByUserId("user-1");
        yield* store.deleteByUserId("user-1");

        return {
          missing,
          listed,
          afterDelete: yield* store.listByUserId("user-1"),
          untouched: yield* store.listByUserId("user-2"),
        };
      }),
    );

    expect(result.missing).toBeNull();
    expect(result.listed.map((session) => session.id)).toEqual(["a", "b", "c"]);
    expect(result.afterDelete).toEqual([]);
    expect(result.untouched.map((session) => session.id)).toEqual(["other"]);
  });
});

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

describe("SQLite / UserStore", () => {
  it("maps rows to users, omitting absent optional fields", async () => {
    const result = await runStores((db, activeTables) =>
      Effect.gen(function* () {
        yield* seedUser(db, activeTables, {
          id: "full",
          name: "Ada",
          image: "https://example.com/a.png",
          attributes: { plan: "pro", flags: { beta: true } },
          createdAt: at(0),
          updatedAt: at(5000),
        });
        yield* seedUser(db, activeTables, { id: "bare" });

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
});

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

describe("SQLite / IdentifierStore", () => {
  it("creates, resolves by (type, value), lists by createdAt and deletes", async () => {
    const result = await runStores(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        const created = yield* store.create(identifier());
        yield* store.create(
          identifier({ id: "identifier-2", type: "username", value: "ada", createdAt: at(1000) }),
        );
        yield* store.create(
          identifier({ id: "identifier-3", value: "b@example.com", createdAt: at(2000) }),
        );
        yield* store.create(identifier({ id: "other", userId: "user-2", value: "z@example.com" }));

        const byEmail = yield* store.getByValue("email", "ada@example.com");
        const byUsername = yield* store.getByValue("username", "ada");
        // Same value, different type — the unique key is the pair.
        const crossType = yield* store.getByValue("phone", "ada@example.com");
        const missing = yield* store.getByValue("email", "nobody@example.com");

        const listed = yield* store.listByUser("user-1");
        yield* store.delete("identifier-3");
        yield* store.delete("never-existed");
        const afterSingle = yield* store.listByUser("user-1");
        yield* store.deleteByUser("user-1");
        yield* store.deleteByUser("ghost");

        return {
          created,
          byEmail,
          byUsername,
          crossType,
          missing,
          listed,
          afterSingle,
          afterBulk: yield* store.listByUser("user-1"),
          kept: yield* store.listByUser("user-2"),
        };
      }),
    );

    expect(result.created).toEqual(identifier());
    expect(result.byEmail).toEqual(identifier());
    // `verified` survives the 0/1 round trip as a real boolean...
    expect(result.byEmail?.verified).toBe(false);
    // ...and a NULL `verified_at` is omitted, not surfaced as null.
    expect(result.byEmail && "verifiedAt" in result.byEmail).toBe(false);
    expect(result.byUsername?.id).toBe("identifier-2");
    expect(result.crossType).toBeNull();
    expect(result.missing).toBeNull();
    expect(result.listed.map((row) => row.id)).toEqual([
      "identifier-1",
      "identifier-2",
      "identifier-3",
    ]);
    expect(result.afterSingle.map((row) => row.id)).toEqual(["identifier-1", "identifier-2"]);
    expect(result.afterBulk).toEqual([]);
    expect(result.kept.map((row) => row.id)).toEqual(["other"]);
  });

  it("rejects a duplicate (type, value) with AuthError, which claimIdentifier reads as taken", async () => {
    const result = await runStores(() =>
      Effect.gen(function* () {
        const store = yield* Auth.IdentifierStore;
        yield* store.create(identifier());

        const duplicate = yield* Effect.flip(
          store.create(identifier({ id: "identifier-2", userId: "user-2" })),
        );
        const claim = yield* Effect.flip(
          Auth.claimIdentifier(store, identifier({ id: "identifier-3", userId: "user-2" })),
        );
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

  it("setVerified stamps the timestamp and returns null for an unknown id", async () => {
    // MySQL has no `RETURNING`, so the store updates and then re-reads. That
    // path has to behave identically here to the PostgreSQL suite's.
    const result = await runStores(() =>
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
});

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

describe("SQLite / Schema", () => {
  it("drives every store from custom table names", async () => {
    const names = {
      sessions: "app_sessions",
      users: "app_users",
      identifiers: "app_identifiers",
    };

    const result = await runStores(
      (db, activeTables, client) =>
        Effect.gen(function* () {
          yield* seedUser(db, activeTables, { id: "user-1" });

          const sessions = yield* Auth.SessionStore;
          const users = yield* Auth.UserStore;
          const identifiers = yield* Auth.IdentifierStore;

          yield* sessions.create(makeSession({ attributes: { via: "custom" } }));
          yield* identifiers.create(identifier());

          const present = yield* Effect.sync(() =>
            (
              client
                .prepare(
                  "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .all() as Array<{ name: string }>
            ).map((row) => row.name),
          );

          return {
            present,
            session: yield* sessions.get("session-1"),
            user: yield* users.get("user-1"),
            identifier: yield* identifiers.getByValue("email", "ada@example.com"),
          };
        }),
      names,
    );

    expect(result.present).toEqual(["app_identifiers", "app_sessions", "app_users"]);
    expect(result.session?.attributes).toEqual({ via: "custom" });
    expect(result.user?.id).toBe("user-1");
    expect(result.identifier?.id).toBe("identifier-1");
  });

  it("emits SQLite DDL matching the requested table names", () => {
    const statements = migrationStatements();
    expect(statements).toHaveLength(6);
    expect(statements[0]).toContain("CREATE TABLE IF NOT EXISTS effect_auth_users");
    // Instants are epoch-millisecond integers, bags are JSON text, flags are 0/1.
    expect(statements[0]).toContain("created_at INTEGER NOT NULL");
    expect(statements[0]).toContain("attributes TEXT NOT NULL DEFAULT '{}'");
    expect(statements[3]).toContain("verified INTEGER NOT NULL DEFAULT 0");
    expect(statements[4]).toContain(
      "CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_identifiers_type_value_key",
    );
    // No email columns on users: handles live in the identifiers table.
    expect(statements[0]).not.toContain("email");
  });
});

// ---------------------------------------------------------------------------
// Batched reads
// ---------------------------------------------------------------------------

describe("SQLite / Requests", () => {
  it("batches every read path into one query per resolver", async () => {
    await withDatabase(async (db, log, activeTables) => {
      await db
        .insert(activeTables.users)
        .values([
          {
            id: "user-1",
            name: "name-user-1",
            image: null,
            passwordHash: "argon2id$hash",
            attributes: {},
            createdAt: at(0),
            updatedAt: at(0),
          },
          {
            id: "user-2",
            name: "name-user-2",
            image: null,
            passwordHash: null,
            attributes: {},
            createdAt: at(0),
            updatedAt: at(0),
          },
        ])
        .execute();
      await db
        .insert(activeTables.sessions)
        .values({
          id: "session-1",
          userId: "user-1",
          expiresAt: at(60_000),
          createdAt: at(0),
          lastActivityAt: at(0),
          attributes: { device: "laptop" },
        })
        .execute();
      await db
        .insert(activeTables.identifiers)
        .values([
          {
            id: "email-1",
            userId: "user-1",
            type: "email",
            value: "ada@example.com",
            verified: false,
            verifiedAt: null,
            createdAt: at(1000),
          },
          {
            id: "name-1",
            userId: "user-1",
            type: "username",
            value: "ada",
            verified: false,
            verifiedAt: null,
            createdAt: at(2000),
          },
        ])
        .execute();
      log.reset();

      const program = Effect.all(
        [
          Effect.all([getUser("user-1"), getUser("user-1"), getUser("user-2"), getUser("ghost")], {
            concurrency: "unbounded",
          }),
          getSession("session-1"),
          getSession("nope"),
          Effect.all(
            [
              getIdentifierByValue("email", "ada@example.com"),
              getIdentifierByValue("username", "ada"),
              getIdentifierByValue("phone", "ada@example.com"),
            ],
            { concurrency: "unbounded" },
          ),
          listIdentifiersByUser("user-1"),
          listIdentifiersByUser("ghost"),
        ],
        { concurrency: "unbounded" },
      );

      const [users, session, missingSession, byValue, mine, none] = await runRequests(
        db,
        activeTables,
        program,
      );

      // One query per resolver: users (four reads), sessions, identifiers-by-pair
      // and identifiers-by-user.
      expect(log.selectsOn("effect_auth_users")).toHaveLength(1);
      expect(log.selectsOn("effect_auth_sessions")).toHaveLength(1);
      expect(log.selectsOn("effect_auth_identifiers")).toHaveLength(2);

      expect(users.map((user) => user?.id ?? null)).toEqual(["user-1", "user-1", "user-2", null]);
      expect(users[0]?.name).toBe("name-user-1");
      expect(session?.attributes).toEqual({ device: "laptop" });
      expect(missingSession).toBeNull();
      expect(byValue.map((row) => row?.id ?? null)).toEqual(["email-1", "name-1", null]);
      expect(mine.map((row) => row.id)).toEqual(["email-1", "name-1"]);
      expect(none).toEqual([]);
    });
  });
});

// The shared IdentifierStore contract (#182), run against the multi-identifier
// store on SQLite as well as on PostgreSQL: a fresh database per test.
describe("SQLite / IdentifierStore contract", () => {
  let client: Database.Database;
  let db: BetterSQLite3Database;

  beforeEach(() => {
    client = new Database(":memory:");
    for (const statement of migrationStatements()) {
      client.exec(statement);
    }
    db = drizzle(client);
  });

  afterEach(() => {
    client.close();
  });

  identifierStoreContract("IdentifierStore (multi-identifier) SQLite", {
    run: <A, E>(build: () => Effect.Effect<A, E, Auth.IdentifierStore>): Promise<A> =>
      Effect.runPromise(
        build().pipe(
          Effect.provide(layer(tables).pipe(Layer.provide(databaseLayer(db)))),
        ) as Effect.Effect<A, E>,
      ),
    seedUsers: async () => {},
  });

  // The core's published IdentifierStore suite, over the same store.
  conformance(
    "IdentifierStore (multi-identifier) SQLite",
    Testing.identifierStoreConformance(),
    (effect) =>
      Effect.runPromise(
        effect.pipe(
          Effect.provide(layer(tables).pipe(Layer.provide(databaseLayer(db)))),
        ) as Effect.Effect<void>,
      ),
  );
});
