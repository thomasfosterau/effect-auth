import { afterAll, assert, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";
import { Array as Arr, Data, Effect, Layer, Order, Predicate, Stream } from "effect";
import { SqlClient, SqlConnection, SqlError, Statement } from "effect/sql";
import { Reactivity } from "effect/reactivity";
import Database from "better-sqlite3";
import type { PGlite } from "@electric-sql/pglite";
import * as PgliteClient from "@effect/sql-pglite/PgliteClient";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { migrate, schemaStatements } from "./Schema.ts";
import * as Sql from "./Stores.ts";
import { layer } from "./Stores.ts";
import { migratedPglite } from "./testing/PgliteTemplate.ts";

// ---------------------------------------------------------------------------
// Minimal test-only SqlClient over better-sqlite3.
//
// This is a real `SqlClient` built with `SqlClient.make` from
// effect/sql — the same construction path a production driver uses —
// backed by an in-memory SQLite database, so the stores are exercised through
// the genuine tagged-template/compiler pipeline.
// ---------------------------------------------------------------------------

/** The failure the broken test connection reports. */
class SimulatedFailure extends Data.TaggedError("SimulatedFailure")<{ readonly message: string }> {}

const driverError = (cause: unknown): SqlError.SqlError =>
  new SqlError.SqlError({
    reason: new SqlError.UnknownError({
      cause,
      message: Predicate.isError(cause) ? cause.message : "sqlite error",
    }),
  });

const makeConnection = (db: Database.Database): SqlConnection.Connection => {
  const runStatement = (
    sqlText: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<any>, SqlError.SqlError> =>
    Effect.try({
      try: () => {
        const statement = db.prepare(sqlText);
        if (statement.reader) {
          return statement.all(...(params as ReadonlyArray<never>)) as ReadonlyArray<any>;
        }
        statement.run(...(params as ReadonlyArray<never>));
        return [] as ReadonlyArray<any>;
      },
      catch: driverError,
    });

  const runValues = (
    sqlText: string,
    params: ReadonlyArray<unknown>,
  ): Effect.Effect<ReadonlyArray<ReadonlyArray<unknown>>, SqlError.SqlError> =>
    Effect.try({
      try: () => {
        const statement = db.prepare(sqlText);
        if (statement.reader) {
          return statement.raw(true).all(...(params as ReadonlyArray<never>)) as ReadonlyArray<
            ReadonlyArray<unknown>
          >;
        }
        statement.run(...(params as ReadonlyArray<never>));
        return [] as ReadonlyArray<ReadonlyArray<unknown>>;
      },
      catch: driverError,
    });

  return {
    execute: (sqlText, params, transformRows) =>
      runStatement(sqlText, params).pipe(
        Effect.map((rows) => (transformRows ? transformRows(rows) : rows)),
      ),
    executeRaw: (sqlText, params) => runStatement(sqlText, params),
    executeStream: (sqlText, params, transformRows) =>
      Stream.fromArrayEffect(
        runStatement(sqlText, params).pipe(
          Effect.map((rows) => (transformRows ? transformRows(rows) : rows)),
        ),
      ),
    executeValues: runValues,
    // better-sqlite3 has no separate unprepared path — every statement goes
    // through `db.prepare` — so the unprepared variants reuse the same
    // execution as their prepared counterparts.
    executeValuesUnprepared: runValues,
    executeUnprepared: (sqlText, params, transformRows) =>
      runStatement(sqlText, params).pipe(
        Effect.map((rows) => (transformRows ? transformRows(rows) : rows)),
      ),
  };
};

/** Fresh in-memory SqlClient layer per invocation so tests are isolated. */
const sqlClientLayer = (): Layer.Layer<SqlClient.SqlClient> =>
  Layer.effect(
    SqlClient.SqlClient,
    Effect.gen(function* () {
      const db = new Database(":memory:");
      const connection = makeConnection(db);
      return yield* SqlClient.make({
        acquirer: Effect.succeed(connection),
        compiler: Statement.makeCompilerSqlite(),
        spanAttributes: [],
      });
    }),
  ).pipe(Layer.provide(Reactivity.layer));

// ---------------------------------------------------------------------------
// Engines
//
// The same store contract runs over two real SQL engines, so every case below
// is checked on both: SQLite (better-sqlite3, a fresh in-memory database per
// test) and PostgreSQL (PGlite, Postgres compiled to WASM, one instance per
// file, opened from a migrated template and emptied before each test). Each
// engine supplies a real `SqlClient` built through effect/sql's own
// construction path, so the stores run through the genuine tagged-template and
// compiler pipeline.
// ---------------------------------------------------------------------------

/** Services a store test may need from the context, beyond the store layers. */
type StoreServices = Layer.Success<typeof layer> | SqlClient.SqlClient;

/** One SQL engine the store contract runs against. */
interface StoreEngine {
  /** Suite title. */
  readonly name: string;
  /** Statement compiler for the engine's dialect. */
  readonly compiler: Statement.Compiler;
  /** Registers the engine's per-file hooks; called inside the suite's `describe`. */
  readonly hooks: () => void;
  /** A `SqlClient` over a database holding only the auth schema, with no rows. */
  readonly client: () => Layer.Layer<SqlClient.SqlClient, SqlError.SqlError>;
  /** Names of the `auth_` tables, sorted. */
  readonly tableNames: Effect.Effect<ReadonlyArray<string>, SqlError.SqlError, SqlClient.SqlClient>;
  /** Declared column types of a table in upper case, keyed by column name. */
  readonly columnTypes: (
    table: string,
  ) => Effect.Effect<Record<string, string>, SqlError.SqlError, SqlClient.SqlClient>;
}

const sqlite: StoreEngine = {
  name: "SQLite (better-sqlite3)",
  compiler: Statement.makeCompilerSqlite(),
  hooks: () => {},
  client: sqlClientLayer,
  tableNames: Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rows = yield* sql<{ name: string }>`
      SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
    return rows.map((row) => row.name);
  }),
  columnTypes: (table) =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{
        readonly name: string;
        readonly type: string;
      }>`PRAGMA table_info(${sql.literal(table)})`;
      return Object.fromEntries(rows.map((row) => [row.name, row.type.toUpperCase()]));
    }),
};

// ---------------------------------------------------------------------------
// PostgreSQL over PGlite. The instance is opened in the suite's `beforeAll`
// from the run's migrated template (see testing/PgliteTemplate.setup.ts), so a
// boot skips initdb and the migrations and stays well inside the hook timeout.
// ---------------------------------------------------------------------------

/** The auth tables, in schema order, read from the DDL the stores ship with. */
const authTables: ReadonlyArray<string> = schemaStatements.flatMap((statement) => {
  const name = /^CREATE TABLE IF NOT EXISTS (\w+)/.exec(statement)?.[1];
  return name === undefined ? [] : [name];
});

let database: PGlite | undefined;

const openDatabase = (): PGlite => {
  assert(database !== undefined, "the PGlite database is opened in the suite's beforeAll");
  return database;
};

const postgres: StoreEngine = {
  name: "PostgreSQL (PGlite)",
  compiler: PgliteClient.makeCompiler(),
  hooks: () => {
    beforeAll(async () => {
      database = await migratedPglite();
    });
    beforeEach(async () => {
      await openDatabase().exec(`TRUNCATE ${authTables.map((table) => `"${table}"`).join(", ")}`);
    });
    afterAll(async () => {
      await database?.close();
      database = undefined;
    });
  },
  client: () => PgliteClient.layer({ liveClient: openDatabase() }),
  tableNames: Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rows = yield* sql<{ name: string }>`
      SELECT table_name AS name FROM information_schema.tables
      WHERE table_schema = current_schema() AND left(table_name, 5) = 'auth_'
      ORDER BY table_name`;
    return rows.map((row) => row.name);
  }),
  columnTypes: (table) =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const rows = yield* sql<{ readonly name: string; readonly type: string }>`
        SELECT column_name AS name, data_type AS type FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = ${table}`;
      return Object.fromEntries(rows.map((row) => [row.name, row.type.toUpperCase()]));
    }),
};

const makeUser = (email: string) =>
  Effect.gen(function* () {
    const store = yield* Auth.Email.EmailPasswordStore;
    const identifiers = yield* Auth.IdentifierStore;
    const { user } = yield* store.createUser({ name: "Test User", attributes: { plan: "pro" } });
    yield* identifiers.create(
      Auth.makeIdentifier({ userId: user.id, type: "email", value: email }),
    );
    return user;
  });

// ---------------------------------------------------------------------------
// The store contract
// ---------------------------------------------------------------------------

const storeContract = (engine: StoreEngine): void => {
  /** Run an effect against a migrated database with every store layer. */
  const run = <A, E>(effect: Effect.Effect<A, E, StoreServices>): Promise<A> =>
    Effect.runPromise(
      Effect.gen(function* () {
        yield* migrate;
        return yield* effect;
      }).pipe(Effect.provide(layer.pipe(Layer.provideMerge(engine.client())))) as Effect.Effect<
        A,
        E
      >,
    );

  describe(`@thomasfosterau/effect-auth-sql stores over ${engine.name}`, () => {
    engine.hooks();

    it("migrate is idempotent and creates every auth_ table", async () => {
      const tables = await run(
        Effect.gen(function* () {
          yield* migrate; // second run: every statement is IF NOT EXISTS
          return yield* engine.tableNames;
        }),
      );
      expect(tables).toEqual([
        "auth_account_lockouts",
        "auth_api_keys",
        "auth_email_otps",
        "auth_email_verifications",
        "auth_identifiers",
        "auth_magic_links",
        "auth_multi_factor",
        "auth_oauth_accounts",
        "auth_oauth_states",
        "auth_password_resets",
        "auth_pending_multi_factor",
        "auth_rate_limits",
        "auth_role_permissions",
        "auth_sessions",
        "auth_user_roles",
        "auth_users",
        "auth_webauthn_challenges",
        "auth_webauthn_credentials",
      ]);
      expect(schemaStatements.length).toBeGreaterThan(0);
    });

    it("SessionStore roundtrips sessions with Date/attribute codecs", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.SessionStore;
          const now = new Date();
          const session: Auth.Session = {
            id: "sess-1",
            userId: "user-1",
            expiresAt: new Date(now.getTime() + 60_000),
            createdAt: now,
            lastActivityAt: now,
            attributes: { device: "laptop" },
          };
          yield* store.create(session);
          yield* store.create({ ...session, id: "sess-2" });
          yield* store.create({ ...session, id: "sess-3", userId: "user-2" });
          const loaded = yield* store.get("sess-1");
          const updated = yield* store.update({
            ...loaded!,
            lastActivityAt: new Date(now.getTime() + 1000),
            attributes: { device: "phone" },
          });
          const listed = yield* store.listByUserId("user-1");
          yield* store.delete("sess-2");
          yield* store.deleteByUserId("user-1");
          const missing = yield* store.get("sess-1");
          const other = yield* store.listByUserId("user-2");
          return { loaded, updated, listed, missing, other };
        }),
      );
      expect(result.loaded?.attributes).toEqual({ device: "laptop" });
      expect(result.loaded?.expiresAt).toBeInstanceOf(Date);
      expect(result.updated.attributes).toEqual({ device: "phone" });
      expect(
        Arr.sort(
          result.listed.map((s) => s.id),
          Order.String,
        ),
      ).toEqual(["sess-1", "sess-2"]);
      expect(result.missing).toBeNull();
      expect(result.other).toHaveLength(1);
    });

    it("EmailPasswordStore + UserStore share auth_users (booleans as 0/1, attributes as JSON)", async () => {
      const result = await run(
        Effect.gen(function* () {
          const emailPassword = yield* Auth.Email.EmailPasswordStore;
          const identifiers = yield* Auth.IdentifierStore;
          const users = yield* Auth.UserStore;
          const created = yield* makeUser("a@example.com");
          const byEmail = yield* identifiers.getByValue("email", "a@example.com");
          const missingEmail = yield* identifiers.getByValue("email", "nobody@example.com");
          yield* emailPassword.setPasswordHash(created.id, "hash-1");
          const hash = yield* emailPassword.getPasswordHash(created.id);
          const loaded = yield* users.get(created.id);
          const missing = yield* users.get("nope");
          yield* emailPassword.clearPasswordHash(created.id);
          const cleared = yield* emailPassword.getPasswordHash(created.id);
          return { created, byEmail, missingEmail, hash, loaded, missing, cleared };
        }),
      );
      expect(result.byEmail?.userId).toBe(result.created.id);
      expect(result.byEmail?.verified).toBe(false);
      expect(result.loaded?.attributes).toEqual({ plan: "pro" });
      expect(result.loaded?.name).toBe("Test User");
      expect(result.missingEmail).toBeNull();
      expect(result.hash).toBe("hash-1");
      expect(result.cleared).toBeNull();
      expect(result.loaded?.createdAt).toBeInstanceOf(Date);
      expect(result.missing).toBeNull();
    });

    it("UserServiceStore updates and deletes users", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.UserServiceStore;
          const created = yield* makeUser("b@example.com");
          const updated = yield* store.update({
            ...created,
            name: "Renamed",
            image: "https://example.com/x.png",
            updatedAt: new Date(),
          });
          const loaded = yield* store.get(created.id);
          yield* store.delete(created.id);
          const gone = yield* store.get(created.id);
          return { updated, loaded, gone };
        }),
      );
      expect(result.loaded?.name).toBe("Renamed");
      expect(result.loaded?.image).toBe("https://example.com/x.png");
      expect(result.gone).toBeNull();
    });

    it("PasswordResetUserStore sets password hashes by user", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Password.PasswordResetUserStore;
          const emailPassword = yield* Auth.Email.EmailPasswordStore;
          const created = yield* makeUser("c@example.com");
          yield* store.setPasswordHash(created.id, "reset-hash");
          const hash = yield* emailPassword.getPasswordHash(created.id);
          return { hash };
        }),
      );
      expect(result.hash).toBe("reset-hash");
    });

    it("RBAC entity resolver projects auth_user_roles as Role parents", async () => {
      const result = await run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient;
          const resolver = yield* Sql.makeRbacEntityResolver;
          yield* sql`INSERT INTO auth_user_roles (user_id, role) VALUES ('user-1', 'admin')`;
          yield* sql`INSERT INTO auth_user_roles (user_id, role) VALUES ('user-1', 'editor')`;
          const resolved = yield* resolver.resolve([
            Auth.Entity.ref("User", "user-1"),
            Auth.Entity.ref("User", "user-2"),
            Auth.Entity.ref("Widget", "w-1"),
          ]);
          return { slice: Auth.Entity.slice(resolved), resolved };
        }),
      );
      const { slice, resolved } = result;
      // Only `User::` references are answered; the Widget is omitted.
      expect(
        Arr.sort(
          resolved.map((entity) => entity.ref.id),
          Order.String,
        ),
      ).toEqual(["user-1", "user-2"]);
      expect(
        Auth.Entity.entityIn(slice, Auth.Entity.ref("User", "user-1"), Auth.Rbac.roleRef("admin")),
      ).toBe(true);
      expect(
        Auth.Entity.entityIn(slice, Auth.Entity.ref("User", "user-1"), Auth.Rbac.roleRef("viewer")),
      ).toBe(false);
      expect(
        Auth.Entity.entityIn(slice, Auth.Entity.ref("User", "user-2"), Auth.Rbac.roleRef("admin")),
      ).toBe(false);
    });

    it("RBAC policies compile auth_role_permissions into declarative permits", async () => {
      const result = await run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient;
          yield* sql`INSERT INTO auth_user_roles (user_id, role) VALUES ('user-1', 'admin')`;
          yield* sql`INSERT INTO auth_role_permissions (role, resource, action) VALUES ('admin', 'posts', 'delete')`;
          const policies = yield* Sql.readRbacPolicies;
          const resolver = yield* Sql.makeRbacEntityResolver;
          const slice = Auth.Entity.slice(
            yield* resolver.resolve([Auth.Entity.ref("User", "user-1")]),
          );
          const decide = (userId: string, action: string) =>
            Auth.Policy.decide<never, never>(
              policies,
              Auth.Policy.request({
                principal: Auth.Entity.ref("User", userId),
                action: Auth.Entity.ref("Action", action),
                resource: Auth.Entity.ref("posts", "post-1"),
              }),
              slice,
            );
          return {
            policies,
            allowed: (yield* decide("user-1", "delete")).allowed,
            otherAction: (yield* decide("user-1", "read")).allowed,
            otherUser: (yield* decide("user-2", "delete")).allowed,
          };
        }),
      );
      expect(result.policies.map((policy) => policy.id)).toEqual(["rbac:admin:posts:delete"]);
      expect(result.allowed).toBe(true);
      expect(result.otherAction).toBe(false);
      expect(result.otherUser).toBe(false);
    });

    it("RateLimitStore get/set/increment/delete (atomic upsert)", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          const before = yield* store.get("k");
          const first = yield* store.increment("k", 60);
          const second = yield* store.increment("k", 60);
          yield* store.set(
            "k",
            {
              key: "k",
              count: 9,
              resetAt: Date.now() + 60_000,
              blockedUntil: Date.now() + 120_000,
            },
            60,
          );
          const afterSet = yield* store.get("k");
          // set() on a fresh key inserts (upsert path).
          yield* store.set("fresh", { key: "fresh", count: 3, resetAt: Date.now() + 60_000 }, 60);
          const freshSet = yield* store.get("fresh");
          // Expired window restarts the counter.
          yield* store.set("k", { key: "k", count: 9, resetAt: Date.now() - 1 }, 60);
          const restarted = yield* store.increment("k", 60);
          yield* store.delete("k");
          const deleted = yield* store.get("k");
          return { before, first, second, afterSet, freshSet, restarted, deleted };
        }),
      );
      expect(result.before).toBeNull();
      expect(result.first).toBe(1);
      expect(result.second).toBe(2);
      expect(result.afterSet?.count).toBe(9);
      expect(result.afterSet?.blockedUntil).toBeDefined();
      expect(result.freshSet?.count).toBe(3);
      expect(result.restarted).toBe(1);
      expect(result.deleted).toBeNull();
    });

    it("EmailVerificationStore roundtrips and deletes by user id", async () => {
      const verification = (token: string, userId: string): Auth.Email.EmailVerification => ({
        token,
        userId,
        email: `${userId}@example.com`,
        createdAt: Date.now(),
        expiresAt: Date.now() + 86_400_000,
      });
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailVerificationStore;
          yield* store.create(verification("ev-1", "user-1"));
          yield* store.create(verification("ev-2", "user-1"));
          yield* store.create(verification("ev-3", "user-2"));
          const loaded = yield* store.get("ev-1");
          yield* store.delete("ev-1");
          const deleted = yield* store.get("ev-1");
          yield* store.deleteByUserId("user-1");
          const two = yield* store.get("ev-2");
          const three = yield* store.get("ev-3");
          return { loaded, deleted, two, three };
        }),
      );
      expect(result.loaded?.userId).toBe("user-1");
      expect(result.deleted).toBeNull();
      expect(result.two).toBeNull();
      expect(result.three?.userId).toBe("user-2");
    });

    it("ChallengeStore roundtrips challenge bytes (base64 TEXT)", async () => {
      const bytes = new Uint8Array([0, 1, 2, 250, 255]);
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.MultiFactor.ChallengeStore;
          yield* store.create({
            challenge: bytes,
            expiresAt: Date.now() + 60_000,
            userId: "user-1",
          });
          // create replaces an existing row for the same challenge
          yield* store.create({ challenge: bytes, expiresAt: Date.now() + 90_000 });
          const loaded = yield* store.get(bytes);
          yield* store.delete(bytes);
          const missing = yield* store.get(bytes);
          return { loaded, missing };
        }),
      );
      expect(Array.from(result.loaded?.challenge ?? [])).toEqual([0, 1, 2, 250, 255]);
      expect(result.loaded?.userId).toBeUndefined();
      expect(result.missing).toBeNull();
    });

    it("CredentialStore roundtrips credentials incl. transports and getByCredentialId", async () => {
      const credential: Auth.MultiFactor.WebAuthnCredential = {
        id: "cred-1",
        userId: "user-1",
        publicKey: new Uint8Array([9, 8, 7]),
        algorithm: -7,
        counter: 0,
        createdAt: Date.now(),
        name: "MacBook",
        transports: ["internal", "hybrid"],
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.MultiFactor.CredentialStore;
          yield* store.create(credential);
          const loaded = yield* store.get("cred-1");
          const byCredentialId = yield* store.getByCredentialId("cred-1");
          yield* store.update({ ...credential, counter: 5 });
          const updated = yield* store.get("cred-1");
          const byUser = yield* store.listByUserId("user-1");
          yield* store.delete("cred-1");
          const missing = yield* store.get("cred-1");
          return { loaded, byCredentialId, updated, byUser, missing };
        }),
      );
      expect(Array.from(result.loaded?.publicKey ?? [])).toEqual([9, 8, 7]);
      expect(result.loaded?.transports).toEqual(["internal", "hybrid"]);
      expect(result.loaded?.name).toBe("MacBook");
      expect(result.byCredentialId?.id).toBe("cred-1");
      expect(result.updated?.counter).toBe(5);
      expect(result.byUser).toHaveLength(1);
      expect(result.missing).toBeNull();
    });

    it("OAuthStateStore roundtrips states incl. nonce", async () => {
      const state: Auth.OAuth.OAuthState = {
        state: "st-1",
        provider: "google",
        codeVerifier: "cv",
        nonce: "n-1",
        returnTo: "/home",
        createdAt: Date.now(),
        expiresAt: Date.now() + 600_000,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.OAuth.OAuthStateStore;
          yield* store.create(state);
          // create replaces an existing row for the same state
          yield* store.create({ ...state, returnTo: "/dashboard" });
          const loaded = yield* store.get("st-1");
          yield* store.delete("st-1");
          const missing = yield* store.get("st-1");
          return { loaded, missing };
        }),
      );
      expect(result.loaded?.returnTo).toBe("/dashboard");
      expect(result.loaded?.codeVerifier).toBe("cv");
      expect(result.loaded?.nonce).toBe("n-1");
      expect(result.missing).toBeNull();
    });

    it("OAuthAccountStore upserts, links, unlinks and reports hasPassword", async () => {
      const now = Date.now();
      const account: Auth.OAuth.OAuthAccount = {
        id: "acc-1",
        userId: "user-1",
        provider: "github",
        providerId: "gh-123",
        email: "gh@example.com",
        accessToken: "token-1",
        refreshToken: "refresh-1",
        expiresAt: now + 3_600_000,
        createdAt: now,
        updatedAt: now,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.OAuth.OAuthAccountStore;
          yield* store.create(account);
          const loaded = yield* store.get("github", "gh-123");
          yield* store.update({ ...account, accessToken: "token-2", updatedAt: now + 1 });
          const updated = yield* store.get("github", "gh-123");
          yield* store.linkToUser("user-2", account);
          const linked = yield* store.getByUserId("user-2");
          yield* store.unlinkFromUser("user-2", "github");
          const afterUnlink = yield* store.get("github", "gh-123");
          yield* store.create(account);
          yield* store.delete("github", "gh-123");
          const deleted = yield* store.get("github", "gh-123");

          const emailPassword = yield* Auth.Email.EmailPasswordStore;
          const user = yield* makeUser("haspw@example.com");
          const noPassword = yield* store.hasPassword!(user.id);
          yield* emailPassword.setPasswordHash(user.id, "hash");
          const withPassword = yield* store.hasPassword!(user.id);
          return { loaded, updated, linked, afterUnlink, deleted, noPassword, withPassword };
        }),
      );
      expect(result.loaded?.accessToken).toBe("token-1");
      expect(result.loaded?.refreshToken).toBe("refresh-1");
      expect(result.updated?.accessToken).toBe("token-2");
      expect(result.linked).toHaveLength(1);
      expect(result.linked[0]?.userId).toBe("user-2");
      expect(result.afterUnlink).toBeNull();
      expect(result.deleted).toBeNull();
      expect(result.noPassword).toBe(false);
      expect(result.withPassword).toBe(true);
    });

    it("OAuthUserStore creates, resolves and updates users", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.OAuth.OAuthUserStore;
          const { user: created } = yield* store.createUser({
            name: "OAuth User",
            image: "https://example.com/pic.png",
          });
          const loaded = yield* store.getUser(created.id);
          const missing = yield* Effect.flip(store.getUser("nope"));
          const renamed = yield* store.updateUser!(created.id, { name: "Renamed" });
          return { created, loaded, missing, renamed };
        }),
      );
      expect(result.loaded.name).toBe("OAuth User");
      expect(result.loaded.image).toBe("https://example.com/pic.png");
      expect(result.missing._tag).toBe("UserNotFoundError");
      expect(result.renamed.name).toBe("Renamed");
      expect(result.renamed.image).toBe("https://example.com/pic.png");
    });

    it("PasswordResetStore roundtrips and deletes by user id", async () => {
      const reset = (token: string, userId: string): Auth.Password.PasswordResetToken => ({
        token,
        userId,
        email: `${userId}@example.com`,
        createdAt: Date.now(),
        expiresAt: Date.now() + 3_600_000,
      });
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Password.PasswordResetStore;
          yield* store.create(reset("pr-1", "user-1"));
          yield* store.create(reset("pr-2", "user-1"));
          yield* store.create(reset("pr-3", "user-2"));
          const loaded = yield* store.get("pr-1");
          yield* store.delete("pr-1");
          yield* store.deleteByUserId("user-1");
          const two = yield* store.get("pr-2");
          const three = yield* store.get("pr-3");
          return { loaded, two, three };
        }),
      );
      expect(result.loaded?.token).toBe("pr-1");
      expect(result.two).toBeNull();
      expect(result.three?.userId).toBe("user-2");
    });

    it("MagicLinkStore roundtrips and deletes by email", async () => {
      const link = (token: string, email: string): Auth.MagicLinkToken => ({
        token,
        email,
        createdAt: Date.now(),
        expiresAt: Date.now() + 300_000,
      });
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.MagicLinkStore;
          const userStore = yield* Auth.MagicLinkUserStore;
          yield* store.create(link("ml-1", "a@example.com"));
          yield* store.create(link("ml-2", "a@example.com"));
          yield* store.create(link("ml-3", "b@example.com"));
          const loaded = yield* store.get("ml-1");
          yield* store.delete("ml-1");
          yield* store.deleteByEmail("a@example.com");
          const two = yield* store.get("ml-2");
          const three = yield* store.get("ml-3");
          const { user } = yield* userStore.createUser({ name: "Magic User" });
          return { loaded, two, three, user };
        }),
      );
      expect(result.loaded?.email).toBe("a@example.com");
      expect(result.two).toBeNull();
      expect(result.three?.email).toBe("b@example.com");
      expect(result.user.name).toBe("Magic User");
    });

    it("EmailOtpStore upserts per email+purpose and increments attempts", async () => {
      const record: Auth.Email.EmailOtpRecord = {
        email: "otp@example.com",
        otpHash: "hash",
        purpose: "sign-in",
        attempts: 0,
        createdAt: Date.now(),
        expiresAt: Date.now() + 300_000,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Email.EmailOtpStore;
          const userStore = yield* Auth.Email.EmailOtpUserStore;
          yield* store.upsert(record);
          yield* store.upsert({ ...record, purpose: "forget-password", otpHash: "other" });
          const attempts1 = yield* store.incrementAttempts("otp@example.com", "sign-in");
          const attempts2 = yield* store.incrementAttempts("otp@example.com", "sign-in");
          yield* store.upsert({ ...record, otpHash: "new-hash" });
          const replaced = yield* store.get("otp@example.com", "sign-in");
          const other = yield* store.get("otp@example.com", "forget-password");
          yield* store.delete("otp@example.com", "sign-in");
          const deleted = yield* store.get("otp@example.com", "sign-in");
          const missingIncrement = yield* Effect.flip(
            store.incrementAttempts("otp@example.com", "sign-in"),
          );
          const { user } = yield* userStore.createUser({ name: "OTP User" });
          return { attempts1, attempts2, replaced, other, deleted, missingIncrement, user };
        }),
      );
      expect(result.attempts1).toBe(1);
      expect(result.attempts2).toBe(2);
      expect(result.replaced?.otpHash).toBe("new-hash");
      expect(result.replaced?.attempts).toBe(0);
      expect(result.other?.otpHash).toBe("other");
      expect(result.deleted).toBeNull();
      expect(result.missingIncrement._tag).toBe("AuthError");
      expect(result.user.name).toBe("OTP User");
    });

    it("MultiFactorStore and PendingMultiFactorStore roundtrip incl. lastUsedCounter", async () => {
      const record: Auth.MultiFactor.MultiFactorRecord = {
        userId: "user-1",
        secret: "JBSWY3DPEHPK3PXP",
        backupCodes: ["h1", "h2", "h3"],
        verified: false,
        createdAt: Date.now(),
      };
      const pending: Auth.MultiFactor.PendingMultiFactor = {
        token: "p2f-1",
        userId: "user-1",
        expiresAt: Date.now() + 300_000,
        createdAt: Date.now(),
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.MultiFactor.MultiFactorStore;
          const pendingStore = yield* Auth.MultiFactor.PendingMultiFactorStore;
          const before = yield* store.get("user-1");
          yield* store.upsert(record);
          const created = yield* store.get("user-1");
          yield* store.upsert({
            ...record,
            verified: true,
            backupCodes: ["h2", "h3"],
            lastUsedCounter: 42,
          });
          const updated = yield* store.get("user-1");
          yield* store.delete("user-1");
          const deleted = yield* store.get("user-1");

          yield* pendingStore.create(pending);
          const loadedPending = yield* pendingStore.get("p2f-1");
          yield* pendingStore.delete("p2f-1");
          const deletedPending = yield* pendingStore.get("p2f-1");
          return { before, created, updated, deleted, loadedPending, deletedPending };
        }),
      );
      expect(result.before).toBeNull();
      expect(result.created?.verified).toBe(false);
      expect(result.created?.backupCodes).toEqual(["h1", "h2", "h3"]);
      expect(result.created?.lastUsedCounter).toBeUndefined();
      expect(result.updated?.verified).toBe(true);
      expect(result.updated?.backupCodes).toEqual(["h2", "h3"]);
      expect(result.updated?.lastUsedCounter).toBe(42);
      expect(result.deleted).toBeNull();
      expect(result.loadedPending).toEqual(pending);
      expect(result.deletedPending).toBeNull();
    });

    it("schema declares BIGINT for all epoch-ms timestamp columns", async () => {
      // Verifies the DDL uses BIGINT (not INTEGER) for every column that stores
      // epoch-milliseconds, ensuring Postgres adopters don't get int4
      // overflow on values like Date.now() (~1.75e12).
      const timestampColumns: Record<string, readonly string[]> = {
        auth_users: ["created_at", "updated_at"],
        auth_sessions: ["expires_at", "created_at", "last_activity_at"],
        auth_rate_limits: ["reset_at", "blocked_until"],
        auth_email_verifications: ["created_at", "expires_at"],
        auth_webauthn_challenges: ["expires_at"],
        auth_webauthn_credentials: ["created_at"],
        auth_oauth_states: ["created_at", "expires_at"],
        auth_oauth_accounts: ["expires_at", "created_at", "updated_at"],
        auth_password_resets: ["created_at", "expires_at"],
        auth_magic_links: ["created_at", "expires_at"],
        auth_email_otps: ["created_at", "expires_at"],
        auth_multi_factor: ["created_at"],
        auth_pending_multi_factor: ["expires_at", "created_at"],
        auth_identifiers: ["verified_at", "created_at"],
        auth_api_keys: [
          "expires_at",
          "last_used_at",
          "refill_interval",
          "last_refill_at",
          "rate_limit_window_ms",
          "created_at",
          "updated_at",
        ],
      };

      await run(
        Effect.gen(function* () {
          yield* Effect.forEach(
            Object.entries(timestampColumns),
            ([table, columns]) =>
              engine.columnTypes(table).pipe(
                Effect.map((typeByCol) => {
                  for (const col of columns) {
                    expect(typeByCol[col], `${table}.${col}`).toBe("BIGINT");
                  }
                }),
              ),
            { concurrency: 1, discard: true },
          );
        }),
      );
    });

    it("BIGINT timestamps beyond int4 max round-trip correctly", async () => {
      // int4 max is 2_147_483_647; epoch-ms for 2040 is ~2.2e12, well beyond it.
      const FAR_FUTURE_MS = 2_200_000_000_000; // ~2039-09
      const result = await run(
        Effect.gen(function* () {
          const sessionStore = yield* Auth.SessionStore;
          const session: Auth.Session = {
            id: "bigint-test",
            userId: "user-bigint",
            expiresAt: new Date(FAR_FUTURE_MS),
            createdAt: new Date(FAR_FUTURE_MS - 1000),
            lastActivityAt: new Date(FAR_FUTURE_MS - 500),
            attributes: {},
          };
          yield* sessionStore.create(session);
          return yield* sessionStore.get("bigint-test");
        }),
      );
      expect(result?.expiresAt.getTime()).toBe(FAR_FUTURE_MS);
      expect(result?.createdAt.getTime()).toBe(FAR_FUTURE_MS - 1000);
      expect(result?.lastActivityAt.getTime()).toBe(FAR_FUTURE_MS - 500);
    });

    it("IdentifierStore roundtrips create/getByValue/listByUser/setVerified/delete/deleteByUser", async () => {
      const now = new Date("2026-07-04T00:00:00.000Z");
      const emailId: Auth.Identifier = {
        id: "ident-email",
        userId: "user-ident",
        type: "email",
        value: "alice@example.com",
        verified: false,
        createdAt: now,
      };
      const usernameId: Auth.Identifier = {
        id: "ident-username",
        userId: "user-ident",
        type: "username",
        value: "alice",
        verified: true,
        verifiedAt: now,
        createdAt: new Date(now.getTime() + 1000),
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          yield* store.create(emailId);
          yield* store.create(usernameId);
          const byEmail = yield* store.getByValue("email", "alice@example.com");
          const missing = yield* store.getByValue("email", "nobody@example.com");
          const listed = yield* store.listByUser("user-ident");
          const emptyList = yield* store.listByUser("no-such-user");
          const verifiedAt = new Date("2026-07-04T12:00:00.000Z");
          const verified = yield* store.setVerified("ident-email", verifiedAt);
          const verifiedMissing = yield* store.setVerified("no-such-id", verifiedAt);
          const afterVerify = yield* store.getByValue("email", "alice@example.com");
          yield* store.delete("ident-username");
          const afterDelete = yield* store.getByValue("username", "alice");
          yield* store.deleteByUser("user-ident");
          const afterDeleteUser = yield* store.listByUser("user-ident");
          return {
            byEmail,
            missing,
            listed,
            emptyList,
            verified,
            verifiedMissing,
            afterVerify,
            afterDelete,
            afterDeleteUser,
          };
        }),
      );
      expect(result.byEmail?.id).toBe("ident-email");
      expect(result.byEmail?.verified).toBe(false);
      expect(result.byEmail?.createdAt).toBeInstanceOf(Date);
      expect(result.missing).toBeNull();
      expect(result.listed.map((i) => i.id)).toEqual(["ident-email", "ident-username"]);
      expect(result.emptyList).toEqual([]);
      expect(result.verified?.verified).toBe(true);
      expect(result.verified?.verifiedAt).toBeInstanceOf(Date);
      expect(result.verifiedMissing).toBeNull();
      expect(result.afterVerify?.verified).toBe(true);
      expect(result.afterDelete).toBeNull();
      expect(result.afterDeleteUser).toHaveLength(0);
    });

    it("IdentifierStore.replace swaps a user's identifier in one transaction, and keeps it on any refusal", async () => {
      const email = (userId: string, value: string, verified = false) =>
        Auth.makeIdentifier({ userId, type: "email", value, verified });
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(email("user-ada", "ada@example.com", true));
          yield* store.create(email("user-grace", "grace@example.com"));

          const replaced = yield* store.replace(
            ada,
            email("user-ada", "ada-new@example.com", true),
          );
          const afterReplace = {
            listed: yield* store.listByUser("user-ada"),
            old: yield* store.getByValue("email", "ada@example.com"),
          };

          // A value another user holds: the INSERT is refused by the unique
          // index and the transaction rolls back, so the user keeps their address.
          const takenRaw = yield* Effect.flip(
            store.replace(replaced!, email("user-ada", "grace@example.com")),
          );
          const taken = yield* Effect.flip(
            Auth.replaceIdentifier(store, replaced!, email("user-ada", "grace@example.com")),
          );
          // `from` is no longer held: null, and nothing is written.
          const stale = yield* store.replace(ada, email("user-ada", "ada-other@example.com"));
          const staleTyped = yield* Effect.flip(
            Auth.replaceIdentifier(store, ada, email("user-ada", "ada-other@example.com")),
          );
          // Another user's replacement, or one reusing `from`'s id, is refused outright.
          const wrongUser = yield* Effect.flip(
            store.replace(replaced!, email("user-grace", "x@example.com")),
          );
          const sameId = yield* Effect.flip(
            store.replace(replaced!, { ...email("user-ada", "y@example.com"), id: replaced!.id }),
          );
          return {
            replaced,
            afterReplace,
            takenRaw,
            taken,
            stale,
            staleTyped,
            wrongUser,
            sameId,
            listed: yield* store.listByUser("user-ada"),
            grace: yield* store.getByValue("email", "grace@example.com"),
            other: yield* store.getByValue("email", "ada-other@example.com"),
          };
        }),
      );
      expect(result.replaced?.value).toBe("ada-new@example.com");
      expect(result.afterReplace.old).toBeNull();
      expect(result.afterReplace.listed.map((i) => [i.value, i.verified])).toEqual([
        ["ada-new@example.com", true],
      ]);
      expect(result.takenRaw._tag).toBe("AuthError");
      expect(result.taken._tag).toBe("IdentifierTakenError");
      expect(result.stale).toBeNull();
      expect(result.staleTyped._tag).toBe("IdentifierNotFoundError");
      expect(result.wrongUser._tag).toBe("AuthError");
      expect(result.sameId._tag).toBe("AuthError");
      expect(result.sameId.message).toContain("with its own id");
      expect(result.listed.map((i) => i.value)).toEqual(["ada-new@example.com"]);
      expect(result.grace?.userId).toBe("user-grace");
      expect(result.other).toBeNull();
    });

    it("IdentifierStore.replace releases `from` with a compare-and-swap: of two replaces of one `from`, the second resolves to null", async () => {
      // The second replace runs after the first has committed, which is what a
      // concurrent second sees on PostgreSQL once the first's row lock is
      // released: its INSERT lands, its guarded DELETE matches nothing, and the
      // claim is taken back.
      const email = (value: string) =>
        Auth.makeIdentifier({ userId: "user-ada", type: "email", value, verified: true });
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.IdentifierStore;
          const ada = yield* store.create(email("ada@example.com"));
          const first = yield* store.replace(ada, email("ada-a@example.com"));
          const second = yield* store.replace(ada, email("ada-b@example.com"));
          // A double submit of the same change: the second claim is refused by
          // the unique index (this user already holds the value), and
          // replaceIdentifier reports that `from` is gone.
          const again = yield* Effect.flip(
            Auth.replaceIdentifier(store, ada, email("ada-a@example.com")),
          );
          // The guard is the whole record, not just the id: the held row with a
          // value it no longer has is not released.
          const staleValue = yield* store.replace(
            { ...first!, value: "ada@example.com" },
            email("ada-c@example.com"),
          );
          return {
            first,
            second,
            again,
            staleValue,
            listed: yield* store.listByUser("user-ada"),
            b: yield* store.getByValue("email", "ada-b@example.com"),
          };
        }),
      );
      expect(result.first?.value).toBe("ada-a@example.com");
      expect(result.second).toBeNull();
      expect(result.again._tag).toBe("IdentifierNotFoundError");
      expect(result.staleValue).toBeNull();
      expect(result.listed.map((i) => i.value)).toEqual(["ada-a@example.com"]);
      expect(result.b).toBeNull();
    });

    it("ApiKeyStore roundtrips full records incl. permissions/metadata/refill/rateLimit", async () => {
      const now = Date.now();
      const apiKey: Auth.ApiKey = {
        id: "key-1",
        name: "CI deploy key",
        prefix: "ak_",
        start: "abcdef",
        keyHash: "hash-1",
        userId: "user-1",
        enabled: true,
        expiresAt: now + 3_600_000,
        permissions: { posts: ["read", "write"] },
        metadata: { plan: "pro" },
        remaining: 10,
        refillAmount: 5,
        refillInterval: 60_000,
        refillMax: 10,
        lastRefillAt: now,
        rateLimit: { maxRequests: 100, windowMs: 60_000 },
        createdAt: now,
        updatedAt: now,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.ApiKeyStore;
          yield* store.create(apiKey);
          yield* store.create({ ...apiKey, id: "key-2", keyHash: "hash-2" });
          yield* store.create({ ...apiKey, id: "key-3", userId: "user-2", keyHash: "hash-3" });
          const loaded = yield* store.get("key-1");
          const byHash = yield* store.getByHash("hash-1");
          const missingHash = yield* store.getByHash("no-such-hash");
          const updated = yield* store.update({
            ...apiKey,
            enabled: false,
            remaining: 9,
            lastUsedAt: now + 1000,
            updatedAt: now + 1000,
          });
          const afterUpdate = yield* store.get("key-1");
          const byUser = yield* store.listByUserId("user-1");
          yield* store.delete("key-2");
          const deleted = yield* store.get("key-2");
          return { loaded, byHash, missingHash, updated, afterUpdate, byUser, deleted };
        }),
      );
      expect(result.loaded?.name).toBe("CI deploy key");
      expect(result.loaded?.permissions).toEqual({ posts: ["read", "write"] });
      expect(result.loaded?.metadata).toEqual({ plan: "pro" });
      expect(result.loaded?.rateLimit).toEqual({ maxRequests: 100, windowMs: 60_000 });
      expect(result.loaded?.refillAmount).toBe(5);
      expect(result.byHash?.id).toBe("key-1");
      expect(result.missingHash).toBeNull();
      expect(result.updated.enabled).toBe(false);
      expect(result.afterUpdate?.enabled).toBe(false);
      expect(result.afterUpdate?.remaining).toBe(9);
      expect(result.afterUpdate?.lastUsedAt).toBe(now + 1000);
      expect(result.byUser).toHaveLength(2);
      expect(result.deleted).toBeNull();
    });

    it("ApiKeyStore treats minimal records (no permissions/metadata/refill/rateLimit) as absent, not null", async () => {
      const now = Date.now();
      const minimal: Auth.ApiKey = {
        id: "key-min",
        start: "ghijkl",
        keyHash: "hash-min",
        userId: "user-1",
        enabled: true,
        metadata: {},
        createdAt: now,
        updatedAt: now,
      };
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.ApiKeyStore;
          yield* store.create(minimal);
          return yield* store.get("key-min");
        }),
      );
      expect(result?.name).toBeUndefined();
      expect(result?.prefix).toBeUndefined();
      expect(result?.expiresAt).toBeUndefined();
      expect(result?.permissions).toBeUndefined();
      expect(result?.metadata).toEqual({});
      expect(result?.remaining).toBeUndefined();
      expect(result?.rateLimit).toBeUndefined();
    });

    it("ApiKeyStore surfaces malformed JSON permissions as AuthError not defect", async () => {
      const result = await run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient;
          const now = Date.now();
          yield* sql`INSERT INTO auth_api_keys (id, name, prefix, start, key_hash, user_id, enabled, expires_at, last_used_at, permissions, metadata, remaining, refill_amount, refill_interval, refill_max, last_refill_at, rate_limit_max_requests, rate_limit_window_ms, created_at, updated_at)
            VALUES (${"key-corrupt"}, ${null}, ${null}, ${"abcdef"}, ${"hash-corrupt"}, ${"user-1"}, ${1}, ${null}, ${null}, ${"INVALID_JSON"}, ${"{}"}, ${null}, ${null}, ${null}, ${null}, ${null}, ${null}, ${null}, ${now}, ${now})`;
          const store = yield* Auth.ApiKeyStore;
          return yield* Effect.flip(store.get("key-corrupt"));
        }),
      );
      expect(result._tag).toBe("AuthError");
      expect(result.cause).toBeDefined();
    });

    it("AdminUserStore lists/paginates/searches users by earliest email and manages passwords", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.AdminUserStore;
          const emailPassword = yield* Auth.Email.EmailPasswordStore;
          const alice = yield* makeUser("alice@example.com");
          const bob = yield* makeUser("bob@example.com");
          const { user: created } = yield* store.createUser({
            name: "Carol",
            attributes: { role: "admin" },
          });

          const all = yield* store.listUsers({});
          const page = yield* store.listUsers({ limit: 2, offset: 1 });
          const searched = yield* store.listUsers({ searchEmail: "example.com" });
          const searchedNarrow = yield* store.listUsers({ searchEmail: "alice" });

          yield* store.setPasswordHash(created.id, "admin-hash");
          const hash = yield* emailPassword.getPasswordHash(created.id);

          return { alice, bob, created, all, page, searched, searchedNarrow, hash };
        }),
      );
      expect(result.all.total).toBe(3);
      // No email identifier sorts first (empty string), so the admin-created
      // user (no identifier claimed) leads the ascending email sort.
      expect(result.all.users[0]?.id).toBe(result.created.id);
      expect(result.all.users.map((u) => u.id)).toEqual([
        result.created.id,
        result.alice.id,
        result.bob.id,
      ]);
      expect(result.page.total).toBe(3);
      expect(result.page.users.map((u) => u.id)).toEqual([result.alice.id, result.bob.id]);
      expect(result.searched.total).toBe(2);
      expect(
        Arr.sort(
          result.searched.users.map((u) => u.id),
          Order.String,
        ),
      ).toEqual(Arr.sort([result.alice.id, result.bob.id], Order.String));
      expect(result.searchedNarrow.total).toBe(1);
      expect(result.searchedNarrow.users[0]?.id).toBe(result.alice.id);
      expect(result.created.name).toBe("Carol");
      expect(result.created.attributes).toEqual({ role: "admin" });
      expect(result.hash).toBe("admin-hash");
    });

    it("integration: SessionService runs over the aggregate layer", async () => {
      const config: Auth.SessionConfig = {
        sessionExpiresIn: { activePeriod: 60_000, idlePeriod: 30_000 },
      };
      const program = Effect.gen(function* () {
        const user = yield* makeUser("manager@example.com");
        const manager = yield* Auth.SessionService;
        const session = yield* manager.createSession(user.id, { ip: "127.0.0.1" });
        const validated = yield* manager.validateSession(session.id);
        yield* manager.invalidateSession(session.id);
        const invalidated = yield* Effect.flip(manager.validateSession(session.id));
        return { user, session, validated, invalidated };
      }).pipe(
        Effect.provide(
          Auth.SessionService.layer(config).pipe(Layer.provideMerge(Auth.Hooks.Default)),
        ),
      );

      const result = await run(program);
      expect(result.validated.user.id).toBe(result.user.id);
      expect(result.validated.session.attributes).toEqual({ ip: "127.0.0.1" });
      expect(result.invalidated._tag).toBe("SessionNotFoundError");
    });

    it("store gets surface AuthError (not defect) on SQL failure", async () => {
      const simulatedFailure = () =>
        driverError(new SimulatedFailure({ message: "simulated failure" }));
      const brokenConnection: SqlConnection.Connection = {
        execute: () => Effect.fail(simulatedFailure()),
        executeRaw: () => Effect.fail(simulatedFailure()),
        executeStream: () => Stream.fail(simulatedFailure()),
        executeValues: () => Effect.fail(simulatedFailure()),
        executeValuesUnprepared: () => Effect.fail(simulatedFailure()),
        executeUnprepared: () => Effect.fail(simulatedFailure()),
      };
      const brokenClientLayer = Layer.effect(
        SqlClient.SqlClient,
        SqlClient.make({
          acquirer: Effect.succeed(brokenConnection),
          compiler: engine.compiler,
          spanAttributes: [],
        }),
      ).pipe(Layer.provide(Reactivity.layer));

      const program = Effect.gen(function* () {
        const challenges = yield* Auth.MultiFactor.ChallengeStore;
        const credentials = yield* Auth.MultiFactor.CredentialStore;
        const rateLimits = yield* Auth.RateLimitStore;
        const apiKeys = yield* Auth.ApiKeyStore;
        const adminUsers = yield* Auth.AdminUserStore;
        const e1 = yield* Effect.flip(challenges.get(new Uint8Array([1, 2, 3])));
        const e2 = yield* Effect.flip(credentials.get("cred-id"));
        const e3 = yield* Effect.flip(rateLimits.get("key"));
        const e4 = yield* Effect.flip(apiKeys.get("key-id"));
        const e5 = yield* Effect.flip(adminUsers.listUsers({}));
        return { e1, e2, e3, e4, e5 };
      });

      const result = await Effect.runPromise(
        program.pipe(Effect.provide(layer.pipe(Layer.provideMerge(brokenClientLayer)))),
      );

      expect(result.e1._tag).toBe("AuthError");
      expect(result.e1.cause).toBeDefined();
      expect(result.e2._tag).toBe("AuthError");
      expect(result.e3._tag).toBe("AuthError");
      expect(result.e4._tag).toBe("AuthError");
      expect(result.e5._tag).toBe("AuthError");
    });

    it("decodeAttributes surfaces malformed JSON attributes as AuthError not defect", async () => {
      const result = await run(
        Effect.gen(function* () {
          const sql = yield* SqlClient.SqlClient;
          const now = Date.now();
          yield* sql`INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
            VALUES (${"u-corrupt"}, ${null}, ${null}, ${null}, ${"INVALID_JSON"}, ${now}, ${now})`;
          const store = yield* Auth.UserServiceStore;
          return yield* Effect.flip(store.get("u-corrupt"));
        }),
      );
      expect(result._tag).toBe("AuthError");
      expect(result.cause).toBeDefined();
    });

    it("AccountLockoutStore registerAttempt is atomic and follows the transition semantics", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.Plugins.AccountLockoutStore;
          const now = Date.now();
          const opts = { maxAttempts: 3, lockoutDurationMs: 60_000, now };

          const before = yield* store.get("lockout:a");
          const first = yield* store.registerAttempt("lockout:a", opts);
          const second = yield* store.registerAttempt("lockout:a", opts);
          const third = yield* store.registerAttempt("lockout:a", opts); // crosses threshold
          const whileLocked = yield* store.registerAttempt("lockout:a", opts); // unchanged
          // Expired lock resets the streak.
          const afterExpiry = yield* store.registerAttempt("lockout:a", {
            ...opts,
            now: now + 120_000,
          });
          yield* store.delete("lockout:a");
          const deleted = yield* store.get("lockout:a");

          // Concurrency: 25 parallel attempts, none lost.
          yield* Effect.all(
            Array.from({ length: 25 }, () =>
              store.registerAttempt("lockout:burst", {
                maxAttempts: 100,
                lockoutDurationMs: 60_000,
                now,
              }),
            ),
            { concurrency: "unbounded" },
          );
          const burst = yield* store.get("lockout:burst");

          return { before, first, second, third, whileLocked, afterExpiry, deleted, burst };
        }),
      );
      expect(result.before).toBeNull();
      expect(result.first).toEqual({ failures: 1 });
      expect(result.second).toEqual({ failures: 2 });
      expect(result.third.failures).toBe(3);
      expect(result.third.lockedUntil).toBeDefined();
      expect(result.whileLocked).toEqual(result.third);
      expect(result.afterExpiry).toEqual({ failures: 1 });
      expect(result.deleted).toBeNull();
      expect(result.burst?.failures).toBe(25);
    });

    it("concurrent rateLimit.increment does not undercount", async () => {
      const result = await run(
        Effect.gen(function* () {
          const store = yield* Auth.RateLimitStore;
          yield* Effect.all(
            Array.from({ length: 20 }, () => store.increment("burst", 60)),
            { concurrency: "unbounded" },
          );
          const entry = yield* store.get("burst");
          return entry?.count;
        }),
      );
      expect(result).toBe(20);
    });

    // The core's published conformance suites (`@thomasfosterau/effect-auth/testing`),
    // over the same engine. Every case mints its own ids, so they share the database.
    const seedUser = (user: Auth.User) =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        yield* sql`INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
          VALUES (${user.id}, ${user.name ?? null}, ${user.image ?? null}, ${null}, ${JSON.stringify(user.attributes)}, ${user.createdAt.getTime()}, ${user.updatedAt.getTime()})`;
      });
    const suites: ReadonlyArray<Testing.ConformanceSuite<SqlError.SqlError, StoreServices>> = [
      Testing.sessionStoreConformance({ seedUser }),
      Testing.userStoreConformance({ seedUser }),
      Testing.identifierStoreConformance({ seedUser }),
      Testing.apiKeyStoreConformance({ seedUser }),
    ];
    for (const suite of suites) {
      describe(`${suite.contract} conformance`, () => {
        for (const testCase of suite.cases) {
          it(testCase.name, () => run(testCase.run));
        }
      });
    }
  });
};

storeContract(sqlite);
storeContract(postgres);

// ---------------------------------------------------------------------------
// IdentifierStore.replace inside its transaction (SQLite)
//
// A trigger makes one of replace's statements fail, so these cases show what
// the transaction and the statement order guarantee rather than what a
// well-behaved database happens to allow.
// ---------------------------------------------------------------------------

describe("@thomasfosterau/effect-auth-sql IdentifierStore.replace on SQLite: transaction and order", () => {
  const email = (value: string) =>
    Auth.makeIdentifier({ userId: "user-ada", type: "email", value, verified: true });

  const replaceUnder = (trigger: string) =>
    Effect.runPromise(
      Effect.gen(function* () {
        yield* migrate;
        const sql = yield* SqlClient.SqlClient;
        const store = yield* Auth.IdentifierStore;
        const ada = yield* store.create(email("ada@example.com"));
        yield* sql.unsafe(trigger);
        const outcome = yield* Effect.result(store.replace(ada, email("ada-new@example.com")));
        const rows = yield* sql<{
          readonly value: string;
        }>`SELECT value FROM auth_identifiers WHERE user_id = ${"user-ada"} ORDER BY value`;
        return { outcome, values: rows.map((row) => row.value) };
      }).pipe(Effect.provide(layer.pipe(Layer.provideMerge(sqlClientLayer())))),
    );

  it("a failed release rolls the claim back: only the old row remains", async () => {
    const result = await replaceUnder(`
      CREATE TRIGGER refuse_release BEFORE DELETE ON auth_identifiers
      BEGIN SELECT RAISE(ABORT, 'release refused'); END`);
    expect(result.outcome._tag).toBe("Failure");
    expect(result.values).toEqual(["ada@example.com"]);
  });

  it("claims before it releases: a user is never without an identifier, even mid-transaction", async () => {
    // Refuses any DELETE that would leave its user holding no identifier, so a
    // release that ran before the claim would fail.
    const result = await replaceUnder(`
      CREATE TRIGGER keep_one BEFORE DELETE ON auth_identifiers
      WHEN NOT EXISTS (
        SELECT 1 FROM auth_identifiers WHERE user_id = OLD.user_id AND id <> OLD.id
      )
      BEGIN SELECT RAISE(ABORT, 'user left without an identifier'); END`);
    expect(result.outcome._tag).toBe("Success");
    expect(result.values).toEqual(["ada-new@example.com"]);
  });
});
