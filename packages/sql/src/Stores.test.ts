import { describe, it, expect } from "vite-plus/test";
import { Effect, Layer, Stream } from "effect";
import { SqlClient, SqlConnection, SqlError, Statement } from "effect/unstable/sql";
import { Reactivity } from "effect/unstable/reactivity";
import Database from "better-sqlite3";
import * as Auth from "@thomasfosterau/effect-auth";
import { migrate, schemaStatements } from "./Schema.ts";
import { layer } from "./Stores.ts";

// ---------------------------------------------------------------------------
// Minimal test-only SqlClient over better-sqlite3.
//
// This is a real `SqlClient` built with `SqlClient.make` from
// effect/unstable/sql — the same construction path a production driver uses —
// backed by an in-memory SQLite database, so the stores are exercised through
// the genuine tagged-template/compiler pipeline.
// ---------------------------------------------------------------------------

const sqliteError = (cause: unknown): SqlError.SqlError =>
  new SqlError.SqlError({
    reason: new SqlError.UnknownError({
      cause,
      message: cause instanceof Error ? cause.message : "sqlite error",
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
      catch: sqliteError,
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
    executeValues: (sqlText, params) =>
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
        catch: sqliteError,
      }),
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

type StoreServices = Layer.Success<typeof layer> | SqlClient.SqlClient;

/** Run an effect against a fresh migrated database with every store layer. */
const run = <A, E>(effect: Effect.Effect<A, E, StoreServices>): Promise<A> =>
  Effect.runPromise(
    Effect.gen(function* () {
      yield* migrate;
      return yield* effect;
    }).pipe(Effect.provide(layer.pipe(Layer.provideMerge(sqlClientLayer())))) as Effect.Effect<
      A,
      E
    >,
  );

const makeUser = (email: string) =>
  Effect.gen(function* () {
    const store = yield* Auth.Email.EmailPasswordStore;
    return yield* store.createUser({ email, name: "Test User", attributes: { plan: "pro" } });
  });

describe("@thomasfosterau/effect-auth-sql stores over a real SqlClient", () => {
  it("migrate is idempotent and creates every auth_ table", async () => {
    const tables = await run(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        yield* migrate; // second run: every statement is IF NOT EXISTS
        const rows = yield* sql<{ name: string }>`
          SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
        return rows.map((row) => row.name);
      }),
    );
    expect(tables).toEqual([
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
    expect(result.listed.map((s) => s.id).sort()).toEqual(["sess-1", "sess-2"]);
    expect(result.missing).toBeNull();
    expect(result.other).toHaveLength(1);
  });

  it("EmailPasswordStore + UserStore share auth_users (booleans as 0/1, attributes as JSON)", async () => {
    const result = await run(
      Effect.gen(function* () {
        const emailPassword = yield* Auth.Email.EmailPasswordStore;
        const users = yield* Auth.UserStore;
        const created = yield* makeUser("a@example.com");
        const byEmail = yield* emailPassword.getUserByEmail("a@example.com");
        const missingEmail = yield* emailPassword.getUserByEmail("nobody@example.com");
        yield* emailPassword.setPasswordHash(created.id, "hash-1");
        const hash = yield* emailPassword.getPasswordHash(created.id);
        const credentials = yield* users.getCredentials(created.id);
        const loaded = yield* users.get(created.id);
        const missing = yield* users.get("nope");
        return { created, byEmail, missingEmail, hash, credentials, loaded, missing };
      }),
    );
    expect(result.created.emailVerified).toBe(false);
    expect(result.byEmail?.id).toBe(result.created.id);
    expect(result.byEmail?.attributes).toEqual({ plan: "pro" });
    expect(result.byEmail?.name).toBe("Test User");
    expect(result.missingEmail).toBeNull();
    expect(result.hash).toBe("hash-1");
    expect(result.credentials).toBe("hash-1");
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
          emailVerified: true,
          name: "Renamed",
          image: "https://example.com/x.png",
          updatedAt: new Date(),
        });
        const loaded = yield* store.get(created.id);
        yield* store.delete(created.id);
        const gone = yield* store.getByEmail("b@example.com");
        return { updated, loaded, gone };
      }),
    );
    expect(result.loaded?.emailVerified).toBe(true);
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
        const byEmail = yield* store.getUserByEmail("c@example.com");
        return { hash, byEmail };
      }),
    );
    expect(result.hash).toBe("reset-hash");
    expect(result.byEmail?.email).toBe("c@example.com");
  });

  it("RoleStore reads roles and permissions", async () => {
    const result = await run(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const store = yield* Auth.Authz.RoleStore;
        yield* sql`INSERT INTO auth_user_roles (user_id, role) VALUES ('user-1', 'admin')`;
        yield* sql`INSERT INTO auth_user_roles (user_id, role) VALUES ('user-1', 'editor')`;
        yield* sql`INSERT INTO auth_role_permissions (role, resource, action) VALUES ('admin', 'posts', 'delete')`;
        const roles = yield* store.getUserRoles("user-1");
        const permissions = yield* store.getRolePermissions("admin");
        const none = yield* store.getUserRoles("user-2");
        return { roles, permissions, none };
      }),
    );
    expect([...result.roles].sort()).toEqual(["admin", "editor"]);
    expect(result.permissions).toEqual([{ resource: "posts", action: "delete" }]);
    expect(result.none).toEqual([]);
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
          { key: "k", count: 9, resetAt: Date.now() + 60_000, blockedUntil: Date.now() + 120_000 },
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
        const store = yield* Auth.SecondFactor.ChallengeStore;
        yield* store.create({ challenge: bytes, expiresAt: Date.now() + 60_000, userId: "user-1" });
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
    const credential: Auth.SecondFactor.WebAuthnCredential = {
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
        const store = yield* Auth.SecondFactor.CredentialStore;
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
        const created = yield* store.createUser({
          email: "oauth@example.com",
          emailVerified: true,
          name: "OAuth User",
          image: "https://example.com/pic.png",
        });
        const loaded = yield* store.getUser(created.id);
        const byEmail = yield* store.getUserByEmail("oauth@example.com");
        const missing = yield* Effect.flip(store.getUser("nope"));
        const renamed = yield* store.updateUser!(created.id, { name: "Renamed" });
        return { created, loaded, byEmail, missing, renamed };
      }),
    );
    expect(result.created.emailVerified).toBe(true);
    expect(result.loaded.name).toBe("OAuth User");
    expect(result.byEmail?.image).toBe("https://example.com/pic.png");
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
        const user = yield* userStore.createUser({ email: "ml@example.com", emailVerified: true });
        const byEmail = yield* userStore.getUserByEmail("ml@example.com");
        return { loaded, two, three, user, byEmail };
      }),
    );
    expect(result.loaded?.email).toBe("a@example.com");
    expect(result.two).toBeNull();
    expect(result.three?.email).toBe("b@example.com");
    expect(result.byEmail?.id).toBe(result.user.id);
    expect(result.byEmail?.emailVerified).toBe(true);
  });

  it("EmailOTPStore upserts per email+purpose and increments attempts", async () => {
    const record: Auth.Email.EmailOTPRecord = {
      email: "otp@example.com",
      otpHash: "hash",
      purpose: "sign-in",
      attempts: 0,
      createdAt: Date.now(),
      expiresAt: Date.now() + 300_000,
    };
    const result = await run(
      Effect.gen(function* () {
        const store = yield* Auth.Email.EmailOTPStore;
        const userStore = yield* Auth.Email.EmailOTPUserStore;
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
        const user = yield* userStore.createUser({ email: "otp@example.com", emailVerified: true });
        const byEmail = yield* userStore.getUserByEmail("otp@example.com");
        return { attempts1, attempts2, replaced, other, deleted, missingIncrement, user, byEmail };
      }),
    );
    expect(result.attempts1).toBe(1);
    expect(result.attempts2).toBe(2);
    expect(result.replaced?.otpHash).toBe("new-hash");
    expect(result.replaced?.attempts).toBe(0);
    expect(result.other?.otpHash).toBe("other");
    expect(result.deleted).toBeNull();
    expect(result.missingIncrement._tag).toBe("AuthError");
    expect(result.byEmail?.id).toBe(result.user.id);
  });

  it("MultiFactorStore and PendingMultiFactorStore roundtrip incl. lastUsedCounter", async () => {
    const record: Auth.SecondFactor.MultiFactorRecord = {
      userId: "user-1",
      secret: "JBSWY3DPEHPK3PXP",
      backupCodes: ["h1", "h2", "h3"],
      verified: false,
      createdAt: Date.now(),
    };
    const pending: Auth.SecondFactor.PendingMultiFactor = {
      token: "p2f-1",
      userId: "user-1",
      expiresAt: Date.now() + 300_000,
      createdAt: Date.now(),
    };
    const result = await run(
      Effect.gen(function* () {
        const store = yield* Auth.SecondFactor.MultiFactorStore;
        const pendingStore = yield* Auth.SecondFactor.PendingMultiFactorStore;
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
    // epoch-milliseconds, ensuring Postgres/MySQL adopters don't get int4
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
    };

    interface PragmaRow {
      readonly name: string;
      readonly type: string;
    }

    await run(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        for (const [table, columns] of Object.entries(timestampColumns)) {
          const rows = yield* sql<PragmaRow>`PRAGMA table_info(${sql.literal(table)})`;
          const typeByCol = Object.fromEntries(rows.map((r) => [r.name, r.type.toUpperCase()]));
          for (const col of columns) {
            expect(typeByCol[col], `${table}.${col}`).toBe("BIGINT");
          }
        }
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
    const brokenConnection: SqlConnection.Connection = {
      execute: () => Effect.fail(sqliteError(new Error("simulated failure"))),
      executeRaw: () => Effect.fail(sqliteError(new Error("simulated failure"))),
      executeStream: () => Stream.fail(sqliteError(new Error("simulated failure"))),
      executeValues: () => Effect.fail(sqliteError(new Error("simulated failure"))),
      executeUnprepared: () => Effect.fail(sqliteError(new Error("simulated failure"))),
    };
    const brokenClientLayer = Layer.effect(
      SqlClient.SqlClient,
      Effect.gen(function* () {
        return yield* SqlClient.make({
          acquirer: Effect.succeed(brokenConnection),
          compiler: Statement.makeCompilerSqlite(),
          spanAttributes: [],
        });
      }),
    ).pipe(Layer.provide(Reactivity.layer));

    const program = Effect.gen(function* () {
      const challenges = yield* Auth.SecondFactor.ChallengeStore;
      const credentials = yield* Auth.SecondFactor.CredentialStore;
      const rateLimits = yield* Auth.RateLimitStore;
      const e1 = yield* Effect.flip(challenges.get(new Uint8Array([1, 2, 3])));
      const e2 = yield* Effect.flip(credentials.get("cred-id"));
      const e3 = yield* Effect.flip(rateLimits.get("key"));
      return { e1, e2, e3 };
    });

    const result = await Effect.runPromise(
      program.pipe(Effect.provide(layer.pipe(Layer.provideMerge(brokenClientLayer)))),
    );

    expect(result.e1._tag).toBe("AuthError");
    expect(result.e1.cause).toBeDefined();
    expect(result.e2._tag).toBe("AuthError");
    expect(result.e3._tag).toBe("AuthError");
  });

  it("decodeAttributes surfaces malformed JSON attributes as AuthError not defect", async () => {
    const result = await run(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient;
        const now = Date.now();
        yield* sql`INSERT INTO auth_users (id, email, email_verified, name, image, password_hash, attributes, created_at, updated_at)
          VALUES (${"u-corrupt"}, ${"corrupt@example.com"}, ${0}, ${null}, ${null}, ${null}, ${"INVALID_JSON"}, ${now}, ${now})`;
        const store = yield* Auth.UserServiceStore;
        return yield* Effect.flip(store.get("u-corrupt"));
      }),
    );
    expect(result._tag).toBe("AuthError");
    expect(result.cause).toBeDefined();
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
});
