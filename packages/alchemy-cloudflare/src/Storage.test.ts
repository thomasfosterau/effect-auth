import { assert, describe, it, expect } from "vite-plus/test";
import { Clock, DateTime, Effect, Layer, Order } from "effect";
import * as Arr from "effect/Array";
import * as Schema from "effect/Schema";
import { SqlClient } from "effect/sql";
import type { RuntimeContext } from "alchemy/RuntimeContext";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { authTableNames } from "@thomasfosterau/effect-auth/sql";
import * as D1Client from "./D1Client.ts";
import { layer, migrate, purgeExpired } from "./Storage.ts";
import { makeTestD1, runtimeContext } from "./testShim.ts";

/** Run an effect the way a Worker event does: with Alchemy's `RuntimeContext`. */
const runPromise = <A, E>(effect: Effect.Effect<A, E, RuntimeContext>): Promise<A> =>
  Effect.runPromise(effect.pipe(Effect.provide(runtimeContext)));

/**
 * Run an effect against a fresh D1-backed database with the schema applied and
 * every `@thomasfosterau/effect-auth/sql` store provided. Nothing is mocked
 * above the raw binding: the stores, the DDL, the `SqlClient` and Alchemy's
 * D1 client are the real ones, and the binding is SQLite — which is what D1 is.
 */
const run = <A, E>(
  effect: Effect.Effect<
    A,
    E,
    Layer.Success<ReturnType<typeof layer>> | SqlClient.SqlClient | RuntimeContext
  >,
): Promise<A> => {
  const database = makeTestD1();
  const stores = layer(database).pipe(Layer.provideMerge(D1Client.layer({ db: database })));
  return runPromise(migrate(database).pipe(Effect.andThen(effect), Effect.provide(stores)));
};

describe("D1-backed effect-auth storage", () => {
  it("applies the shared schema and converges on a re-run", async () => {
    const database = makeTestD1();
    const tables = await runPromise(
      migrate(database).pipe(
        // Every statement is `IF NOT EXISTS`: a second apply is a no-op.
        Effect.andThen(migrate(database)),
        Effect.andThen(
          Effect.gen(function* () {
            const sql = yield* SqlClient.SqlClient;
            const rows = yield* sql<{
              readonly name: string;
            }>`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
            return rows.map((row) => row.name);
          }).pipe(Effect.provide(D1Client.layer({ db: database }))),
        ),
      ),
    );
    expect(tables).toEqual(Arr.sort(authTableNames, Order.String));
    expect(tables).toContain("auth_users");
    expect(tables).toContain("auth_sessions");
  });

  it("round-trips users and sessions through the SQL stores", async () => {
    const result = await run(
      Effect.gen(function* () {
        const users = yield* Auth.Email.EmailPasswordStore;
        const sessions = yield* Auth.SessionStore;
        const { user } = yield* users.createUser({
          name: "Test User",
          attributes: { plan: "pro" },
        });
        const now = yield* DateTime.nowAsDate;
        const session: Auth.Session = {
          id: "sess-1",
          userId: user.id,
          expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(now.getTime() + 60_000)),
          createdAt: now,
          lastActivityAt: now,
          attributes: { device: "laptop" },
        };
        yield* sessions.create(session);
        const loaded = yield* sessions.get("sess-1");
        yield* sessions.delete("sess-1");
        const deleted = yield* sessions.get("sess-1");
        return { user, loaded, deleted };
      }),
    );
    expect(result.user.attributes).toEqual({ plan: "pro" });
    expect(result.loaded?.userId).toBe(result.user.id);
    expect(result.loaded?.attributes).toEqual({ device: "laptop" });
    expect(result.loaded?.expiresAt).toBeInstanceOf(Date);
    expect(result.deleted).toBeNull();
  });

  it("runs the atomic single-statement upserts (ON CONFLICT / RETURNING)", async () => {
    const result = await run(
      Effect.gen(function* () {
        const limits = yield* Auth.RateLimitStore;
        const first = yield* limits.increment("k", 60);
        const second = yield* limits.increment("k", 60);
        yield* limits.delete("k");
        const deleted = yield* limits.get("k");
        return { first, second, deleted };
      }),
    );
    expect(result.first).toBe(1);
    expect(result.second).toBe(2);
    expect(result.deleted).toBeNull();
  });

  it("purges expired magic links and email OTPs through the binding", async () => {
    const database = makeTestD1();
    const result = await runPromise(
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        yield* migrate(database);
        yield* Effect.gen(function* () {
          const links = yield* Auth.MagicLinkStore;
          yield* links.create({
            token: "stale",
            email: "a@example.com",
            createdAt: now - 600_000,
            expiresAt: now - 1,
          });
          yield* links.create({
            token: "live",
            email: "b@example.com",
            createdAt: now,
            expiresAt: now + 300_000,
          });
        }).pipe(Effect.provide(layer(database)));
        return yield* purgeExpired(database);
      }),
    );
    expect(result).toEqual({ magicLinks: 1, emailOtps: 0 });
  });

  /**
   * These three stores wrap their DELETE-then-INSERT upsert in
   * `sql.withTransaction`. D1 rejects `BEGIN`/`COMMIT`, so {@link D1Client}
   * sends the transaction's writes as one `batch()` — this asserts that path
   * works end to end rather than dying.
   */
  it("supports the stores that ask for a transaction", async () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    const result = await run(
      Effect.gen(function* () {
        const challenges = yield* Auth.MultiFactor.ChallengeStore;
        yield* challenges.create({
          challenge: bytes,
          expiresAt: (yield* Clock.currentTimeMillis) + 60_000,
          userId: "user-1",
        });
        // A second create replaces the row — the DELETE + INSERT pair.
        yield* challenges.create({
          challenge: bytes,
          expiresAt: (yield* Clock.currentTimeMillis) + 90_000,
        });
        const challenge = yield* challenges.get(bytes);

        const states = yield* Auth.OAuth.OAuthStateStore;
        yield* states.create({
          state: "st-1",
          provider: "google",
          codeVerifier: "cv",
          createdAt: yield* Clock.currentTimeMillis,
          expiresAt: (yield* Clock.currentTimeMillis) + 600_000,
        });
        const state = yield* states.get("st-1");

        const otps = yield* Auth.Email.EmailOtpStore;
        yield* otps.upsert({
          email: "otp@example.com",
          otpHash: "hash",
          purpose: "sign-in",
          attempts: 0,
          createdAt: yield* Clock.currentTimeMillis,
          expiresAt: (yield* Clock.currentTimeMillis) + 300_000,
        });
        const attempts = yield* otps.incrementAttempts("otp@example.com", "sign-in");

        return { challenge, state, attempts };
      }),
    );
    expect(Array.from(result.challenge?.challenge ?? [])).toEqual([0, 1, 2, 250, 255]);
    expect(result.challenge?.userId).toBeUndefined();
    expect(result.state?.codeVerifier).toBe("cv");
    expect(result.attempts).toBe(1);
  });

  /**
   * `IdentifierStore.replace` asks for a transaction too: its INSERT and its
   * `DELETE … RETURNING` go to D1 in one batch, and a taken address is refused
   * by the unique index with the old address kept.
   */
  it("replaces an identifier, and refuses a taken address keeping the old one", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const ada = yield* identifiers.create(
          Auth.makeIdentifier({
            userId: "user-1",
            type: "email",
            value: "ada@example.com",
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          }),
        );
        yield* identifiers.create(
          Auth.makeIdentifier({
            userId: "user-2",
            type: "email",
            value: "grace@example.com",
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          }),
        );
        const replaced = yield* Auth.replaceIdentifier(
          identifiers,
          ada,
          Auth.makeIdentifier({
            userId: "user-1",
            type: "email",
            value: "ada-new@example.com",
            verified: true,
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          }),
        );
        const taken = yield* Effect.flip(
          Auth.replaceIdentifier(
            identifiers,
            replaced,
            Auth.makeIdentifier({
              userId: "user-1",
              type: "email",
              value: "grace@example.com",
              now: DateTime.toDateUtc(DateTime.nowUnsafe()),
            }),
          ),
        );
        // A concurrent claim the read-before-write cannot see: the store's own
        // unique index refuses it and the old address stays.
        const raced = yield* Effect.flip(
          identifiers.replace(
            replaced,
            Auth.makeIdentifier({
              userId: "user-1",
              type: "email",
              value: "grace@example.com",
              now: DateTime.toDateUtc(DateTime.nowUnsafe()),
            }),
          ),
        );
        return {
          replaced,
          taken,
          raced,
          listed: yield* identifiers.listByUser("user-1"),
          grace: yield* identifiers.getByValue("email", "grace@example.com"),
        };
      }),
    );
    expect(result.replaced.value).toBe("ada-new@example.com");
    expect(result.taken._tag).toBe("IdentifierTakenError");
    expect(result.raced._tag).toBe("AuthError");
    expect(result.listed.map((identifier) => [identifier.value, identifier.verified])).toEqual([
      ["ada-new@example.com", true],
    ]);
    expect(result.grace?.userId).toBe("user-2");
  });

  /**
   * The release is a compare-and-swap: two replaces of the same address run
   * concurrently, their batches interleaving on the binding, and only one
   * releases it. The other deletes its own claim again.
   */
  it("lets one of two concurrent replaces of the same address succeed", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const ada = yield* identifiers.create(
          Auth.makeIdentifier({
            userId: "user-1",
            type: "email",
            value: "ada@example.com",
            now: DateTime.toDateUtc(DateTime.nowUnsafe()),
          }),
        );
        const outcomes = yield* Effect.all(
          ["ada-a@example.com", "ada-b@example.com"].map((value) =>
            identifiers.replace(
              ada,
              Auth.makeIdentifier({
                userId: "user-1",
                type: "email",
                value,
                verified: true,
                now: DateTime.toDateUtc(DateTime.nowUnsafe()),
              }),
            ),
          ),
          { concurrency: "unbounded" },
        );
        return { outcomes, listed: yield* identifiers.listByUser("user-1") };
      }),
    );
    const won = result.outcomes.filter((outcome) => outcome !== null);
    const [winner] = won;
    assert(won.length === 1 && winner !== undefined, "exactly one replace wins");
    expect(result.listed.map((identifier) => identifier.value)).toEqual([winner.value]);
  });

  it("keeps epoch-millisecond timestamps intact through BIGINT columns", async () => {
    // ~2065: overflows a 32-bit INTEGER, so this is the column-type check.
    const farFuture = 3_000_000_000_000;
    const loaded = await run(
      Effect.gen(function* () {
        const sessions = yield* Auth.SessionStore;
        yield* sessions.create({
          id: "sess-bigint",
          userId: "user-1",
          expiresAt: DateTime.toDateUtc(DateTime.makeUnsafe(farFuture)),
          createdAt: DateTime.toDateUtc(DateTime.makeUnsafe(farFuture - 1000)),
          lastActivityAt: DateTime.toDateUtc(DateTime.makeUnsafe(farFuture - 500)),
          attributes: {},
        });
        return yield* sessions.get("sess-bigint");
      }),
    );
    expect(loaded?.expiresAt.getTime()).toBe(farFuture);
  });
});

// The core's published conformance suites (`@thomasfosterau/effect-auth/testing`),
// over the D1 stores: a fresh database per case.
describe("D1-backed effect-auth storage: conformance", () => {
  const encodeAttributes = Schema.encodeSync(Schema.fromJsonString(Schema.Unknown));
  const seedUser = (user: Auth.User) =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      yield* sql`INSERT INTO auth_users (id, name, image, password_hash, attributes, created_at, updated_at)
        VALUES (${user.id}, ${user.name ?? null}, ${user.image ?? null}, ${null}, ${encodeAttributes(user.attributes)}, ${user.createdAt.getTime()}, ${user.updatedAt.getTime()})`;
    });
  Arr.forEach(
    [
      Testing.sessionStoreConformance({ seedUser }),
      Testing.userStoreConformance({ seedUser }),
      Testing.identifierStoreConformance({ seedUser }),
      Testing.apiKeyStoreConformance({ seedUser }),
      Testing.emailOtpStoreConformance(),
      Testing.pendingMultiFactorStoreConformance({ seedUser }),
    ],
    (suite) => {
      describe(suite.contract, () => {
        suite.cases.forEach((testCase) => {
          it(testCase.name, () => run(testCase.run));
        });
      });
    },
  );
});

/** Run an effect with a `SqlClient` over `database`. */
const withSql = <A, E>(
  database: ReturnType<typeof makeTestD1>,
  effect: Effect.Effect<A, E, SqlClient.SqlClient>,
): Promise<A> => runPromise(effect.pipe(Effect.provide(D1Client.layer({ db: database }))));

// The transaction mapping itself (see `D1Client`'s module docs): a transaction's
// writes go to D1 as `batch()`es, so they commit or fail together.
describe("D1Client transactions", () => {
  const setUp = Effect.fn("setUp")(function* () {
    const sql = yield* SqlClient.SqlClient;
    yield* sql`CREATE TABLE t (id TEXT PRIMARY KEY, n INTEGER NOT NULL)`;
    yield* sql`INSERT INTO t (id, n) VALUES ('a', 1)`;
  });

  const ids = Effect.fn("ids")(function* () {
    const sql = yield* SqlClient.SqlClient;
    const rows = yield* sql<{ readonly id: string }>`SELECT id FROM t ORDER BY id`;
    return rows.map((row) => row.id);
  });

  it("rolls back every write of a transaction whose batch fails", async () => {
    const database = makeTestD1();
    const result = await withSql(
      database,
      Effect.gen(function* () {
        yield* setUp();
        const sql = yield* SqlClient.SqlClient;
        const failure = yield* Effect.flip(
          sql.withTransaction(
            Effect.gen(function* () {
              yield* sql`DELETE FROM t WHERE id = 'a'`;
              yield* sql`INSERT INTO t (id, n) VALUES ('b', 2)`;
              // NOT NULL violation: the whole batch, the DELETE included, fails.
              yield* sql`INSERT INTO t (id, n) VALUES ('c', NULL)`;
            }),
          ),
        );
        return { failure, ids: yield* ids() };
      }),
    );
    expect(result.failure._tag).toBe("SqlError");
    expect(result.ids).toEqual(["a"]);
  });

  it("lets a read inside a transaction see the writes buffered before it", async () => {
    const database = makeTestD1();
    const result = await withSql(
      database,
      Effect.gen(function* () {
        yield* setUp();
        const sql = yield* SqlClient.SqlClient;
        const inside = yield* sql.withTransaction(
          Effect.gen(function* () {
            yield* sql`INSERT INTO t (id, n) VALUES ('b', 2)`;
            return yield* sql<{ readonly id: string }>`DELETE FROM t WHERE id = 'a' RETURNING id`;
          }),
        );
        return { inside: inside.map((row) => row.id), ids: yield* ids() };
      }),
    );
    expect(result.inside).toEqual(["a"]);
    expect(result.ids).toEqual(["b"]);
  });

  it("discards a rolled-back transaction, and a nested one back to its savepoint", async () => {
    const database = makeTestD1();
    const result = await withSql(
      database,
      Effect.gen(function* () {
        yield* setUp();
        const sql = yield* SqlClient.SqlClient;
        yield* Effect.flip(
          sql.withTransaction(
            Effect.andThen(sql`INSERT INTO t (id, n) VALUES ('x', 9)`, Effect.fail("abort")),
          ),
        );
        const afterRollback = yield* ids();
        yield* sql.withTransaction(
          Effect.gen(function* () {
            yield* sql`INSERT INTO t (id, n) VALUES ('b', 2)`;
            yield* Effect.flip(
              sql.withTransaction(
                Effect.andThen(sql`INSERT INTO t (id, n) VALUES ('c', 3)`, Effect.fail("inner")),
              ),
            );
          }),
        );
        return { afterRollback, afterNested: yield* ids() };
      }),
    );
    expect(result.afterRollback).toEqual(["a"]);
    expect(result.afterNested).toEqual(["a", "b"]);
  });

  it("reports a failed statement as a SqlError", async () => {
    const database = makeTestD1();
    const failure = await withSql(
      database,
      Effect.flip(Effect.flatMap(SqlClient.SqlClient, (sql) => sql`SELECT * FROM missing`)),
    );
    expect(failure._tag).toBe("SqlError");
  });
});
