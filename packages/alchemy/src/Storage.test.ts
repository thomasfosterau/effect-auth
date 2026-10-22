import { describe, it, expect } from "vite-plus/test";
import { Array as Arr, Effect, Layer, Order, Schema } from "effect";
import { SqlClient } from "effect/sql";
import * as Auth from "@thomasfosterau/effect-auth";
import * as Testing from "@thomasfosterau/effect-auth/testing";
import { authTableNames } from "./AuthTables.ts";
import * as D1Client from "./D1Client.ts";
import { layer, migrate } from "./Storage.ts";
import { makeTestD1 } from "./testShim.ts";

/**
 * Run an effect against a fresh D1-backed database with the schema applied and
 * every `@thomasfosterau/effect-auth-sql` store provided. Nothing is mocked
 * below the binding: the stores, the DDL and the `SqlClient` are the real
 * ones, and the binding is SQLite — which is what D1 is.
 */
const run = <A, E>(
  effect: Effect.Effect<A, E, Layer.Success<ReturnType<typeof layer>> | SqlClient.SqlClient>,
): Promise<A> => {
  const database = makeTestD1();
  const stores = layer(database).pipe(Layer.provideMerge(D1Client.layer({ db: database })));
  return Effect.runPromise(
    migrate(database).pipe(Effect.andThen(effect), Effect.provide(stores)) as Effect.Effect<A, E>,
  );
};

const listTables = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;
  const rows = yield* sql<{
    readonly name: string;
  }>`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth_%' ORDER BY name`;
  return rows.map((row) => row.name);
});

describe("D1-backed effect-auth storage", () => {
  it("applies the shared schema and converges on a re-run", async () => {
    const database = makeTestD1();
    const tables = await Effect.runPromise(
      migrate(database).pipe(
        // Every statement is `IF NOT EXISTS`: a second apply is a no-op.
        Effect.andThen(migrate(database)),
        Effect.andThen(listTables.pipe(Effect.provide(D1Client.layer({ db: database })))),
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
        const now = new Date();
        const session: Auth.Session = {
          id: "sess-1",
          userId: user.id,
          expiresAt: new Date(now.getTime() + 60_000),
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

  /**
   * These three stores wrap their DELETE-then-INSERT upsert in
   * `sql.withTransaction`. D1 rejects `BEGIN`/`COMMIT`, so {@link D1Client}
   * answers those control statements locally and the writes autocommit — this
   * asserts that path works end to end rather than dying.
   */
  it("supports the stores that ask for a transaction", async () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    const result = await run(
      Effect.gen(function* () {
        const challenges = yield* Auth.MultiFactor.ChallengeStore;
        yield* challenges.create({
          challenge: bytes,
          expiresAt: Date.now() + 60_000,
          userId: "user-1",
        });
        // A second create replaces the row — the DELETE + INSERT pair.
        yield* challenges.create({ challenge: bytes, expiresAt: Date.now() + 90_000 });
        const challenge = yield* challenges.get(bytes);

        const states = yield* Auth.OAuth.OAuthStateStore;
        yield* states.create({
          state: "st-1",
          provider: "google",
          codeVerifier: "cv",
          createdAt: Date.now(),
          expiresAt: Date.now() + 600_000,
        });
        const state = yield* states.get("st-1");

        const otps = yield* Auth.Email.EmailOtpStore;
        yield* otps.upsert({
          email: "otp@example.com",
          otpHash: "hash",
          purpose: "sign-in",
          attempts: 0,
          createdAt: Date.now(),
          expiresAt: Date.now() + 300_000,
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
   * `IdentifierStore.replace` asks for a transaction too: its INSERT-then-DELETE
   * autocommits on D1, in that order, and a taken address is still refused by
   * the unique index with the old address kept.
   */
  it("replaces an identifier, and refuses a taken address keeping the old one", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const ada = yield* identifiers.create(
          Auth.makeIdentifier({ userId: "user-1", type: "email", value: "ada@example.com" }),
        );
        yield* identifiers.create(
          Auth.makeIdentifier({ userId: "user-2", type: "email", value: "grace@example.com" }),
        );
        const replaced = yield* Auth.replaceIdentifier(
          identifiers,
          ada,
          Auth.makeIdentifier({
            userId: "user-1",
            type: "email",
            value: "ada-new@example.com",
            verified: true,
          }),
        );
        const taken = yield* Effect.flip(
          Auth.replaceIdentifier(
            identifiers,
            replaced,
            Auth.makeIdentifier({ userId: "user-1", type: "email", value: "grace@example.com" }),
          ),
        );
        // A concurrent claim the read-before-write cannot see: the store's own
        // unique index refuses it and the old address stays.
        const raced = yield* Effect.flip(
          identifiers.replace(
            replaced,
            Auth.makeIdentifier({ userId: "user-1", type: "email", value: "grace@example.com" }),
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
   * Without a transaction the release is still a compare-and-swap: two replaces
   * of the same address run concurrently, their statements interleaving on the
   * binding, and only one releases it. The other deletes its own claim again.
   */
  it("lets one of two concurrent replaces of the same address succeed", async () => {
    const result = await run(
      Effect.gen(function* () {
        const identifiers = yield* Auth.IdentifierStore;
        const ada = yield* identifiers.create(
          Auth.makeIdentifier({ userId: "user-1", type: "email", value: "ada@example.com" }),
        );
        const outcomes = yield* Effect.all(
          ["ada-a@example.com", "ada-b@example.com"].map((value) =>
            identifiers.replace(
              ada,
              Auth.makeIdentifier({ userId: "user-1", type: "email", value, verified: true }),
            ),
          ),
          { concurrency: "unbounded" },
        );
        return { outcomes, listed: yield* identifiers.listByUser("user-1") };
      }),
    );
    const won = result.outcomes.filter((outcome) => outcome !== null);
    expect(won).toHaveLength(1);
    expect(result.listed.map((identifier) => identifier.value)).toEqual([won[0]!.value]);
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
          expiresAt: new Date(farFuture),
          createdAt: new Date(farFuture - 1000),
          lastActivityAt: new Date(farFuture - 500),
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
  for (const suite of [
    Testing.sessionStoreConformance({ seedUser }),
    Testing.userStoreConformance({ seedUser }),
    Testing.identifierStoreConformance({ seedUser }),
    Testing.apiKeyStoreConformance({ seedUser }),
  ]) {
    describe(suite.contract, () => {
      for (const testCase of suite.cases) {
        it(testCase.name, () => run(testCase.run));
      }
    });
  }
});
