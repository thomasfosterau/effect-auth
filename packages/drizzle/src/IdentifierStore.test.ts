/**
 * The drizzle `IdentifierStore` exercised against a real PostgreSQL engine
 * (PGlite — Postgres compiled to WASM, in-process, no server), so `RETURNING`
 * and the `(type, value)` unique-index violation behave exactly as they do in
 * production.
 */

import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vite-plus/test";
import * as Auth from "@thomasfosterau/effect-auth";
import { databaseLayer } from "./Database.ts";
import { layer as identifierStoreLayer } from "./IdentifierStore.ts";
import { migrationStatements, tables } from "./PgSchema.ts";

/**
 * Spin up a fresh in-memory Postgres, apply the exported DDL, run `build`'s
 * program against the identifier store, then tear the database down.
 */
const runFresh = async <A, E>(
  build: () => Effect.Effect<A, E, Auth.IdentifierStore>,
): Promise<A> => {
  const client = await PGlite.create();
  try {
    for (const statement of migrationStatements()) {
      await client.exec(statement);
    }
    const db = drizzle(client);
    return await Effect.runPromise(
      build().pipe(
        Effect.provide(identifierStoreLayer(tables).pipe(Layer.provide(databaseLayer(db)))),
      ) as Effect.Effect<A, E>,
    );
  } finally {
    await client.close();
  }
};

const at = (offsetMs: number): Date => new Date(Date.UTC(2026, 0, 1) + offsetMs);

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
