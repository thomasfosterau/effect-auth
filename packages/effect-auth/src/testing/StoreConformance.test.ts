/**
 * The conformance suites run against the core's own in-memory stores, and
 * against deliberately broken ones, which they must fail. effect-auth-sql runs
 * the same suites over SQLite and PostgreSQL (`packages/sql/src/Stores.test.ts`).
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Array as Arr, Effect, Layer, Result } from "effect";
import { KeyValueStore } from "effect/persistence";
import * as ApiKey from "../ApiKey.ts";
import * as Errors from "../Errors.ts";
import { type Identifier, IdentifierStore } from "../Identifier.ts";
import { IdentifierStoreKV } from "../KeyValueStores.ts";
import { SessionStore } from "../SessionStore.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";
import * as Testing from "./index.ts";

const sessionStore = (): typeof SessionStore.Service => {
  const sessions = new Map<string, Types.Session>();
  return {
    create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    get: (id) => Effect.sync(() => sessions.get(id) ?? null),
    update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
    delete: (id) => Effect.sync(() => void sessions.delete(id)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        sessions.forEach((session, id) => {
          if (session.userId === userId) sessions.delete(id);
        });
      }),
    listByUserId: (userId) =>
      Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
  };
};

const apiKeyStore = (): typeof ApiKey.ApiKeyStore.Service => {
  const keys = new Map<string, ApiKey.ApiKey>();
  return {
    create: (key) => Effect.sync(() => (keys.set(key.id, key), key)),
    get: (id) => Effect.sync(() => keys.get(id) ?? null),
    getByHash: (hash) =>
      Effect.sync(() => [...keys.values()].find((key) => key.keyHash === hash) ?? null),
    update: (key) => Effect.sync(() => (keys.set(key.id, key), key)),
    delete: (id) => Effect.sync(() => void keys.delete(id)),
    listByUserId: (userId) =>
      Effect.sync(() => [...keys.values()].filter((key) => key.userId === userId)),
  };
};

const users = new Map<string, Types.User>();
const userStore: typeof UserStore.Service = {
  get: (id) => Effect.sync(() => users.get(id) ?? null),
};
const seedUser = (user: Types.User) => Effect.sync(() => void users.set(user.id, user));

const register = <E, R>(
  suite: Testing.ConformanceSuite<E, R>,
  layer: () => Layer.Layer<R, unknown>,
): void => {
  describe(`${suite.contract} conformance`, () => {
    Arr.forEach(suite.cases, (testCase) => {
      it(testCase.name, () =>
        Effect.runPromise(testCase.run.pipe(Effect.provide(layer())) as Effect.Effect<void>),
      );
    });
  });
};

register(Testing.sessionStoreConformance(), () => Layer.succeed(SessionStore, sessionStore()));
register(Testing.userStoreConformance({ seedUser }), () => Layer.succeed(UserStore, userStore));
register(Testing.apiKeyStoreConformance(), () => Layer.succeed(ApiKey.ApiKeyStore, apiKeyStore()));
register(Testing.identifierStoreConformance(), () =>
  IdentifierStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
);

describe("the suites share one store", () => {
  it("runs every case of a suite against a single store instance", async () => {
    const layer = Layer.succeed(SessionStore, sessionStore());
    await Arr.reduce(
      Testing.sessionStoreConformance().cases,
      Promise.resolve(),
      async (previous, testCase) => {
        await previous;
        await Effect.runPromise(testCase.run.pipe(Effect.provide(layer)));
      },
    );
  });

  it("calls seedUser for every user a case touches", async () => {
    const seeded: Array<string> = [];
    const suite = Testing.sessionStoreConformance({
      seedUser: (user) => Effect.sync(() => void seeded.push(user.id)),
    });
    const listing = suite.cases.find((testCase) => testCase.name.startsWith("listByUserId"));
    assert(listing !== undefined, "the suite has a listByUserId case");

    await Effect.runPromise(
      listing.run.pipe(Effect.provide(Layer.succeed(SessionStore, sessionStore()))),
    );
    expect(seeded).toHaveLength(2);
  });
});

/** The names of the cases a store fails, with the first message. */
const failures = async <E, R>(
  suite: Testing.ConformanceSuite<E, R>,
  layer: () => Layer.Layer<R>,
): Promise<ReadonlyArray<{ readonly name: string; readonly error: unknown }>> => {
  const failed: Array<{ readonly name: string; readonly error: unknown }> = [];
  await Arr.reduce(suite.cases, Promise.resolve(), async (previous, testCase) => {
    await previous;
    const result = await Effect.runPromise(
      Effect.result(testCase.run.pipe(Effect.provide(layer())) as Effect.Effect<void, unknown>),
    );
    if (Result.isFailure(result)) failed.push({ name: testCase.name, error: result.failure });
  });
  return failed;
};

describe("a broken store fails its suite", () => {
  it("a SessionStore that drops attributes fails the round trip with a ConformanceError", async () => {
    const failed = await failures(Testing.sessionStoreConformance(), () => {
      const inner = sessionStore();
      return Layer.succeed(SessionStore, {
        ...inner,
        create: (session) => inner.create({ ...session, attributes: {} }),
      });
    });
    expect(failed.map((failure) => failure.name)).toContain(
      "create returns the session, and get reads it back with its dates and attributes",
    );
    expect(failed[0]?.error).toEqual(
      expect.objectContaining({ _tag: "ConformanceError", contract: "SessionStore" }),
    );
  });

  it("a SessionStore whose deleteByUserId deletes everyone's sessions fails", async () => {
    const failed = await failures(Testing.sessionStoreConformance(), () => {
      const inner = sessionStore();
      const ids = new Set<string>();
      return Layer.succeed(SessionStore, {
        ...inner,
        create: (session) => (ids.add(session.id), inner.create(session)),
        deleteByUserId: () =>
          Effect.forEach([...ids], (id) => inner.delete(id), {
            concurrency: 1,
            discard: true,
          }),
      });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "deleteByUserId removes that user's sessions only, and is a no-op for a user with none",
    ]);
  });

  it("an IdentifierStore that swallows its unique-constraint error fails the uniqueness case", async () => {
    const failed = await failures(Testing.identifierStoreConformance(), () =>
      Layer.effect(
        IdentifierStore,
        Effect.map(Effect.service(IdentifierStore), (inner) => ({
          ...inner,
          create: (identifier: Identifier) =>
            inner.create(identifier).pipe(Effect.catch(() => Effect.succeed(identifier))),
        })),
      ).pipe(Layer.provide(IdentifierStoreKV), Layer.provide(KeyValueStore.layerMemory)),
    );
    expect(failed.map((failure) => failure.name)).toEqual([
      "create refuses a claimed (type, value) with AuthError, which claimIdentifier reports as taken",
    ]);
  });

  it("an ApiKeyStore whose getByHash misses fails", async () => {
    const failed = await failures(Testing.apiKeyStoreConformance(), () => {
      const inner = apiKeyStore();
      return Layer.succeed(ApiKey.ApiKeyStore, { ...inner, getByHash: () => Effect.succeed(null) });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "create returns the key, and get and getByHash read it back with every field",
    ]);
  });

  it("a store that fails unexpectedly fails the case with its own AuthError", async () => {
    const failed = await failures(Testing.userStoreConformance({ seedUser }), () =>
      Layer.succeed(UserStore, {
        get: () => Effect.fail(new Errors.AuthError({ message: "database down" })),
      }),
    );
    expect(failed).toHaveLength(3);
    expect(failed.every((failure) => failure.error instanceof Errors.AuthError)).toBe(true);
  });
});
