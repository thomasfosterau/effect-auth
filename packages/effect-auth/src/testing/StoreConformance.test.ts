/**
 * The conformance suites run against the core's own in-memory stores, and
 * against deliberately broken ones, which they must fail. effect-auth/sql runs
 * the same suites over SQLite and PostgreSQL (`packages/effect-auth/src/sql/Stores.test.ts`).
 */
import { assert, describe, expect, it } from "vite-plus/test";
import { Effect, Layer, MutableHashMap, MutableHashSet, Result } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import { KeyValueStore } from "effect/persistence";
import * as ApiKey from "../ApiKey.ts";
import * as Errors from "../Errors.ts";
import { type Identifier, IdentifierStore } from "../Identifier.ts";
import { IdentifierStoreKV } from "../KeyValueStores.ts";
import { type OAuthAccount, OAuthAccountStore } from "../oauth/OAuthAccount.ts";
import { type OneTimeTokenRecord, OneTimeTokenStore } from "../OneTimeToken.ts";
import { PhoneOtpStore } from "../PhoneOtp.ts";
import { SessionStore } from "../SessionStore.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";
import * as Testing from "./index.ts";
import { memorySessionStore } from "./MemoryStores.ts";
import type { SessionTouch } from "../SessionStore.ts";

const sessionStore = (): typeof SessionStore.Service => {
  const sessions = MutableHashMap.empty<string, Types.Session>();
  return {
    create: (session) =>
      Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
    get: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, id))),
    update: (session) => memorySessionStore(sessions).update(session),
    touch: (sessionId: string, touch: SessionTouch) =>
      memorySessionStore(sessions).touch(sessionId, touch),
    delete: (id) => Effect.sync(() => void MutableHashMap.remove(sessions, id)),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        MutableHashMap.forEach(sessions, (session, id) => {
          if (session.userId === userId) MutableHashMap.remove(sessions, id);
        });
      }),
    listByUserId: (userId) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(sessions)).filter(
          (session) => session.userId === userId,
        ),
      ),
  };
};

const users = MutableHashMap.empty<string, Types.User>();
const userStore: typeof UserStore.Service = {
  get: (id) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(users, id))),
};
const seedUser = (user: Types.User) =>
  Effect.sync(() => void MutableHashMap.set(users, user.id, user));

const register = <E, R>(
  suite: Testing.ConformanceSuite<E, R>,
  layer: () => Layer.Layer<R, unknown>,
): void => {
  describe(`${suite.contract} conformance`, () => {
    Arr.forEach(suite.cases, (testCase) => {
      it(testCase.name, () => Effect.runPromise(testCase.run.pipe(Effect.provide(layer()))));
    });
  });
};

register(Testing.sessionStoreConformance(), () => Layer.succeed(SessionStore, sessionStore()));
register(Testing.userStoreConformance({ seedUser }), () => Layer.succeed(UserStore, userStore));
register(Testing.apiKeyStoreConformance(), () =>
  Layer.succeed(ApiKey.ApiKeyStore, Testing.memoryApiKeyStore()),
);
register(Testing.identifierStoreConformance(), () =>
  IdentifierStoreKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
);

/**
 * A `OneTimeTokenStore` over a map. With `yieldBetween`, its `consume` is the
 * pre-atomic shape: a `get`, then a `delete`, with a fiber switch between them.
 */
const oneTimeTokenStore = (yieldBetween = false): typeof OneTimeTokenStore.Service => {
  const tokens = MutableHashMap.empty<string, OneTimeTokenRecord>();
  const get = (token: string) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(tokens, token)));
  const remove = (token: string) => Effect.sync(() => void MutableHashMap.remove(tokens, token));
  return {
    create: (record) =>
      Effect.sync(() => (MutableHashMap.set(tokens, record.token, record), record)),
    get,
    consume: (token) =>
      Effect.gen(function* () {
        const found = yield* get(token);
        if (yieldBetween) yield* Effect.yieldNow;
        if (found !== null) yield* remove(token);
        return found;
      }),
    delete: remove,
  };
};
register(Testing.oneTimeTokenStoreConformance(), () =>
  Layer.succeed(OneTimeTokenStore, oneTimeTokenStore()),
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
      Effect.result(testCase.run.pipe(Effect.provide(layer()))),
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
      const ids = MutableHashSet.empty<string>();
      return Layer.succeed(SessionStore, {
        ...inner,
        create: (session) => (MutableHashSet.add(ids, session.id), inner.create(session)),
        deleteByUserId: () =>
          Effect.forEach(Arr.fromIterable(ids), (id) => inner.delete(id), {
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
            inner.create(identifier).pipe(Effect.orElseSucceed(() => identifier)),
        })),
      ).pipe(Layer.provide(IdentifierStoreKV), Layer.provide(KeyValueStore.layerMemory)),
    );
    expect(failed.map((failure) => failure.name)).toEqual([
      "create refuses a claimed (type, value) with AuthError, which claimIdentifier reports as taken",
    ]);
  });

  it("an ApiKeyStore whose getByHash misses fails", async () => {
    const failed = await failures(Testing.apiKeyStoreConformance(), () => {
      const inner = Testing.memoryApiKeyStore();
      return Layer.succeed(ApiKey.ApiKeyStore, { ...inner, getByHash: () => Effect.succeed(null) });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "create returns the key, and get and getByHash read it back with every field",
    ]);
  });

  it("an ApiKeyStore whose deleteByUserId keeps the keys, or deletes everyone's, fails the per-user delete case", async () => {
    const perUser =
      "deleteByUserId removes that user's keys only, and is a no-op for a user with none";
    const keeping = await failures(Testing.apiKeyStoreConformance(), () =>
      Layer.succeed(ApiKey.ApiKeyStore, {
        ...Testing.memoryApiKeyStore(),
        deleteByUserId: () => Effect.void,
      }),
    );
    expect(keeping.map((failure) => failure.name)).toEqual([perUser]);
    const sweeping = await failures(Testing.apiKeyStoreConformance(), () => {
      const keys = MutableHashMap.empty<string, ApiKey.ApiKey>();
      return Layer.succeed(ApiKey.ApiKeyStore, {
        ...Testing.memoryApiKeyStore(keys),
        deleteByUserId: () => Effect.sync(() => MutableHashMap.clear(keys)),
      });
    });
    expect(sweeping.map((failure) => failure.name)).toEqual([perUser]);
  });

  it("an OAuthAccountStore whose deleteByUserId is a no-op fails its suite", async () => {
    const failed = await failures(Testing.oauthAccountStoreConformance(), () =>
      Layer.succeed(OAuthAccountStore, {
        ...Testing.memoryOAuthAccountStore(),
        deleteByUserId: () => Effect.void,
      }),
    );
    expect(failed.map((failure) => failure.name)).toEqual([
      "deleteByUserId removes that user's provider links only, and is a no-op for a user with none",
    ]);
  });

  it("an OAuthAccountStore whose create and update upsert on (provider, providerId) fails its suite", async () => {
    const failed = await failures(Testing.oauthAccountStoreConformance(), () => {
      const accounts = MutableHashMap.empty<string, OAuthAccount>();
      const key = (account: OAuthAccount) => `${account.provider}\u0000${account.providerId}`;
      const upsert = (account: OAuthAccount) =>
        Effect.sync(() => (MutableHashMap.set(accounts, key(account), account), account));
      return Layer.succeed(OAuthAccountStore, {
        ...Testing.memoryOAuthAccountStore(undefined, accounts),
        create: upsert,
        update: upsert,
      });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "create refuses a provider account already linked with AuthError, and the link keeps its user",
      "update refreshes tokens and profile by id, never changes userId, and never creates",
    ]);
  });

  it("an OAuthAccountStore whose linkToUser moves another user's link fails its suite", async () => {
    const failed = await failures(Testing.oauthAccountStoreConformance(), () => {
      const accounts = MutableHashMap.empty<string, OAuthAccount>();
      const key = (account: OAuthAccount) => `${account.provider}\u0000${account.providerId}`;
      return Layer.succeed(OAuthAccountStore, {
        ...Testing.memoryOAuthAccountStore(undefined, accounts),
        linkToUser: (userId, account) =>
          Effect.sync(() => {
            const stored = MutableHashMap.get(accounts, key(account));
            if (Option.isSome(stored)) {
              MutableHashMap.set(accounts, key(account), { ...stored.value, userId });
            }
          }),
      });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "linkToUser links an unlinked account, and refuses one another user holds with AuthError",
    ]);
  });

  it("a SessionStore whose update is a bare set fails the update-of-a-deleted-session case", async () => {
    const failed = await failures(Testing.sessionStoreConformance(), () => {
      const sessions = MutableHashMap.empty<string, Types.Session>();
      return Layer.succeed(SessionStore, {
        ...memorySessionStore(sessions),
        update: (session) =>
          Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
      });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "update of a session deleted meanwhile creates nothing",
    ]);
  });

  it("a PhoneOtpStore whose upsert resets the failure budget fails the failure-budget case", async () => {
    const failed = await failures(Testing.phoneOtpStoreConformance(), () => {
      const failures = MutableHashMap.empty<string, Types.OtpFailures>();
      const inner = Testing.memoryPhoneOtpStore(MutableHashMap.empty(), failures);
      // The naive shape: the count lives with the code, so a resend clears it.
      return Layer.succeed(PhoneOtpStore, {
        ...inner,
        upsert: (record) =>
          Effect.andThen(
            Effect.sync(() => MutableHashMap.clear(failures)),
            inner.upsert(record),
          ),
      });
    });
    expect(failed.map((failure) => failure.name)).toEqual([
      "the failure budget survives upsert, incrementAttempts and delete of the pair's record",
    ]);
  });

  it("a OneTimeTokenStore whose consume is a get then a delete fails the race case", async () => {
    const failed = await failures(Testing.oneTimeTokenStoreConformance(), () =>
      Layer.succeed(OneTimeTokenStore, oneTimeTokenStore(true)),
    );
    expect(failed.map((failure) => failure.name)).toEqual([
      "concurrent consumes of one one-time token hand it to exactly one caller",
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
