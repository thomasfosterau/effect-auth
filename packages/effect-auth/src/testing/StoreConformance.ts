/**
 * Store-contract conformance suites: the semantics the core's store contracts
 * state, as executable cases an application runs against the store it brings
 * (`docs/guides/byo-stores.md`).
 *
 * ### How assertions surface
 *
 * This module imports no test runner. A suite is plain data: a contract name
 * and a list of cases, each an `Effect` that succeeds when the store behaves,
 * and fails with {@link ConformanceError} (naming the contract, the case and
 * what was wrong) when it does not. A store failing unexpectedly fails the
 * case with its own `AuthError`. Register the cases with whatever runner the
 * app uses:
 *
 * ```ts
 * import { Effect, Layer } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * // The store under test: here, a map.
 * const sessions = new Map<string, Auth.Session>()
 * const store: typeof Auth.SessionStore.Service = {
 *   create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *   get: (id) => Effect.sync(() => sessions.get(id) ?? null),
 *   update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
 *   delete: (id) => Effect.sync(() => void sessions.delete(id)),
 *   deleteByUserId: (userId) =>
 *     Effect.sync(() => {
 *       for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id)
 *     }),
 *   listByUserId: (userId) =>
 *     Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
 * }
 *
 * const suite = Testing.sessionStoreConformance()
 * for (const testCase of suite.cases) {
 *   // In a test file, one test per case: it(testCase.name, () => Effect.runPromise(...)).
 *   await Effect.runPromise(testCase.run.pipe(Effect.provide(Layer.succeed(Auth.SessionStore, store))))
 * }
 * ```
 *
 * ### Isolation
 *
 * Every case mints its own ids and values (random UUIDs), so cases may share
 * one database and run in any order; nothing needs truncating between them.
 *
 * ### Stores whose tables reference users
 *
 * A store whose rows carry a foreign key to the app's users table needs the
 * user to exist first. Pass `seedUser`, which the suite calls for every user
 * id a case uses before the store sees it. `userStoreConformance` requires it,
 * since `UserStore` only reads.
 *
 * @module testing
 */
import { Array as Arr, Data, Effect, Exit, Option, Order, Predicate, Schema } from "effect";
import * as ApiKey from "../ApiKey.ts";
import type * as Errors from "../Errors.ts";
import * as Identifier from "../Identifier.ts";
import { SessionStore } from "../SessionStore.ts";
import type * as Types from "../Types.ts";
import { UserStore } from "../UserStore.ts";

/**
 * A store did not behave as its contract states.
 *
 * @since 1.0.0
 * @category errors
 */
export class ConformanceError extends Data.TaggedError("ConformanceError")<{
  readonly message: string;
  /** The contract, as `ConformanceSuite.contract` names it. */
  readonly contract: string;
  /** The case, as `ConformanceCase.name` names it. */
  readonly case: string;
}> {}

/**
 * One executable case of a suite.
 *
 * @since 1.0.0
 * @category models
 */
export interface ConformanceCase<E, R> {
  readonly name: string;
  readonly run: Effect.Effect<void, ConformanceError | Errors.AuthError | E, R>;
}

/**
 * A contract's cases.
 *
 * @since 1.0.0
 * @category models
 */
export interface ConformanceSuite<E, R> {
  /** The contract's name, e.g. `"SessionStore"`. */
  readonly contract: string;
  readonly cases: ReadonlyArray<ConformanceCase<E, R>>;
}

/**
 * Options every suite takes.
 *
 * @since 1.0.0
 * @category models
 */
export interface ConformanceOptions<E = never, R = never> {
  /**
   * Write a user row before a case uses its id, for a store whose tables
   * reference the app's users. Omit it when nothing does.
   */
  readonly seedUser?: ((user: Types.User) => Effect.Effect<void, E, R>) | undefined;
}

// ---------------------------------------------------------------------------
// Assertion plumbing
// ---------------------------------------------------------------------------

class Mismatch extends Data.TaggedError("Mismatch")<{ readonly message: string }> {}

/**
 * A value with `Date`s as their instants, undefined properties dropped and
 * keys sorted, so two records compare by content alone.
 */
const canonical = (value: unknown): unknown => {
  if (value instanceof Date) return { $date: value.getTime() };
  if (Array.isArray(value)) return value.map(canonical);
  if (Predicate.isObjectOrArray(value)) {
    return Object.fromEntries(
      Arr.sort(
        Object.entries(value).filter(([, field]) => field !== undefined),
        Order.mapInput(Order.String, ([key]: readonly [string, unknown]) => key),
      ).map(([key, field]) => [key, canonical(field)]),
    );
  }
  return value;
};

const encodeJson = Schema.encodeUnknownOption(Schema.fromJsonString(Schema.Unknown));

const show = (value: unknown): string =>
  Option.getOrElse(encodeJson(canonical(value)), () => String(value));

const expectEqual = (
  what: string,
  actual: unknown,
  expected: unknown,
): Effect.Effect<void, Mismatch> =>
  show(actual) === show(expected)
    ? Effect.void
    : Effect.fail(
        new Mismatch({ message: `${what}: expected ${show(expected)}, got ${show(actual)}` }),
      );

const expectThat = (what: string, holds: boolean): Effect.Effect<void, Mismatch> =>
  holds ? Effect.void : Effect.fail(new Mismatch({ message: what }));

/** Run `effect` and require it to fail with the tag `tag`. */
const expectFailure = <A, E, R>(
  what: string,
  effect: Effect.Effect<A, E, R>,
  tag: string,
): Effect.Effect<void, Mismatch, R> =>
  Effect.flatMap(Effect.exit(effect), (exit) => {
    if (Exit.isSuccess(exit)) {
      return Effect.fail(
        new Mismatch({ message: `${what}: expected ${tag}, succeeded with ${show(exit.value)}` }),
      );
    }
    const error = Exit.findErrorOption(exit);
    const actual =
      Option.isSome(error) &&
      Predicate.isObjectOrArray(error.value) &&
      Predicate.hasProperty(error.value, "_tag")
        ? String(error.value._tag)
        : "a defect";
    return expectThat(`${what}: expected ${tag}, failed with ${actual}`, actual === tag);
  });

const uuid = (): string => globalThis.crypto.randomUUID();

/** A random 64-hex-digit string: the shape of the SHA-256 digests stores index. */
const digest = (): string => `${uuid()}${uuid()}`.replaceAll("-", "");

/** A millisecond-precision instant, `offset` ms from a fixed base. */
const at = (offset = 0): Date => new Date(Date.UTC(2026, 0, 1) + offset);

const makeUser = (id: string): Types.User => ({
  id,
  name: "Conformance User",
  createdAt: at(),
  updatedAt: at(),
  attributes: { conformance: true },
});

const suite = <E, R, S>(
  contract: string,
  options: ConformanceOptions<E, R> | undefined,
  cases: ReadonlyArray<{
    readonly name: string;
    readonly run: (
      newUser: () => Effect.Effect<string, E, R>,
    ) => Effect.Effect<void, Mismatch | Errors.AuthError | E, R | S>;
  }>,
): ConformanceSuite<E, R | S> => {
  const newUser = (): Effect.Effect<string, E, R> => {
    const id = uuid();
    const seed = options?.seedUser;
    return seed === undefined ? Effect.succeed(id) : Effect.as(seed(makeUser(id)), id);
  };
  return {
    contract,
    cases: cases.map(({ name, run }) => ({
      name,
      run: Effect.mapError(run(newUser), (error) =>
        error instanceof Mismatch
          ? new ConformanceError({
              message: `${contract}: ${name}: ${error.message}`,
              contract,
              case: name,
            })
          : error,
      ),
    })),
  };
};

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

const makeSession = (userId: string, offset = 0): Types.Session => ({
  id: digest(),
  userId,
  expiresAt: at(offset + 24 * 60 * 60 * 1000),
  createdAt: at(offset),
  lastActivityAt: at(offset),
  attributes: { device: "laptop", nested: { trusted: true, scopes: ["a", "b"] } },
});

const sessionIds = (sessions: ReadonlyArray<Types.Session>): ReadonlyArray<string> =>
  Arr.sort(
    sessions.map((session) => session.id),
    Order.String,
  );

/**
 * The `SessionStore` contract: sessions round-trip with their `Date`s and
 * attributes, a miss is `null`, deletes of unknown ids are no-ops, and the
 * per-user operations touch that user's sessions only.
 *
 * @since 1.0.0
 * @category suites
 */
export const sessionStoreConformance = <E = never, R = never>(
  options?: ConformanceOptions<E, R>,
): ConformanceSuite<E, R | SessionStore> =>
  suite<E, R, SessionStore>("SessionStore", options, [
    {
      name: "create returns the session, and get reads it back with its dates and attributes",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          const session = makeSession(yield* newUser());
          const created = yield* store.create(session);
          yield* expectEqual("create", created, session);
          yield* expectEqual("get", yield* store.get(session.id), session);
        }),
    },
    {
      name: "get of an unknown id is null",
      run: () =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          yield* expectEqual("get", yield* store.get(digest()), null);
        }),
    },
    {
      name: "update writes expiresAt, lastActivityAt and attributes",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          const session = makeSession(yield* newUser());
          yield* store.create(session);
          const changed: Types.Session = {
            ...session,
            expiresAt: at(48 * 60 * 60 * 1000),
            lastActivityAt: at(60 * 1000),
            attributes: { device: "phone" },
          };
          yield* expectEqual("update", yield* store.update(changed), changed);
          yield* expectEqual("get after update", yield* store.get(session.id), changed);
        }),
    },
    {
      name: "delete removes one session, and is a no-op for an unknown id",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          const userId = yield* newUser();
          const gone = makeSession(userId);
          const kept = makeSession(userId, 1);
          yield* store.create(gone);
          yield* store.create(kept);
          yield* store.delete(gone.id);
          yield* store.delete(digest());
          yield* expectEqual("get of the deleted session", yield* store.get(gone.id), null);
          yield* expectEqual("get of the other session", yield* store.get(kept.id), kept);
        }),
    },
    {
      name: "listByUserId lists that user's sessions only, and [] for a user with none",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          const first = makeSession(userId);
          const second = makeSession(userId, 1);
          yield* store.create(first);
          yield* store.create(second);
          yield* store.create(makeSession(otherId));
          yield* expectEqual(
            "listByUserId",
            sessionIds(yield* store.listByUserId(userId)),
            sessionIds([first, second]),
          );
          yield* expectEqual(
            "listByUserId of a user with none",
            yield* store.listByUserId(uuid()),
            [],
          );
        }),
    },
    {
      name: "deleteByUserId removes that user's sessions only, and is a no-op for a user with none",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* SessionStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          yield* store.create(makeSession(userId));
          yield* store.create(makeSession(userId, 1));
          const other = makeSession(otherId);
          yield* store.create(other);
          yield* store.deleteByUserId(userId);
          yield* store.deleteByUserId(uuid());
          yield* expectEqual(
            "listByUserId after deleteByUserId",
            yield* store.listByUserId(userId),
            [],
          );
          yield* expectEqual("the other user's session", yield* store.get(other.id), other);
        }),
    },
  ]);

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

/**
 * Options for {@link userStoreConformance}: `UserStore` only reads, so the
 * suite writes its users through `seedUser`.
 *
 * @since 1.0.0
 * @category models
 */
export interface UserStoreConformanceOptions<E = never, R = never> {
  /** Write `user` as the app's own user writer would. */
  readonly seedUser: (user: Types.User) => Effect.Effect<void, E, R>;
}

/**
 * The `UserStore` contract: a seeded user reads back with its fields,
 * `Date`s and attributes, and a miss is `null`.
 *
 * @since 1.0.0
 * @category suites
 */
export const userStoreConformance = <E = never, R = never>(
  options: UserStoreConformanceOptions<E, R>,
): ConformanceSuite<E, R | UserStore> =>
  suite<E, R, UserStore>("UserStore", undefined, [
    {
      name: "get reads a user back with its name, image, dates and attributes",
      run: () =>
        Effect.gen(function* () {
          const store = yield* UserStore;
          const user: Types.User = {
            id: uuid(),
            name: "Ada",
            image: "https://example.test/ada.png",
            createdAt: at(),
            updatedAt: at(1000),
            attributes: { role: "admin", nested: { flags: ["a"] } },
          };
          yield* options.seedUser(user);
          yield* expectEqual("get", yield* store.get(user.id), user);
        }),
    },
    {
      name: "get reads a user with no name or image back without them",
      run: () =>
        Effect.gen(function* () {
          const store = yield* UserStore;
          const user: Types.User = { id: uuid(), createdAt: at(), updatedAt: at(), attributes: {} };
          yield* options.seedUser(user);
          yield* expectEqual("get", yield* store.get(user.id), user);
        }),
    },
    {
      name: "get of an unknown id is null",
      run: () =>
        Effect.gen(function* () {
          const store = yield* UserStore;
          yield* expectEqual("get", yield* store.get(uuid()), null);
        }),
    },
  ]);

// ---------------------------------------------------------------------------
// IdentifierStore
// ---------------------------------------------------------------------------

const email = (userId: string, verified = false): Identifier.Identifier =>
  Identifier.makeIdentifier({
    userId,
    type: "email",
    value: `${uuid()}@example.test`,
    verified,
    now: at(),
  });

/**
 * What every identifier store reports faithfully, whatever else it derives. The
 * `id` is not among them: a store that keeps the identifier on the user's own
 * row reports the user's id, so every case works from the record as the store
 * reports it (what `create` returns), never from the one it handed in.
 */
const identity = (identifier: Identifier.Identifier | null | undefined) =>
  identifier === null || identifier === undefined
    ? null
    : {
        userId: identifier.userId,
        type: identifier.type,
        value: identifier.value,
        verified: identifier.verified,
      };

const values = (identifiers: ReadonlyArray<Identifier.Identifier>) =>
  identifiers.map((identifier) => [identifier.value, identifier.verified]);

/**
 * The `IdentifierStore` contract, over email identifiers so a store that keeps
 * one email on the user's own row qualifies as well as one with an
 * identifiers table: lookups and misses, `(type, value)` uniqueness (which
 * `claimIdentifier` relies on), listing, verification, deletes, and every
 * rule of `replace`.
 *
 * @since 1.0.0
 * @category suites
 */
export const identifierStoreConformance = <E = never, R = never>(
  options?: ConformanceOptions<E, R>,
): ConformanceSuite<E, R | Identifier.IdentifierStore> =>
  suite<E, R, Identifier.IdentifierStore>("IdentifierStore", options, [
    {
      name: "getByValue resolves an identifier by (type, value), and misses with null",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const claim = email(yield* newUser());
          const created = yield* store.create(claim);
          yield* expectEqual("create", identity(created), identity(claim));
          const found = yield* store.getByValue("email", claim.value);
          yield* expectEqual("getByValue", identity(found), identity(claim));
          yield* expectEqual("getByValue's id", found?.id, created.id);
          yield* expectEqual(
            "getByValue of an unclaimed value",
            yield* store.getByValue("email", `${uuid()}@example.test`),
            null,
          );
          yield* expectEqual(
            "getByValue under another type",
            yield* store.getByValue("phone", claim.value),
            null,
          );
        }),
    },
    {
      name: "create refuses a claimed (type, value) with AuthError, which claimIdentifier reports as taken",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const owner = yield* newUser();
          const rival = yield* newUser();
          const claim = email(owner);
          yield* store.create(claim);
          const duplicate = { ...email(rival), value: claim.value };
          yield* expectFailure("create of a claimed value", store.create(duplicate), "AuthError");
          yield* expectFailure(
            "claimIdentifier of a claimed value",
            Identifier.claimIdentifier(store, { ...email(rival), value: claim.value }),
            "IdentifierTakenError",
          );
          yield* expectEqual(
            "the claimed value's holder",
            (yield* store.getByValue("email", claim.value))?.userId,
            owner,
          );
        }),
    },
    {
      name: "listByUser lists a user's identifiers, and [] for a user with none",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const claim = email(userId);
          yield* store.create(claim);
          yield* expectEqual("listByUser", (yield* store.listByUser(userId)).map(identity), [
            identity(claim),
          ]);
          yield* expectEqual(
            "listByUser of a seeded user with none",
            yield* store.listByUser(yield* newUser()),
            [],
          );
          yield* expectEqual("listByUser of an unknown user", yield* store.listByUser(uuid()), []);
        }),
    },
    {
      name: "setVerified marks the identifier verified, and is null for an unknown id",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const claim = email(yield* newUser());
          const created = yield* store.create(claim);
          const verified = yield* store.setVerified(created.id, at(1000));
          yield* expectEqual("setVerified", verified?.verified, true);
          yield* expectEqual(
            "getByValue after setVerified",
            (yield* store.getByValue("email", claim.value))?.verified,
            true,
          );
          yield* expectEqual(
            "setVerified of an unknown id",
            yield* store.setVerified(uuid(), at()),
            null,
          );
        }),
    },
    {
      name: "delete removes one identifier, and is a no-op for an unknown id",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          const gone = email(userId);
          const kept = email(otherId);
          const created = yield* store.create(gone);
          yield* store.create(kept);
          yield* store.delete(created.id);
          yield* store.delete(uuid());
          yield* expectEqual(
            "getByValue of the deleted identifier",
            yield* store.getByValue("email", gone.value),
            null,
          );
          yield* expectEqual("listByUser after delete", yield* store.listByUser(userId), []);
          yield* expectEqual(
            "the other user's identifier",
            identity(yield* store.getByValue("email", kept.value)),
            identity(kept),
          );
        }),
    },
    {
      name: "deleteByUser removes that user's identifiers only, and is a no-op for a user with none",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          yield* store.create(email(userId));
          const kept = email(otherId);
          yield* store.create(kept);
          yield* store.deleteByUser(userId);
          yield* store.deleteByUser(uuid());
          yield* expectEqual("listByUser after deleteByUser", yield* store.listByUser(userId), []);
          yield* expectEqual(
            "the other user's identifiers",
            (yield* store.listByUser(otherId)).map(identity),
            [identity(kept)],
          );
        }),
    },
    {
      name: "replace swaps the identifier, and the old value is free to claim again",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          const from = yield* store.create(email(userId));
          const to = email(userId, true);
          const replaced = yield* store.replace(from, to);
          yield* expectEqual(
            "replace",
            [replaced?.userId, replaced?.value, replaced?.verified],
            [userId, to.value, true],
          );
          yield* expectEqual("listByUser after replace", values(yield* store.listByUser(userId)), [
            [to.value, true],
          ]);
          yield* expectEqual(
            "getByValue of the old value",
            yield* store.getByValue("email", from.value),
            null,
          );
          yield* expectEqual(
            "getByValue of the new value",
            (yield* store.getByValue("email", to.value))?.userId,
            userId,
          );
          const reclaimed = yield* Identifier.claimIdentifier(store, {
            ...email(otherId),
            value: from.value,
          }).pipe(
            Effect.catchTag("IdentifierTakenError", () =>
              Effect.fail(
                new Mismatch({ message: "claim of the released value: still taken after replace" }),
              ),
            ),
          );
          yield* expectEqual("claim of the released value", reclaimed.userId, otherId);
        }),
    },
    {
      name: "replace refuses a value another user holds with AuthError, which replaceIdentifier reports as taken, and keeps the old one",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          const from = yield* store.create(email(userId, true));
          const held = email(otherId);
          yield* store.create(held);
          yield* expectFailure(
            "replace with a held value",
            store.replace(from, { ...email(userId), value: held.value }),
            "AuthError",
          );
          yield* expectFailure(
            "replaceIdentifier with a held value",
            Identifier.replaceIdentifier(store, from, { ...email(userId), value: held.value }),
            "IdentifierTakenError",
          );
          yield* expectEqual(
            "listByUser after the refusal",
            values(yield* store.listByUser(userId)),
            [[from.value, true]],
          );
          yield* expectEqual(
            "the held value's holder",
            (yield* store.getByValue("email", held.value))?.userId,
            otherId,
          );
        }),
    },
    {
      name: "replace of an identifier the user no longer holds is null and writes nothing",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const current = yield* store.create(email(userId));
          const stale: Identifier.Identifier = { ...current, value: `${uuid()}@example.test` };
          const to = email(userId);
          yield* expectEqual(
            "replace of a stale identifier",
            yield* store.replace(stale, to),
            null,
          );
          yield* expectFailure(
            "replaceIdentifier of a stale identifier",
            Identifier.replaceIdentifier(store, stale, email(userId)),
            "IdentifierNotFoundError",
          );
          yield* expectEqual(
            "listByUser after the stale replace",
            values(yield* store.listByUser(userId)),
            [[current.value, false]],
          );
          yield* expectEqual(
            "getByValue of the replacement",
            yield* store.getByValue("email", to.value),
            null,
          );
        }),
    },
    {
      name: "replace refuses a replacement for another user, of another type, with the same id, or of the same value",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* Identifier.IdentifierStore;
          const userId = yield* newUser();
          const otherId = yield* newUser();
          const from = yield* store.create(email(userId));
          const fresh = email(userId);
          yield* expectFailure(
            "replace for another user",
            store.replace(from, email(otherId)),
            "AuthError",
          );
          yield* expectFailure(
            "replace with another type",
            store.replace(
              from,
              Identifier.makeIdentifier({ userId, type: "username", value: uuid() }),
            ),
            "AuthError",
          );
          yield* expectFailure(
            "replace keeping the id",
            store.replace(from, { ...fresh, id: from.id }),
            "AuthError",
          );
          yield* expectFailure(
            "replace with the same value",
            store.replace(from, { ...email(userId, true), value: from.value }),
            "AuthError",
          );
          yield* expectEqual(
            "listByUser after the refusals",
            values(yield* store.listByUser(userId)),
            [[from.value, false]],
          );
          yield* expectEqual("the other user's identifiers", yield* store.listByUser(otherId), []);
          yield* expectEqual(
            "getByValue of the refused value",
            yield* store.getByValue("email", fresh.value),
            null,
          );
        }),
    },
  ]);

// ---------------------------------------------------------------------------
// ApiKeyStore
// ---------------------------------------------------------------------------

const makeApiKey = (userId: string, full = false): ApiKey.ApiKey => ({
  id: uuid(),
  start: "abc123",
  keyHash: digest(),
  userId,
  enabled: true,
  metadata: { purpose: "conformance" },
  createdAt: at().getTime(),
  updatedAt: at().getTime(),
  ...(full
    ? {
        name: "CI deploy key",
        prefix: "app_",
        expiresAt: at(24 * 60 * 60 * 1000).getTime(),
        lastUsedAt: at(1000).getTime(),
        permissions: { projects: ["read", "write"] },
        remaining: 10,
        refillAmount: 5,
        refillInterval: 60_000,
        refillMax: 10,
        lastRefillAt: at().getTime(),
        rateLimit: { maxRequests: 100, windowMs: 60_000 },
      }
    : {}),
});

const keyIds = (keys: ReadonlyArray<ApiKey.ApiKey>): ReadonlyArray<string> =>
  Arr.sort(
    keys.map((key) => key.id),
    Order.String,
  );

/**
 * The `ApiKeyStore` contract: keys round-trip with every optional field, read
 * by id and by hash, misses are `null`, `update` writes, and the per-user list
 * is that user's keys only.
 *
 * @since 1.0.0
 * @category suites
 */
export const apiKeyStoreConformance = <E = never, R = never>(
  options?: ConformanceOptions<E, R>,
): ConformanceSuite<E, R | ApiKey.ApiKeyStore> =>
  suite<E, R, ApiKey.ApiKeyStore>("ApiKeyStore", options, [
    {
      name: "create returns the key, and get and getByHash read it back with every field",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* ApiKey.ApiKeyStore;
          const userId = yield* newUser();
          yield* Effect.forEach(
            [makeApiKey(userId, true), makeApiKey(userId)],
            (key) =>
              Effect.gen(function* () {
                yield* expectEqual("create", yield* store.create(key), key);
                yield* expectEqual("get", yield* store.get(key.id), key);
                yield* expectEqual("getByHash", yield* store.getByHash(key.keyHash), key);
              }),
            { concurrency: 1, discard: true },
          );
        }),
    },
    {
      name: "get and getByHash of an unknown key are null",
      run: () =>
        Effect.gen(function* () {
          const store = yield* ApiKey.ApiKeyStore;
          yield* expectEqual("get", yield* store.get(uuid()), null);
          yield* expectEqual("getByHash", yield* store.getByHash(digest()), null);
        }),
    },
    {
      name: "update writes the key's mutable fields",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* ApiKey.ApiKeyStore;
          const key = makeApiKey(yield* newUser(), true);
          yield* store.create(key);
          const changed: ApiKey.ApiKey = {
            ...key,
            name: "renamed",
            enabled: false,
            lastUsedAt: at(5000).getTime(),
            remaining: 3,
            lastRefillAt: at(5000).getTime(),
            metadata: { purpose: "rotated" },
            updatedAt: at(5000).getTime(),
          };
          yield* expectEqual("update", yield* store.update(changed), changed);
          yield* expectEqual("get after update", yield* store.get(key.id), changed);
        }),
    },
    {
      name: "delete removes the key, and is a no-op for an unknown id",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* ApiKey.ApiKeyStore;
          const userId = yield* newUser();
          const gone = makeApiKey(userId);
          const kept = makeApiKey(userId);
          yield* store.create(gone);
          yield* store.create(kept);
          yield* store.delete(gone.id);
          yield* store.delete(uuid());
          yield* expectEqual("get of the deleted key", yield* store.get(gone.id), null);
          yield* expectEqual(
            "getByHash of the deleted key",
            yield* store.getByHash(gone.keyHash),
            null,
          );
          yield* expectEqual("get of the other key", yield* store.get(kept.id), kept);
        }),
    },
    {
      name: "listByUserId lists that user's keys only, and [] for a user with none",
      run: (newUser) =>
        Effect.gen(function* () {
          const store = yield* ApiKey.ApiKeyStore;
          const userId = yield* newUser();
          const first = makeApiKey(userId);
          const second = makeApiKey(userId, true);
          yield* store.create(first);
          yield* store.create(second);
          yield* store.create(makeApiKey(yield* newUser()));
          yield* expectEqual(
            "listByUserId",
            keyIds(yield* store.listByUserId(userId)),
            keyIds([first, second]),
          );
          yield* expectEqual(
            "listByUserId of a user with none",
            yield* store.listByUserId(uuid()),
            [],
          );
        }),
    },
  ]);
