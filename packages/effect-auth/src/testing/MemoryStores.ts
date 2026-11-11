/**
 * In-memory reference stores for the contracts a typical service graph needs,
 * so a test or a docs example can build and run `SessionService`,
 * `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService`,
 * `OidcProviderService` and the trusted-device and OTP second-factor gates
 * without a database.
 *
 * Each `memoryXStore` returns a plain implementation of one contract over
 * `MutableHashMap`s that live as long as the value. The three user-writing contracts
 * (`UserStore`, `EmailPasswordStore`, `OAuthUserStore`) and
 * `OAuthAccountStore.hasPassword` share one {@link MemoryUserTable}, so a user
 * created through one is read through the others. {@link layer} provides every
 * store at once over fresh state, along with the core's `KeyValueStore`-backed
 * ephemeral stores (`layerKV`) over an in-memory `KeyValueStore` (provided
 * with its `KeyValueStoreKeys` listing, so `purgeExpiredKV` runs against it),
 * and `memoryIdentifierStore`.
 *
 * Every operation is synchronous, so the read-then-write steps are atomic
 * within one process. These are references for tests, examples and
 * single-process demos: nothing persists.
 *
 * @module testing
 */
import { DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import type { KeyValueStore } from "effect/persistence";
import { memoryIdentifierStore, IdentifierStore } from "../Identifier.ts";
import { JwtKeyStore, type JwtKeyPair } from "../Jwt.ts";
import { type KeyValueStoreKeys, layerKV, layerMemoryKeyValueStore } from "../KeyValueStores.ts";
import { type CreateUserInput, EmailPasswordStore } from "../email/EmailPassword.ts";
import * as Errors from "../Errors.ts";
import { MultiFactorStore, type MultiFactorRecord } from "../multifactor/MultiFactor.ts";
import {
  OtpSecondFactorStore,
  type OtpSecondFactorRecord,
} from "../multifactor/OtpSecondFactor.ts";
import {
  type OAuthAccount,
  OAuthAccountStore,
  type OAuthCreateUserInput,
  OAuthUserStore,
} from "../oauth/OAuth.ts";
import {
  type OidcAuthorizationCode,
  type OidcClient,
  OidcClientStore,
  OidcCodeStore,
  type OidcConsent,
  OidcConsentStore,
  type OidcToken,
  OidcTokenStore,
} from "../OidcProvider.ts";
import { SessionStore } from "../SessionStore.ts";
import { TrustedDeviceStore, type TrustedDeviceRecord } from "../TrustedDevice.ts";
import type * as Types from "../Types.ts";
import { type CreateUserResult, UserStore } from "../UserStore.ts";

/** Removes every entry whose value matches `predicate`. */
const removeWhere = <V>(
  map: MutableHashMap.MutableHashMap<string, V>,
  predicate: (value: V) => boolean,
): void =>
  Arr.forEach(
    Arr.filter(Arr.fromIterable(map), ([, value]) => predicate(value)),
    ([key]) => void MutableHashMap.remove(map, key),
  );

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/**
 * The user rows the user-writing stores share: the records, and each user's
 * password hash.
 *
 * @since 0.1.0
 * @category models
 */
export interface MemoryUserTable {
  readonly users: MutableHashMap.MutableHashMap<string, Types.User>;
  readonly passwordHashes: MutableHashMap.MutableHashMap<string, string>;
}

/**
 * An empty {@link MemoryUserTable}. Pre-seed `users` to start with accounts.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryUserTable = (): MemoryUserTable => ({
  users: MutableHashMap.empty(),
  passwordHashes: MutableHashMap.empty(),
});

const insertUser = (
  table: MemoryUserTable,
  input: CreateUserInput | OAuthCreateUserInput,
  now: Date,
): CreateUserResult => {
  const user: Types.User = {
    id: globalThis.crypto.randomUUID(),
    ...(input.name === undefined ? {} : { name: input.name }),
    ...(input.image === undefined ? {} : { image: input.image }),
    createdAt: now,
    updatedAt: now,
    attributes: "attributes" in input && input.attributes !== undefined ? input.attributes : {},
  };
  MutableHashMap.set(table.users, user.id, user);
  return { user, created: true };
};

/**
 * `UserStore` over a {@link MemoryUserTable}.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryUserStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof UserStore.Service => ({
  get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(table.users, userId))),
});

/**
 * `EmailPasswordStore` over a {@link MemoryUserTable}: `createUser` always
 * inserts a new user with a random UUID id. The address itself lives in the
 * `IdentifierStore`, as with any store that has an identifiers table.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryEmailPasswordStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof EmailPasswordStore.Service => ({
  createUser: (input) => Effect.map(DateTime.nowAsDate, (now) => insertUser(table, input, now)),
  getPasswordHash: (userId) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(table.passwordHashes, userId))),
  setPasswordHash: (userId, hash) =>
    Effect.sync(() => void MutableHashMap.set(table.passwordHashes, userId, hash)),
  clearPasswordHash: (userId) =>
    Effect.sync(() => void MutableHashMap.remove(table.passwordHashes, userId)),
});

/**
 * `OAuthUserStore` over a {@link MemoryUserTable}, with `updateUser`.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOAuthUserStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof OAuthUserStore.Service => ({
  getUser: (userId) =>
    Effect.suspend(() => {
      const user = Option.getOrUndefined(MutableHashMap.get(table.users, userId));
      return user === undefined
        ? Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId }))
        : Effect.succeed(user);
    }),
  createUser: (input) => Effect.map(DateTime.nowAsDate, (now) => insertUser(table, input, now)),
  updateUser: (userId, update) =>
    Effect.flatMap(DateTime.nowAsDate, (now) => {
      const user = Option.getOrUndefined(MutableHashMap.get(table.users, userId));
      if (user === undefined) {
        return Effect.fail(new Errors.AuthError({ message: "User not found" }));
      }
      const updated: Types.User = {
        ...user,
        ...(update.name === undefined ? {} : { name: update.name }),
        ...(update.image === undefined ? {} : { image: update.image }),
        updatedAt: now,
      };
      MutableHashMap.set(table.users, userId, updated);
      return Effect.succeed(updated);
    }),
});

// ---------------------------------------------------------------------------
// Sessions and second factors
// ---------------------------------------------------------------------------

/**
 * `SessionStore` over a `MutableHashMap` keyed by the session's token hash.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memorySessionStore = (
  sessions: MutableHashMap.MutableHashMap<string, Types.Session> = MutableHashMap.empty(),
): typeof SessionStore.Service => ({
  create: (session) =>
    Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
  get: (sessionId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(sessions, sessionId))),
  update: (session) =>
    Effect.sync(() => (MutableHashMap.set(sessions, session.id, session), session)),
  delete: (sessionId) => Effect.sync(() => void MutableHashMap.remove(sessions, sessionId)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(sessions, (session) => session.userId === userId);
    }),
  listByUserId: (userId) =>
    Effect.sync(() =>
      Arr.fromIterable(MutableHashMap.values(sessions)).filter(
        (session) => session.userId === userId,
      ),
    ),
});

/**
 * `MultiFactorStore` over a `MutableHashMap` keyed by user id.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryMultiFactorStore = (
  records: MutableHashMap.MutableHashMap<string, MultiFactorRecord> = MutableHashMap.empty(),
): typeof MultiFactorStore.Service => ({
  get: (userId) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, userId))),
  upsert: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.userId, record), record)),
  delete: (userId) => Effect.sync(() => void MutableHashMap.remove(records, userId)),
});

/**
 * `TrustedDeviceStore` over a `MutableHashMap` keyed by the device token's hash.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryTrustedDeviceStore = (
  records: MutableHashMap.MutableHashMap<string, TrustedDeviceRecord> = MutableHashMap.empty(),
): typeof TrustedDeviceStore.Service => ({
  upsert: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.tokenHash, record), record)),
  getByTokenHash: (tokenHash) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, tokenHash))),
  delete: (tokenHash) => Effect.sync(() => void MutableHashMap.remove(records, tokenHash)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(records, (record) => record.userId === userId);
    }),
});

/**
 * `OtpSecondFactorStore` over a `MutableHashMap` keyed by the pending token.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOtpSecondFactorStore = (
  records: MutableHashMap.MutableHashMap<string, OtpSecondFactorRecord> = MutableHashMap.empty(),
): typeof OtpSecondFactorStore.Service => ({
  create: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.pendingToken, record), record)),
  get: (pendingToken) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(records, pendingToken))),
  update: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.pendingToken, record), record)),
  delete: (pendingToken) => Effect.sync(() => void MutableHashMap.remove(records, pendingToken)),
});

/**
 * `JwtKeyStore` over an array: the most recently created key is active, and
 * every key stays listed for verification.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryJwtKeyStore = (keys: Array<JwtKeyPair> = []): typeof JwtKeyStore.Service => ({
  getActive: () => Effect.sync(() => keys.at(-1) ?? null),
  create: (pair) => Effect.sync(() => (keys.push(pair), pair)),
  list: () => Effect.sync(() => [...keys]),
});

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

const accountKey = (provider: string, providerId: string) => `${provider}\u0000${providerId}`;

/**
 * `OAuthAccountStore` over a `MutableHashMap` keyed by `(provider, providerId)`.
 * `hasPassword` reads the {@link MemoryUserTable}'s password hashes, so the
 * last-credential unlink guard is on.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOAuthAccountStore = (
  table: MemoryUserTable = memoryUserTable(),
  accounts: MutableHashMap.MutableHashMap<string, OAuthAccount> = MutableHashMap.empty(),
): typeof OAuthAccountStore.Service => {
  const put = (account: OAuthAccount) =>
    void MutableHashMap.set(accounts, accountKey(account.provider, account.providerId), account);
  return {
    create: (account) => Effect.sync(() => (put(account), account)),
    get: (provider, providerId) =>
      Effect.sync(() =>
        Option.getOrNull(MutableHashMap.get(accounts, accountKey(provider, providerId))),
      ),
    getByUserId: (userId) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(accounts)).filter(
          (account) => account.userId === userId,
        ),
      ),
    update: (account) => Effect.sync(() => (put(account), account)),
    linkToUser: (userId, account) => Effect.sync(() => put({ ...account, userId })),
    unlinkFromUser: (userId, provider) =>
      Effect.sync(() => {
        removeWhere(
          accounts,
          (account) => account.userId === userId && account.provider === provider,
        );
      }),
    delete: (provider, providerId) =>
      Effect.sync(() => void MutableHashMap.remove(accounts, accountKey(provider, providerId))),
    hasPassword: (userId) => Effect.sync(() => MutableHashMap.has(table.passwordHashes, userId)),
  };
};

// ---------------------------------------------------------------------------
// OIDC provider
// ---------------------------------------------------------------------------

/**
 * `OidcClientStore` over a `MutableHashMap` keyed by client id.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOidcClientStore = (
  clients: MutableHashMap.MutableHashMap<string, OidcClient> = MutableHashMap.empty(),
): typeof OidcClientStore.Service => ({
  create: (client) =>
    Effect.sync(() => (MutableHashMap.set(clients, client.clientId, client), client)),
  getByClientId: (clientId) =>
    Effect.sync(() => Option.getOrNull(MutableHashMap.get(clients, clientId))),
  update: (client) =>
    Effect.sync(() => (MutableHashMap.set(clients, client.clientId, client), client)),
  delete: (clientId) => Effect.sync(() => void MutableHashMap.remove(clients, clientId)),
  list: () => Effect.sync(() => Arr.fromIterable(MutableHashMap.values(clients))),
});

/**
 * `OidcCodeStore` over a `MutableHashMap` keyed by the code's hash.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOidcCodeStore = (
  codes: MutableHashMap.MutableHashMap<string, OidcAuthorizationCode> = MutableHashMap.empty(),
): typeof OidcCodeStore.Service => ({
  create: (code) => Effect.sync(() => (MutableHashMap.set(codes, code.codeHash, code), code)),
  get: (codeHash) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(codes, codeHash))),
  delete: (codeHash) => Effect.sync(() => void MutableHashMap.remove(codes, codeHash)),
});

/**
 * `OidcTokenStore` over a `MutableHashMap` keyed by the token's hash, with
 * `listByFamily` (refresh-token reuse detection on).
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOidcTokenStore = (
  tokens: MutableHashMap.MutableHashMap<string, OidcToken> = MutableHashMap.empty(),
): typeof OidcTokenStore.Service => ({
  create: (token) => Effect.sync(() => (MutableHashMap.set(tokens, token.tokenHash, token), token)),
  get: (tokenHash) => Effect.sync(() => Option.getOrNull(MutableHashMap.get(tokens, tokenHash))),
  delete: (tokenHash) => Effect.sync(() => void MutableHashMap.remove(tokens, tokenHash)),
  listByFamily: (familyId) =>
    Effect.sync(() =>
      Arr.fromIterable(MutableHashMap.values(tokens)).filter(
        (token) => token.familyId === familyId,
      ),
    ),
});

/**
 * `OidcConsentStore` over a `MutableHashMap` keyed by `(userId, clientId)`.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOidcConsentStore = (
  consents: MutableHashMap.MutableHashMap<string, OidcConsent> = MutableHashMap.empty(),
): typeof OidcConsentStore.Service => {
  const key = (userId: string, clientId: string) => `${userId}\u0000${clientId}`;
  return {
    get: (userId, clientId) =>
      Effect.sync(() => Option.getOrNull(MutableHashMap.get(consents, key(userId, clientId)))),
    upsert: (consent) =>
      Effect.sync(
        () => (
          MutableHashMap.set(consents, key(consent.userId, consent.clientId), consent),
          consent
        ),
      ),
    delete: (userId, clientId) =>
      Effect.sync(() => void MutableHashMap.remove(consents, key(userId, clientId))),
  };
};

// ---------------------------------------------------------------------------
// Everything at once
// ---------------------------------------------------------------------------

/**
 * The stores {@link layer} provides.
 *
 * @since 0.1.0
 * @category models
 */
export type MemoryStores =
  | UserStore
  | EmailPasswordStore
  | OAuthUserStore
  | OAuthAccountStore
  | SessionStore
  | IdentifierStore
  | MultiFactorStore
  | TrustedDeviceStore
  | OtpSecondFactorStore
  | JwtKeyStore
  | OidcClientStore
  | OidcCodeStore
  | OidcTokenStore
  | OidcConsentStore
  | Layer.Success<typeof layerKV>
  | KeyValueStore.KeyValueStore
  | KeyValueStoreKeys;

/**
 * Every in-memory store over fresh, shared state: the user-writing stores
 * share one {@link MemoryUserTable}, identifiers come from
 * `memoryIdentifierStore`, and the ephemeral token stores (`layerKV`: OAuth
 * state, WebAuthn challenges, rate limits, verification, reset and magic-link
 * tokens, email OTPs, pending multi-factor challenges) run over an in-memory
 * `KeyValueStore`, which the layer also provides with its `KeyValueStoreKeys`
 * listing, so `purgeExpiredKV` runs against it. Each build of the layer starts
 * empty.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const program = Effect.gen(function* () {
 *   const sessions = yield* Auth.SessionStore
 *   const users = yield* Auth.UserStore
 *   assert.equal(yield* users.get("nobody"), null)
 *   assert.deepEqual(yield* sessions.listByUserId("nobody"), [])
 * })
 *
 * await Effect.runPromise(program.pipe(Effect.provide(Testing.memoryStores)))
 * ```
 *
 * @since 0.1.0
 * @category layers
 */
export const layer: Layer.Layer<MemoryStores> = Layer.unwrap(
  Effect.sync(() => {
    const table = memoryUserTable();
    return Layer.mergeAll(
      Layer.succeed(UserStore, memoryUserStore(table)),
      Layer.succeed(EmailPasswordStore, memoryEmailPasswordStore(table)),
      Layer.succeed(OAuthUserStore, memoryOAuthUserStore(table)),
      Layer.succeed(OAuthAccountStore, memoryOAuthAccountStore(table)),
      Layer.succeed(SessionStore, memorySessionStore()),
      Layer.succeed(IdentifierStore, memoryIdentifierStore()),
      Layer.succeed(MultiFactorStore, memoryMultiFactorStore()),
      Layer.succeed(TrustedDeviceStore, memoryTrustedDeviceStore()),
      Layer.succeed(OtpSecondFactorStore, memoryOtpSecondFactorStore()),
      Layer.succeed(JwtKeyStore, memoryJwtKeyStore()),
      Layer.succeed(OidcClientStore, memoryOidcClientStore()),
      Layer.succeed(OidcCodeStore, memoryOidcCodeStore()),
      Layer.succeed(OidcTokenStore, memoryOidcTokenStore()),
      Layer.succeed(OidcConsentStore, memoryOidcConsentStore()),
      Layer.provideMerge(layerKV, layerMemoryKeyValueStore),
    );
  }),
);
