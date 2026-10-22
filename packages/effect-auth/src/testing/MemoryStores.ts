/**
 * In-memory reference stores for the contracts a typical service graph needs,
 * so a test or a docs example can build and run `SessionService`,
 * `EmailPasswordService`, `MultiFactorService`, `OAuthService`, `JwtService`,
 * `OidcProviderService` and the trusted-device and OTP second-factor gates
 * without a database.
 *
 * Each `memoryXStore` returns a plain implementation of one contract over
 * `Map`s that live as long as the value. The three user-writing contracts
 * (`UserStore`, `EmailPasswordStore`, `OAuthUserStore`) and
 * `OAuthAccountStore.hasPassword` share one {@link MemoryUserTable}, so a user
 * created through one is read through the others. {@link layer} provides every
 * store at once over fresh state, along with the core's `KeyValueStore`-backed
 * ephemeral stores (`layerKV`) over an in-memory `KeyValueStore`, and
 * `memoryIdentifierStore`.
 *
 * Every operation is synchronous, so the read-then-write steps are atomic
 * within one process. These are references for tests, examples and
 * single-process demos: nothing persists.
 *
 * @module testing
 */
import { Effect, Layer } from "effect";
import { KeyValueStore } from "effect/persistence";
import { memoryIdentifierStore, IdentifierStore } from "../Identifier.ts";
import { JwtKeyStore, type JwtKeyPair } from "../Jwt.ts";
import { layerKV } from "../KeyValueStores.ts";
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

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/**
 * The user rows the user-writing stores share: the records, and each user's
 * password hash.
 *
 * @since 1.0.0
 * @category models
 */
export interface MemoryUserTable {
  readonly users: Map<string, Types.User>;
  readonly passwordHashes: Map<string, string>;
}

/**
 * An empty {@link MemoryUserTable}. Pre-seed `users` to start with accounts.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryUserTable = (): MemoryUserTable => ({
  users: new Map(),
  passwordHashes: new Map(),
});

const insertUser = (
  table: MemoryUserTable,
  input: CreateUserInput | OAuthCreateUserInput,
): CreateUserResult => {
  const now = new Date();
  const user: Types.User = {
    id: globalThis.crypto.randomUUID(),
    ...(input.name === undefined ? {} : { name: input.name }),
    ...(input.image === undefined ? {} : { image: input.image }),
    createdAt: now,
    updatedAt: now,
    attributes: "attributes" in input && input.attributes !== undefined ? input.attributes : {},
  };
  table.users.set(user.id, user);
  return { user, created: true };
};

/**
 * `UserStore` over a {@link MemoryUserTable}.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryUserStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof UserStore.Service => ({
  get: (userId) => Effect.sync(() => table.users.get(userId) ?? null),
});

/**
 * `EmailPasswordStore` over a {@link MemoryUserTable}: `createUser` always
 * inserts a new user with a random UUID id. The address itself lives in the
 * `IdentifierStore`, as with any store that has an identifiers table.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryEmailPasswordStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof EmailPasswordStore.Service => ({
  createUser: (input) => Effect.sync(() => insertUser(table, input)),
  getPasswordHash: (userId) => Effect.sync(() => table.passwordHashes.get(userId) ?? null),
  setPasswordHash: (userId, hash) => Effect.sync(() => void table.passwordHashes.set(userId, hash)),
  clearPasswordHash: (userId) => Effect.sync(() => void table.passwordHashes.delete(userId)),
});

/**
 * `OAuthUserStore` over a {@link MemoryUserTable}, with `updateUser`.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOAuthUserStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof OAuthUserStore.Service => ({
  getUser: (userId) =>
    Effect.suspend(() => {
      const user = table.users.get(userId);
      return user === undefined
        ? Effect.fail(new Errors.UserNotFoundError({ message: "User not found", userId }))
        : Effect.succeed(user);
    }),
  createUser: (input) => Effect.sync(() => insertUser(table, input)),
  updateUser: (userId, update) =>
    Effect.suspend(() => {
      const user = table.users.get(userId);
      if (user === undefined) {
        return Effect.fail(new Errors.AuthError({ message: "User not found" }));
      }
      const updated: Types.User = {
        ...user,
        ...(update.name === undefined ? {} : { name: update.name }),
        ...(update.image === undefined ? {} : { image: update.image }),
        updatedAt: new Date(),
      };
      table.users.set(userId, updated);
      return Effect.succeed(updated);
    }),
});

// ---------------------------------------------------------------------------
// Sessions and second factors
// ---------------------------------------------------------------------------

/**
 * `SessionStore` over a `Map` keyed by the session's token hash.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memorySessionStore = (
  sessions: Map<string, Types.Session> = new Map(),
): typeof SessionStore.Service => ({
  create: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  get: (sessionId) => Effect.sync(() => sessions.get(sessionId) ?? null),
  update: (session) => Effect.sync(() => (sessions.set(session.id, session), session)),
  delete: (sessionId) => Effect.sync(() => void sessions.delete(sessionId)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [id, session] of sessions) if (session.userId === userId) sessions.delete(id);
    }),
  listByUserId: (userId) =>
    Effect.sync(() => [...sessions.values()].filter((session) => session.userId === userId)),
});

/**
 * `MultiFactorStore` over a `Map` keyed by user id.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryMultiFactorStore = (
  records: Map<string, MultiFactorRecord> = new Map(),
): typeof MultiFactorStore.Service => ({
  get: (userId) => Effect.sync(() => records.get(userId) ?? null),
  upsert: (record) => Effect.sync(() => (records.set(record.userId, record), record)),
  delete: (userId) => Effect.sync(() => void records.delete(userId)),
});

/**
 * `TrustedDeviceStore` over a `Map` keyed by the device token's hash.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryTrustedDeviceStore = (
  records: Map<string, TrustedDeviceRecord> = new Map(),
): typeof TrustedDeviceStore.Service => ({
  upsert: (record) => Effect.sync(() => (records.set(record.tokenHash, record), record)),
  getByTokenHash: (tokenHash) => Effect.sync(() => records.get(tokenHash) ?? null),
  delete: (tokenHash) => Effect.sync(() => void records.delete(tokenHash)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      for (const [hash, record] of records) if (record.userId === userId) records.delete(hash);
    }),
});

/**
 * `OtpSecondFactorStore` over a `Map` keyed by the pending token.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOtpSecondFactorStore = (
  records: Map<string, OtpSecondFactorRecord> = new Map(),
): typeof OtpSecondFactorStore.Service => ({
  create: (record) => Effect.sync(() => (records.set(record.pendingToken, record), record)),
  get: (pendingToken) => Effect.sync(() => records.get(pendingToken) ?? null),
  update: (record) => Effect.sync(() => (records.set(record.pendingToken, record), record)),
  delete: (pendingToken) => Effect.sync(() => void records.delete(pendingToken)),
});

/**
 * `JwtKeyStore` over an array: the most recently created key is active, and
 * every key stays listed for verification.
 *
 * @since 1.0.0
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
 * `OAuthAccountStore` over a `Map` keyed by `(provider, providerId)`.
 * `hasPassword` reads the {@link MemoryUserTable}'s password hashes, so the
 * last-credential unlink guard is on.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOAuthAccountStore = (
  table: MemoryUserTable = memoryUserTable(),
  accounts: Map<string, OAuthAccount> = new Map(),
): typeof OAuthAccountStore.Service => {
  const put = (account: OAuthAccount) =>
    void accounts.set(accountKey(account.provider, account.providerId), account);
  return {
    create: (account) => Effect.sync(() => (put(account), account)),
    get: (provider, providerId) =>
      Effect.sync(() => accounts.get(accountKey(provider, providerId)) ?? null),
    getByUserId: (userId) =>
      Effect.sync(() => [...accounts.values()].filter((account) => account.userId === userId)),
    update: (account) => Effect.sync(() => (put(account), account)),
    linkToUser: (userId, account) => Effect.sync(() => put({ ...account, userId })),
    unlinkFromUser: (userId, provider) =>
      Effect.sync(() => {
        for (const [key, account] of accounts) {
          if (account.userId === userId && account.provider === provider) accounts.delete(key);
        }
      }),
    delete: (provider, providerId) =>
      Effect.sync(() => void accounts.delete(accountKey(provider, providerId))),
    hasPassword: (userId) => Effect.sync(() => table.passwordHashes.has(userId)),
  };
};

// ---------------------------------------------------------------------------
// OIDC provider
// ---------------------------------------------------------------------------

/**
 * `OidcClientStore` over a `Map` keyed by client id.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOidcClientStore = (
  clients: Map<string, OidcClient> = new Map(),
): typeof OidcClientStore.Service => ({
  create: (client) => Effect.sync(() => (clients.set(client.clientId, client), client)),
  getByClientId: (clientId) => Effect.sync(() => clients.get(clientId) ?? null),
  update: (client) => Effect.sync(() => (clients.set(client.clientId, client), client)),
  delete: (clientId) => Effect.sync(() => void clients.delete(clientId)),
  list: () => Effect.sync(() => [...clients.values()]),
});

/**
 * `OidcCodeStore` over a `Map` keyed by the code's hash.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOidcCodeStore = (
  codes: Map<string, OidcAuthorizationCode> = new Map(),
): typeof OidcCodeStore.Service => ({
  create: (code) => Effect.sync(() => (codes.set(code.codeHash, code), code)),
  get: (codeHash) => Effect.sync(() => codes.get(codeHash) ?? null),
  delete: (codeHash) => Effect.sync(() => void codes.delete(codeHash)),
});

/**
 * `OidcTokenStore` over a `Map` keyed by the token's hash, with
 * `listByFamily` (refresh-token reuse detection on).
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOidcTokenStore = (
  tokens: Map<string, OidcToken> = new Map(),
): typeof OidcTokenStore.Service => ({
  create: (token) => Effect.sync(() => (tokens.set(token.tokenHash, token), token)),
  get: (tokenHash) => Effect.sync(() => tokens.get(tokenHash) ?? null),
  delete: (tokenHash) => Effect.sync(() => void tokens.delete(tokenHash)),
  listByFamily: (familyId) =>
    Effect.sync(() => [...tokens.values()].filter((token) => token.familyId === familyId)),
});

/**
 * `OidcConsentStore` over a `Map` keyed by `(userId, clientId)`.
 *
 * @since 1.0.0
 * @category constructors
 */
export const memoryOidcConsentStore = (
  consents: Map<string, OidcConsent> = new Map(),
): typeof OidcConsentStore.Service => {
  const key = (userId: string, clientId: string) => `${userId}\u0000${clientId}`;
  return {
    get: (userId, clientId) => Effect.sync(() => consents.get(key(userId, clientId)) ?? null),
    upsert: (consent) =>
      Effect.sync(() => (consents.set(key(consent.userId, consent.clientId), consent), consent)),
    delete: (userId, clientId) => Effect.sync(() => void consents.delete(key(userId, clientId))),
  };
};

// ---------------------------------------------------------------------------
// Everything at once
// ---------------------------------------------------------------------------

/**
 * The stores {@link layer} provides.
 *
 * @since 1.0.0
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
  | Layer.Success<typeof layerKV>;

/**
 * Every in-memory store over fresh, shared state: the user-writing stores
 * share one {@link MemoryUserTable}, identifiers come from
 * `memoryIdentifierStore`, and the ephemeral token stores (`layerKV`: OAuth
 * state, WebAuthn challenges, rate limits, verification, reset and magic-link
 * tokens, email OTPs, pending multi-factor challenges) run over an in-memory
 * `KeyValueStore`. Each build of the layer starts empty.
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
 * @since 1.0.0
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
      layerKV.pipe(Layer.provide(KeyValueStore.layerMemory)),
    );
  }),
);
