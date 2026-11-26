/**
 * In-memory reference stores for tests and examples. The user contracts share
 * one {@link MemoryUserTable}, and {@link layer} provides every store over
 * fresh state, with the `KeyValueStore` stores over an in-memory backend. Every
 * operation is synchronous, so read-then-write steps are atomic in one process.
 * Nothing persists.
 *
 * @module testing
 */
import type { RootSecret } from "../RootSecret.ts";
import { testRootSecretLayer } from "./RootSecret.ts";
import { Clock, DateTime, Effect, Layer, MutableHashMap } from "effect";
import * as Arr from "effect/Array";
import * as Option from "effect/Option";
import type { KeyValueStore } from "effect/persistence";
import { type AccountToken, AccountManagementStore } from "../AccountManagement.ts";
import { type ApiKey, ApiKeyStore, applyApiKeyUse } from "../ApiKey.ts";
import { memoryIdentifierStore, IdentifierStore } from "../Identifier.ts";
import { JwtKeyStore, type JwtKeyPair } from "../Jwt.ts";
import {
  type KeyValueStoreKeys,
  type KeyValueStoreTake,
  layerKVSingleProcess,
  layerMemoryKeyValueStore,
} from "../KeyValueStores.ts";
import { type CreateUserInput, EmailPasswordStore } from "../email/EmailPassword.ts";
import * as Errors from "../Errors.ts";
import {
  type DeviceAuthorizationRecord,
  DeviceAuthorizationStore,
} from "../DeviceAuthorization.ts";
import { type RateLimitEntry, RateLimitStore } from "../RateLimit.ts";
import { MultiFactorStore, type MultiFactorRecord } from "../multifactor/MultiFactor.ts";
import { CredentialStore, type WebAuthnCredential } from "../multifactor/WebAuthn.ts";
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
import { type PhoneOtpPurpose, type PhoneOtpRecord, PhoneOtpStore } from "../PhoneOtp.ts";
import { SessionStore } from "../SessionStore.ts";
import { TrustedDeviceStore, type TrustedDeviceRecord } from "../TrustedDevice.ts";
import type * as Types from "../Types.ts";
import { UserServiceStore } from "../User.ts";
import { type CreateUserResult, UserStore } from "../UserStore.ts";

/**
 * Remove `key` from `map` and return what it held, if anything: a single-use
 * store's `consume`, atomic because it runs in one synchronous step.
 */
const take = <A>(map: MutableHashMap.MutableHashMap<string, A>, key: string): Option.Option<A> => {
  const found = MutableHashMap.get(map, key);
  if (Option.isSome(found)) MutableHashMap.remove(map, key);
  return found;
};

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
  get: (userId) => Effect.sync(() => MutableHashMap.get(table.users, userId)),
});

/**
 * `UserServiceStore` over a {@link MemoryUserTable}: `delete` removes the
 * user row and its password hash, and nothing else, as the contract says;
 * the services that delete an account purge the rest first.
 *
 * @since 0.5.0
 * @category constructors
 */
export const memoryUserServiceStore = (
  table: MemoryUserTable = memoryUserTable(),
): typeof UserServiceStore.Service => ({
  get: (userId) => Effect.sync(() => MutableHashMap.get(table.users, userId)),
  update: (user) => Effect.sync(() => (MutableHashMap.set(table.users, user.id, user), user)),
  delete: (userId) =>
    Effect.sync(() => {
      MutableHashMap.remove(table.users, userId);
      MutableHashMap.remove(table.passwordHashes, userId);
    }),
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
  getPasswordHash: (userId) => Effect.sync(() => MutableHashMap.get(table.passwordHashes, userId)),
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
  get: (sessionId) => Effect.sync(() => MutableHashMap.get(sessions, sessionId)),
  // Never creates: a session deleted since the caller read it stays deleted.
  update: (session) =>
    Effect.sync(() => {
      if (MutableHashMap.has(sessions, session.id))
        MutableHashMap.set(sessions, session.id, session);
      return session;
    }),
  touch: (sessionId, touch) =>
    Effect.sync(() =>
      MutableHashMap.get(sessions, sessionId).pipe(
        Option.filter((session) => session.expiresAt.getTime() >= touch.lastActivityAt.getTime()),
        Option.map((session) => {
          const touched = { ...session, ...touch };
          MutableHashMap.set(sessions, sessionId, touched);
          return touched;
        }),
      ),
    ),
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
 * `ApiKeyStore` over a `MutableHashMap` keyed by the key's id; `getByHash`
 * finds the record whose `keyHash` (the SHA-256 digest of the plaintext key)
 * matches. It honours the whole contract, which `apiKeyStoreConformance`
 * checks.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryApiKeyStore = (
  keys: MutableHashMap.MutableHashMap<string, ApiKey> = MutableHashMap.empty(),
): typeof ApiKeyStore.Service => ({
  create: (key) => Effect.sync(() => (MutableHashMap.set(keys, key.id, key), key)),
  get: (id) => Effect.sync(() => MutableHashMap.get(keys, id)),
  getByHash: (keyHash) =>
    Effect.sync(() => Arr.findFirst(MutableHashMap.values(keys), (key) => key.keyHash === keyHash)),
  update: (key) => Effect.sync(() => (MutableHashMap.set(keys, key.id, key), key)),
  recordUse: (id, use) =>
    Effect.sync(() => {
      const spent = Option.flatMap(MutableHashMap.get(keys, id), (stored) =>
        applyApiKeyUse(stored, use),
      );
      if (Option.isSome(spent)) MutableHashMap.set(keys, id, spent.value);
      return spent;
    }),
  delete: (id) => Effect.sync(() => void MutableHashMap.remove(keys, id)),
  listByUserId: (userId) =>
    Effect.sync(() =>
      Arr.filter(Arr.fromIterable(MutableHashMap.values(keys)), (key) => key.userId === userId),
    ),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(keys, (key) => key.userId === userId);
    }),
});

/**
 * WebAuthn `CredentialStore` (passkeys) over a `MutableHashMap` keyed by the
 * credential id, which is also the raw credential id `getByCredentialId`
 * reads.
 *
 * @since 0.5.0
 * @category constructors
 */
export const memoryCredentialStore = (
  credentials: MutableHashMap.MutableHashMap<string, WebAuthnCredential> = MutableHashMap.empty(),
): typeof CredentialStore.Service => ({
  create: (credential) =>
    Effect.sync(() => (MutableHashMap.set(credentials, credential.id, credential), credential)),
  get: (credentialId) => Effect.sync(() => MutableHashMap.get(credentials, credentialId)),
  getByCredentialId: (credentialId) =>
    Effect.sync(() => MutableHashMap.get(credentials, credentialId)),
  update: (credential) =>
    Effect.sync(() => (MutableHashMap.set(credentials, credential.id, credential), credential)),
  delete: (credentialId) =>
    Effect.sync(() => void MutableHashMap.remove(credentials, credentialId)),
  listByUserId: (userId) =>
    Effect.sync(() =>
      Arr.filter(
        Arr.fromIterable(MutableHashMap.values(credentials)),
        (credential) => credential.userId === userId,
      ),
    ),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(credentials, (credential) => credential.userId === userId);
    }),
});

/**
 * `AccountManagementStore` (pending email-change and account-deletion
 * tokens) over a `MutableHashMap` keyed by the token.
 *
 * @since 0.5.0
 * @category constructors
 */
export const memoryAccountManagementStore = (
  tokens: MutableHashMap.MutableHashMap<string, AccountToken> = MutableHashMap.empty(),
): typeof AccountManagementStore.Service => ({
  create: (token) => Effect.sync(() => (MutableHashMap.set(tokens, token.token, token), token)),
  get: (token) => Effect.sync(() => MutableHashMap.get(tokens, token)),
  delete: (token) => Effect.sync(() => void MutableHashMap.remove(tokens, token)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(tokens, (token) => token.userId === userId);
    }),
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
  get: (userId) => Effect.sync(() => MutableHashMap.get(records, userId)),
  upsert: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.userId, record), record)),
  delete: (userId) => Effect.sync(() => void MutableHashMap.remove(records, userId)),
  // Each spend is one synchronous step, so it is atomic on this map.
  useTotpCounter: (userId, counter) =>
    Effect.sync(() => {
      const record = Option.getOrNull(MutableHashMap.get(records, userId));
      if (record === null || !record.verified) return false;
      if (record.lastUsedCounter !== undefined && record.lastUsedCounter >= counter) return false;
      MutableHashMap.set(records, userId, { ...record, lastUsedCounter: counter });
      return true;
    }),
  useBackupCode: (userId, codeHash) =>
    Effect.sync(() => {
      const record = Option.getOrNull(MutableHashMap.get(records, userId));
      if (record === null || !record.verified || !record.backupCodes.includes(codeHash)) {
        return false;
      }
      MutableHashMap.set(records, userId, {
        ...record,
        backupCodes: record.backupCodes.filter((code) => code !== codeHash),
      });
      return true;
    }),
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
  getByTokenHash: (tokenHash) => Effect.sync(() => MutableHashMap.get(records, tokenHash)),
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
  get: (pendingToken) => Effect.sync(() => MutableHashMap.get(records, pendingToken)),
  update: (record) =>
    Effect.sync(() => (MutableHashMap.set(records, record.pendingToken, record), record)),
  incrementAttempts: (pendingToken) =>
    Effect.sync(() => {
      return Option.map(MutableHashMap.get(records, pendingToken), (record) => {
        MutableHashMap.set(records, pendingToken, { ...record, attempts: record.attempts + 1 });
        return record.attempts + 1;
      });
    }),
  delete: (pendingToken) => Effect.sync(() => void MutableHashMap.remove(records, pendingToken)),
});

/**
 * `RateLimitStore` over a map, for the per-recipient send caps and the
 * limiters in a test: `increment` starts a new window when there is none or
 * it has expired, as the contract requires. Pass `entries` to read the
 * keys a test wrote.
 *
 * @since 0.3.0
 * @category constructors
 */
export const memoryRateLimitStore = (
  entries: MutableHashMap.MutableHashMap<string, RateLimitEntry> = MutableHashMap.empty(),
): typeof RateLimitStore.Service => ({
  get: (key) => Effect.sync(() => MutableHashMap.get(entries, key)),
  set: (key, entry) => Effect.sync(() => void MutableHashMap.set(entries, key, entry)),
  increment: (key, ttl) =>
    Effect.flatMap(Clock.currentTimeMillis, (now) =>
      Effect.sync(() => {
        const entry = Option.getOrUndefined(MutableHashMap.get(entries, key));
        const next: RateLimitEntry =
          entry === undefined || now >= entry.resetAt
            ? { key, count: 1, resetAt: now + ttl * 1000 }
            : { ...entry, count: entry.count + 1 };
        MutableHashMap.set(entries, key, next);
        return next.count;
      }),
    ),
  delete: (key) => Effect.sync(() => void MutableHashMap.remove(entries, key)),
});

/**
 * `JwtKeyStore` over an array: the most recently created key is active, and
 * every key stays listed for verification.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryJwtKeyStore = (keys: Array<JwtKeyPair> = []): typeof JwtKeyStore.Service => ({
  getActive: Effect.sync(() => Arr.last(keys)),
  create: (pair) => Effect.sync(() => (keys.push(pair), pair)),
  list: Effect.sync(() => [...keys]),
});

// ---------------------------------------------------------------------------
// One-time codes
// ---------------------------------------------------------------------------

/** The key of an (address, purpose) pair in the one-time code maps. */
const codeKey = (address: string, purpose: string): string => `${purpose}:${address}`;

/**
 * The failure-budget methods of `EmailOtpStore` and `PhoneOtpStore`
 * over a `MutableHashMap` keyed by purpose and address, to spread into an
 * in-memory code store. The budget lives apart from the code records, so
 * replacing or deleting a code leaves it.
 *
 * @since 0.3.0
 * @category constructors
 */
export const memoryOtpFailures = <P extends string>(
  failures: MutableHashMap.MutableHashMap<string, Types.OtpFailures> = MutableHashMap.empty(),
): Types.OtpFailureBudget<P> => ({
  getFailures: (address, purpose) =>
    Effect.sync(() => MutableHashMap.get(failures, codeKey(address, purpose))),
  recordFailure: (address, purpose, at) =>
    Effect.sync(() => {
      const count = Option.match(MutableHashMap.get(failures, codeKey(address, purpose)), {
        onNone: () => 1,
        onSome: (stored) => stored.count + 1,
      });
      const next: Types.OtpFailures = { count, lastFailureAt: at };
      MutableHashMap.set(failures, codeKey(address, purpose), next);
      return next;
    }),
  clearFailures: (address, purpose) =>
    Effect.sync(() => void MutableHashMap.remove(failures, codeKey(address, purpose))),
});

/**
 * `PhoneOtpStore` over `MutableHashMap`s: one record per phone number and
 * purpose, and each pair's failure budget from {@link memoryOtpFailures}.
 *
 * @since 0.3.0
 * @category constructors
 */
export const memoryPhoneOtpStore = (
  records: MutableHashMap.MutableHashMap<string, PhoneOtpRecord> = MutableHashMap.empty(),
  failures: MutableHashMap.MutableHashMap<string, Types.OtpFailures> = MutableHashMap.empty(),
): typeof PhoneOtpStore.Service => ({
  upsert: (record) =>
    Effect.sync(() => {
      MutableHashMap.set(records, codeKey(record.phoneNumber, record.purpose), record);
      return record;
    }),
  get: (phoneNumber, purpose) =>
    Effect.sync(() => MutableHashMap.get(records, codeKey(phoneNumber, purpose))),
  delete: (phoneNumber, purpose) =>
    Effect.sync(() => void MutableHashMap.remove(records, codeKey(phoneNumber, purpose))),
  incrementAttempts: (phoneNumber, purpose) =>
    Effect.sync(() =>
      Option.map(MutableHashMap.get(records, codeKey(phoneNumber, purpose)), (record) => {
        const updated: PhoneOtpRecord = { ...record, attempts: record.attempts + 1 };
        MutableHashMap.set(records, codeKey(phoneNumber, purpose), updated);
        return updated.attempts;
      }),
    ),
  ...memoryOtpFailures<PhoneOtpPurpose>(failures),
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
    // A plain insert: a pair already linked is refused, as a unique index would.
    create: (account) =>
      MutableHashMap.has(accounts, accountKey(account.provider, account.providerId))
        ? Effect.fail(
            new Errors.AuthError({
              message: `OAuth account (${account.provider}) is already linked`,
            }),
          )
        : Effect.sync(() => (put(account), account)),
    get: (provider, providerId) =>
      Effect.sync(() => MutableHashMap.get(accounts, accountKey(provider, providerId))),
    getByUserId: (userId) =>
      Effect.sync(() =>
        Arr.fromIterable(MutableHashMap.values(accounts)).filter(
          (account) => account.userId === userId,
        ),
      ),
    update: (account) =>
      Effect.sync(() => {
        const stored = Arr.findFirst(
          MutableHashMap.values(accounts),
          (candidate) => candidate.id === account.id,
        );
        if (Option.isNone(stored)) return Option.none();
        // Every field from `account` but the link's identity and owner.
        const updated: OAuthAccount = {
          ...account,
          userId: stored.value.userId,
          provider: stored.value.provider,
          providerId: stored.value.providerId,
          createdAt: stored.value.createdAt,
        };
        put(updated);
        return Option.some(updated);
      }),
    linkToUser: (userId, account) =>
      Effect.suspend(() => {
        const key = accountKey(account.provider, account.providerId);
        const stored = MutableHashMap.get(accounts, key);
        if (Option.isNone(stored)) return Effect.void;
        if (stored.value.userId !== "" && stored.value.userId !== userId) {
          return Effect.fail(
            new Errors.AuthError({ message: "OAuth link belongs to another user" }),
          );
        }
        MutableHashMap.set(accounts, key, {
          ...stored.value,
          userId,
          updatedAt: account.updatedAt,
        });
        return Effect.void;
      }),
    unlinkFromUser: (userId, provider) =>
      Effect.sync(() => {
        removeWhere(
          accounts,
          (account) => account.userId === userId && account.provider === provider,
        );
      }),
    delete: (provider, providerId) =>
      Effect.sync(() => void MutableHashMap.remove(accounts, accountKey(provider, providerId))),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        removeWhere(accounts, (account) => account.userId === userId);
      }),
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
  getByClientId: (clientId) => Effect.sync(() => MutableHashMap.get(clients, clientId)),
  update: (client) =>
    Effect.sync(() => (MutableHashMap.set(clients, client.clientId, client), client)),
  delete: (clientId) => Effect.sync(() => void MutableHashMap.remove(clients, clientId)),
  list: Effect.sync(() => Arr.fromIterable(MutableHashMap.values(clients))),
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
  get: (codeHash) => Effect.sync(() => MutableHashMap.get(codes, codeHash)),
  consume: (codeHash) => Effect.sync(() => take(codes, codeHash)),
  delete: (codeHash) => Effect.sync(() => void MutableHashMap.remove(codes, codeHash)),
});

/**
 * `OidcTokenStore` over a `MutableHashMap` keyed by the token's hash.
 *
 * @since 0.1.0
 * @category constructors
 */
export const memoryOidcTokenStore = (
  tokens: MutableHashMap.MutableHashMap<string, OidcToken> = MutableHashMap.empty(),
): typeof OidcTokenStore.Service => ({
  create: (token) => Effect.sync(() => (MutableHashMap.set(tokens, token.tokenHash, token), token)),
  get: (tokenHash) => Effect.sync(() => MutableHashMap.get(tokens, tokenHash)),
  consume: (tokenHash) => Effect.sync(() => take(tokens, tokenHash)),
  delete: (tokenHash) => Effect.sync(() => void MutableHashMap.remove(tokens, tokenHash)),
  deleteByUserId: (userId) =>
    Effect.sync(() => {
      removeWhere(tokens, (token) => token.userId === userId);
    }),
  deleteByFamily: (familyId) =>
    Effect.sync(() => {
      removeWhere(tokens, (token) => token.familyId === familyId);
    }),
  deleteByClientId: (clientId) =>
    Effect.sync(() => {
      removeWhere(tokens, (token) => token.clientId === clientId);
    }),
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
      Effect.sync(() => MutableHashMap.get(consents, key(userId, clientId))),
    upsert: (consent) =>
      Effect.sync(
        () => (
          MutableHashMap.set(consents, key(consent.userId, consent.clientId), consent),
          consent
        ),
      ),
    delete: (userId, clientId) =>
      Effect.sync(() => void MutableHashMap.remove(consents, key(userId, clientId))),
    deleteByUserId: (userId) =>
      Effect.sync(() => {
        removeWhere(consents, (consent) => consent.userId === userId);
      }),
  };
};

// ---------------------------------------------------------------------------
// Device authorization
// ---------------------------------------------------------------------------

/**
 * `DeviceAuthorizationStore` over a `MutableHashMap` keyed by the device-code
 * digest. `settle`, `touch` and `claimApproval` each read and write in one
 * synchronous step, so they hold the store's conditional-write contract.
 *
 * @since 0.9.0
 * @category constructors
 */
export const memoryDeviceAuthorizationStore = (
  records: MutableHashMap.MutableHashMap<
    string,
    DeviceAuthorizationRecord
  > = MutableHashMap.empty(),
): typeof DeviceAuthorizationStore.Service => {
  const byUserCode = (userCode: string) =>
    Arr.findFirst(MutableHashMap.values(records), (r) => r.userCode === userCode);
  return {
    create: (record) =>
      Effect.sync(() => {
        MutableHashMap.set(records, record.deviceCode, record);
        return record;
      }),
    getByDeviceCode: (deviceCode) => Effect.sync(() => MutableHashMap.get(records, deviceCode)),
    getByUserCode: (userCode) => Effect.sync(() => byUserCode(userCode)),
    settle: (userCode, decision, now) =>
      Effect.sync(() => {
        const found = byUserCode(userCode);
        if (Option.isNone(found)) return Option.none();
        const record = found.value;
        if (record.status !== "pending" || record.expiresAt < now) return Option.none();
        const settled: DeviceAuthorizationRecord = {
          ...record,
          status: decision.status,
          userId: decision.userId,
        };
        MutableHashMap.set(records, record.deviceCode, settled);
        return Option.some(settled);
      }),
    touch: (deviceCode, touch) =>
      Effect.sync(() => {
        return Option.map(MutableHashMap.get(records, deviceCode), (record) => {
          const touched: DeviceAuthorizationRecord = { ...record, ...touch };
          MutableHashMap.set(records, deviceCode, touched);
          return touched;
        });
      }),
    delete: (deviceCode) => Effect.sync(() => void MutableHashMap.remove(records, deviceCode)),
    claimApproval: (deviceCode) =>
      Effect.sync(() => {
        const record = MutableHashMap.get(records, deviceCode).pipe(
          Option.filter((found) => found.status === "approved"),
        );
        if (Option.isSome(record)) MutableHashMap.remove(records, deviceCode);
        return record;
      }),
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
  | UserServiceStore
  | EmailPasswordStore
  | OAuthUserStore
  | OAuthAccountStore
  | SessionStore
  | ApiKeyStore
  | IdentifierStore
  | MultiFactorStore
  | CredentialStore
  | AccountManagementStore
  | TrustedDeviceStore
  | OtpSecondFactorStore
  | JwtKeyStore
  | OidcClientStore
  | OidcCodeStore
  | OidcTokenStore
  | OidcConsentStore
  | Layer.Success<typeof layerKVSingleProcess>
  | KeyValueStore.KeyValueStore
  | KeyValueStoreKeys
  | KeyValueStoreTake
  | RootSecret;

/**
 * Every in-memory store over fresh, shared state: the user-writing stores
 * share one {@link MemoryUserTable}, identifiers come from
 * `memoryIdentifierStore`, and the ephemeral token stores (`layerKVSingleProcess`: OAuth
 * state, WebAuthn challenges, rate limits, verification, reset and magic-link
 * tokens, email OTPs, pending multi-factor challenges) run over an in-memory
 * `KeyValueStore`, which the layer also provides with its `KeyValueStoreKeys`
 * listing, so `purgeExpiredKV` runs against it, and its `KeyValueStoreTake`.
 * It also provides the public test {@link RootSecret} (`testRootSecretLayer`).
 * Each build of the layer starts empty.
 *
 * @example
 * ```ts
 * import assert from "node:assert/strict"
 * import { Effect, Option } from "effect"
 * import * as Auth from "@thomasfosterau/effect-auth"
 * import * as Testing from "@thomasfosterau/effect-auth/testing"
 *
 * const program = Effect.gen(function* () {
 *   const sessions = yield* Auth.SessionStore
 *   const users = yield* Auth.UserStore
 *   assert.ok(Option.isNone(yield* users.get("nobody")))
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
      Layer.succeed(UserServiceStore, memoryUserServiceStore(table)),
      Layer.succeed(EmailPasswordStore, memoryEmailPasswordStore(table)),
      Layer.succeed(OAuthUserStore, memoryOAuthUserStore(table)),
      Layer.succeed(OAuthAccountStore, memoryOAuthAccountStore(table)),
      Layer.succeed(SessionStore, memorySessionStore()),
      Layer.succeed(ApiKeyStore, memoryApiKeyStore()),
      Layer.succeed(IdentifierStore, memoryIdentifierStore()),
      Layer.succeed(MultiFactorStore, memoryMultiFactorStore()),
      Layer.succeed(CredentialStore, memoryCredentialStore()),
      Layer.succeed(AccountManagementStore, memoryAccountManagementStore()),
      Layer.succeed(TrustedDeviceStore, memoryTrustedDeviceStore()),
      Layer.succeed(OtpSecondFactorStore, memoryOtpSecondFactorStore()),
      Layer.succeed(JwtKeyStore, memoryJwtKeyStore()),
      Layer.succeed(OidcClientStore, memoryOidcClientStore()),
      Layer.succeed(OidcCodeStore, memoryOidcCodeStore()),
      Layer.succeed(OidcTokenStore, memoryOidcTokenStore()),
      Layer.succeed(OidcConsentStore, memoryOidcConsentStore()),
      Layer.provideMerge(layerKVSingleProcess, layerMemoryKeyValueStore),
      testRootSecretLayer,
    );
  }),
);
